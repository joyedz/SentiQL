const READ_ONLY_ALLOW = {
  decision: 'allow',
  reason: 'Query is permitted by the read-only policy.',
};

const READ_WRITE_ALLOW = {
  decision: 'allow',
  reason: 'Query is permitted by the read-write policy.',
};

const WRITE_KEYWORDS = new Set(['INSERT', 'UPDATE', 'DELETE']);
const READ_QUERY_KEYWORDS = new Set(['SELECT', 'VALUES', 'EXPLAIN', 'SHOW', 'WITH']);
const DESTRUCTIVE_DROP_TARGETS = new Set([
  'TABLE',
  'DATABASE',
  'SCHEMA',
  'INDEX',
  'VIEW',
]);
const CLAUSE_BOUNDARIES = new Set([
  'GROUP',
  'ORDER',
  'LIMIT',
  'OFFSET',
  'FETCH',
  'FOR',
  'RETURNING',
  'UNION',
  'INTERSECT',
  'EXCEPT',
  'WINDOW',
]);

function deny(reason) {
  return { decision: 'deny', reason };
}

function maskRange(masked, start, end) {
  for (let index = start; index < end; index += 1) {
    if (masked[index] !== '\n' && masked[index] !== '\r') {
      masked[index] = ' ';
    }
  }
}

function maskSql(sql) {
  // String indexes are UTF-16 code-unit offsets. Keep the masks in that same
  // coordinate system so ranges remain correct before astral Unicode literals.
  const masked = sql.split('');
  const stripped = sql.split('');

  for (let index = 0; index < sql.length;) {
    if (sql.startsWith('--', index)) {
      const lineEnd = sql.indexOf('\n', index + 2);
      const end = lineEnd === -1 ? sql.length : lineEnd;
      maskRange(masked, index, end);
      maskRange(stripped, index, end);
      index = end;
      continue;
    }

    if (sql.startsWith('/*', index)) {
      const close = sql.indexOf('*/', index + 2);
      if (close === -1) {
        return { error: 'SQL contains an unclosed block comment.' };
      }
      const end = close + 2;
      maskRange(masked, index, end);
      maskRange(stripped, index, end);
      index = end;
      continue;
    }

    const character = sql[index];
    if (character === "'" || character === '"') {
      const quote = character;
      const isEscapedString =
        quote === "'" &&
        (sql[index - 1] === 'E' || sql[index - 1] === 'e') &&
        (index < 2 || !/[A-Za-z0-9_$]/.test(sql[index - 2]));
      let cursor = index + 1;
      let closed = false;

      while (cursor < sql.length) {
        if (isEscapedString && sql[cursor] === '\\') {
          cursor += 2;
          continue;
        }
        if (sql[cursor] === quote) {
          if (sql[cursor + 1] === quote) {
            cursor += 2;
            continue;
          }
          cursor += 1;
          closed = true;
          break;
        }
        cursor += 1;
      }

      if (!closed) {
        return { error: `SQL contains an unclosed ${quote === "'" ? 'string' : 'identifier'} quote.` };
      }

      maskRange(masked, index, cursor);
      index = cursor;
      continue;
    }

    if (character === '$') {
      const delimiter = sql.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/)?.[0];
      if (delimiter) {
        const close = sql.indexOf(delimiter, index + delimiter.length);
        if (close === -1) {
          return { error: 'SQL contains an unclosed dollar-quoted literal.' };
        }
        const end = close + delimiter.length;
        maskRange(masked, index, end);
        index = end;
        continue;
      }
    }

    index += 1;
  }

  return { masked: masked.join(''), stripped: stripped.join('') };
}

function tokenize(masked) {
  const tokens = [];
  let depth = 0;

  for (let index = 0; index < masked.length;) {
    const character = masked[index];
    if (character === '(') {
      depth += 1;
      index += 1;
      continue;
    }
    if (character === ')') {
      depth -= 1;
      index += 1;
      continue;
    }

    if (/[A-Za-z_]/.test(character)) {
      const start = index;
      index += 1;
      while (index < masked.length && /[A-Za-z0-9_$]/.test(masked[index])) {
        index += 1;
      }
      tokens.push({
        value: masked.slice(start, index).toUpperCase(),
        start,
        end: index,
        depth,
      });
      continue;
    }

    index += 1;
  }

  return tokens;
}

function hasBalancedParentheses(masked) {
  let depth = 0;
  for (const character of masked) {
    if (character === '(') {
      depth += 1;
    } else if (character === ')') {
      depth -= 1;
      if (depth < 0) {
        return false;
      }
    }
  }
  return depth === 0;
}

function hasMultipleStatements(masked) {
  for (let index = 0; index < masked.length; index += 1) {
    if (masked[index] === ';' && /\S/.test(masked.slice(index + 1))) {
      return true;
    }
  }
  return false;
}

function destructiveStatement(tokens) {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1];
    if (
      token.value === 'DROP' &&
      next &&
      next.value === 'MATERIALIZED' &&
      tokens[index + 2]?.value === 'VIEW'
    ) {
      return 'DROP MATERIALIZED VIEW';
    }
    if (token.value === 'DROP' && next && DESTRUCTIVE_DROP_TARGETS.has(next.value)) {
      return `DROP ${next.value}`;
    }
    if (token.value === 'TRUNCATE' || token.value === 'GRANT' || token.value === 'REVOKE') {
      return token.value;
    }
    if (token.value === 'ALTER' && next && DESTRUCTIVE_DROP_TARGETS.has(next.value)) {
      return `ALTER ${next.value}`;
    }
  }
  return null;
}

function hasSelectInto(tokens, masked) {
  return tokens.some((selectToken) => {
    if (selectToken.value !== 'SELECT') {
      return false;
    }
    const end = scopeEnd(masked, selectToken.end, selectToken.depth);
    return tokens.some(
      (token) =>
        token.start >= selectToken.end &&
        token.start < end &&
        token.depth === selectToken.depth &&
        token.value === 'INTO',
    );
  });
}

function scopeEnd(masked, start, depth) {
  let currentDepth = depth;
  for (let index = start; index < masked.length; index += 1) {
    if (masked[index] === '(') {
      currentDepth += 1;
    } else if (masked[index] === ')') {
      if (currentDepth === depth) {
        return index;
      }
      currentDepth -= 1;
    } else if (masked[index] === ';' && currentDepth === depth) {
      return index;
    }
  }
  return masked.length;
}

function isNoOpWhere(whereToken, tokens, masked, stripped) {
  let end = scopeEnd(masked, whereToken.end, whereToken.depth);
  const boundary = tokens.find(
    (token) =>
      token.start >= whereToken.end &&
      token.depth === whereToken.depth &&
      CLAUSE_BOUNDARIES.has(token.value),
  );
  if (boundary) {
    end = Math.min(end, boundary.start);
  }

  const normalized = masked
    .slice(whereToken.end, end)
    .replace(/[\s()]/g, '')
    .toUpperCase();
  const normalizedStripped = stripped
    .slice(whereToken.end, end)
    .replace(/[\s()]/g, '')
    .toUpperCase();

  if (
    normalized === 'TRUE' ||
    normalized === 'FALSE' ||
    normalized === 'NULL' ||
    normalized === 'NOTFALSE' ||
    normalized === '1=1'
  ) {
    return true;
  }
  if (/^'(?:[^']|'')*'$/.test(normalizedStripped)) {
    return true;
  }
  if (/^\$[A-Z_][A-Z0-9_]*\$[\s\S]*\$[A-Z_][A-Z0-9_]*\$$/.test(normalizedStripped) || /^\$\$[\s\S]*\$\$$/.test(normalizedStripped)) {
    return true;
  }

  const numeric = '[+-]?\\d+(?:\\.\\d+)?(?:E[+-]?\\d+)?';
  const cast = '(?:::[A-Z_][A-Z0-9_]*)?';
  const numericIdentity = new RegExp(`^(${numeric})${cast}=\\1${cast}$`);
  if (numericIdentity.test(normalized)) {
    return true;
  }
  const numericComparison = new RegExp(
    `^(${numeric})${cast}(=|<>|!=|>=|<=|>|<)(${numeric})${cast}$`,
  ).exec(normalized);
  if (numericComparison) {
    const left = Number(numericComparison[1]);
    const right = Number(numericComparison[3]);
    const operator = numericComparison[2];
    return (
      (operator === '=' && left === right) ||
      ((operator === '<>' || operator === '!=') && left !== right) ||
      (operator === '>' && left > right) ||
      (operator === '<' && left < right) ||
      (operator === '>=' && left >= right) ||
      (operator === '<=' && left <= right)
    );
  }
  return new RegExp(`^${numeric}${cast}$`).test(normalized);
}

function hasRealWhere(writeToken, tokens, masked, stripped) {
  const whereToken = tokens.find(
    (token) => token.start > writeToken.start && token.depth === 0 && token.value === 'WHERE',
  );
  if (!whereToken) {
    return false;
  }

  const end = scopeEnd(masked, whereToken.end, 0);
  return /\S/.test(stripped.slice(whereToken.end, end));
}

/**
 * Evaluate SQL against the application's intentionally conservative policy.
 * This is synchronous and performs no I/O.
 */
export function evaluatePolicy(sql, { mode = 'read-only' } = {}) {
  if (mode !== 'read-only' && mode !== 'read-write') {
    return deny(`Unsupported policy mode "${mode}".`);
  }
  if (typeof sql !== 'string') {
    return deny('SQL must be a string.');
  }

  const lexical = maskSql(sql);
  if (lexical.error) {
    return deny(lexical.error);
  }

  const { masked, stripped } = lexical;
  if (!/\S/.test(stripped)) {
    return deny('SQL must contain executable SQL; empty or comment-only input is not permitted.');
  }
  if (!hasBalancedParentheses(masked)) {
    return deny('SQL contains unbalanced parentheses.');
  }
  const tokens = tokenize(masked);

  const firstTopLevelToken = tokens.find((token) => token.depth === 0);
  if (!firstTopLevelToken) {
    return deny('SQL does not contain a recognized executable command.');
  }

  if (hasMultipleStatements(masked)) {
    return deny('Multiple SQL statements are not permitted.');
  }

  const destructive = destructiveStatement(tokens);
  if (destructive) {
    return deny(`Destructive statement "${destructive}" is not permitted.`);
  }

  if (hasSelectInto(tokens, masked)) {
    return deny('SELECT INTO is not permitted because it creates a table.');
  }

  const writes = tokens.filter((token) => WRITE_KEYWORDS.has(token.value));
  const nestedWrite = writes.find((token) => token.depth > 0);
  if (nestedWrite) {
    return deny(
      'Writes inside a CTE or subquery are not permitted because WHERE safety cannot be verified for nested writes.',
    );
  }

  if (mode === 'read-only' && writes.length > 0) {
    return deny('Write statements are not permitted in read-only mode.');
  }

  if (mode === 'read-write' && writes.length > 0) {
    const topLevelWrite = writes.find((token) => token.depth === 0);
    if (!topLevelWrite || firstTopLevelToken?.value !== topLevelWrite.value) {
      return deny(
        'Write statements must begin the query with INSERT, UPDATE, or DELETE; prefixed or nested writes cannot be safely verified.',
      );
    }
    if ((topLevelWrite.value === 'DELETE' || topLevelWrite.value === 'UPDATE') && !hasRealWhere(topLevelWrite, tokens, masked, stripped)) {
      return deny(`${topLevelWrite.value} statements require a non-trivial WHERE clause in read-write mode.`);
    }
  }

  const noOpWhere = tokens.find((token) => token.value === 'WHERE' && isNoOpWhere(token, tokens, masked, stripped));
  if (noOpWhere) {
    return deny('No-op WHERE conditions such as "TRUE" or "1=1" are not permitted.');
  }

  const isPermittedReadQuery = READ_QUERY_KEYWORDS.has(firstTopLevelToken.value);
  const isPermittedWrite =
    mode === 'read-write' && WRITE_KEYWORDS.has(firstTopLevelToken.value);
  if (!isPermittedReadQuery && !isPermittedWrite) {
    return deny(`Top-level command "${firstTopLevelToken.value}" is not recognized by this policy and is not permitted.`);
  }

  return mode === 'read-only' ? { ...READ_ONLY_ALLOW } : { ...READ_WRITE_ALLOW };
}
