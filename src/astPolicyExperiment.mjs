import {
  createAstParser,
  getSupportedAstParserVersions,
  summarizeAst,
} from './astParserExperiment.mjs';

const WRITE_KINDS = new Set([
  'InsertStmt',
  'UpdateStmt',
  'DeleteStmt',
  'MergeStmt',
]);

const UTILITY_KINDS = new Set([
  'CreateStmt',
  'AlterTableStmt',
  'DropStmt',
  'TruncateStmt',
  'CopyStmt',
  'DoStmt',
  'TransactionStmt',
]);

// Function names that mutate connection/session context. Kept explicit so the
// evaluator never infers safety from syntax alone.
const CONTEXT_MUTATION_FUNCTIONS = new Set(['set_config']);

function isSupportedVersion(parserVersion) {
  return getSupportedAstParserVersions().includes(parserVersion);
}

function walkNodes(value, visit) {
  if (!value || typeof value !== 'object') return;
  visit(value);

  if (Array.isArray(value)) {
    for (const item of value) walkNodes(item, visit);
    return;
  }

  for (const child of Object.values(value)) walkNodes(child, visit);
}

function readFunctionName(funcCall) {
  const parts = Array.isArray(funcCall?.funcname) ? funcCall.funcname : [];

  return parts
    .map((part) => {
      const stringNode = part?.String ?? part?.string ?? null;
      if (!stringNode || typeof stringNode !== 'object') return null;
      // Newer parser versions use `sval`; older ones use `str`.
      return stringNode.sval ?? stringNode.str ?? null;
    })
    .filter((name) => typeof name === 'string' && name.length > 0)
    .join('.')
    .toLowerCase();
}

function emptyFacts() {
  return {
    statementCount: 0,
    topLevelKinds: [],
    nestedStatementKinds: [],
    nestedWriteCount: 0,
    functionNames: [],
    functionCallCount: 0,
    utilityNodeCount: 0,
    hasSelectInto: false,
    hasUtilityStatement: false,
    hasContextMutation: false,
  };
}

// Normalize only directly observable AST facts. On parser error, return facts
// marked parse_error while preserving the original parser message.
export async function extractAstFacts(sql, { parserVersion } = {}) {
  const parser = createAstParser(parserVersion);

  let result;
  try {
    result = await parser.parse(sql);
  } catch (error) {
    return {
      parseStatus: 'parse_error',
      parseError: error?.message ?? String(error),
      ...emptyFacts(),
    };
  }

  const summary = summarizeAst(result);
  const topLevelKinds = summary.statementKinds.filter((kind) => typeof kind === 'string');
  const nestedStatementKinds = summary.nestedStatementKinds;
  const nestedWriteCount = nestedStatementKinds.filter((kind) => WRITE_KINDS.has(kind)).length;

  const functionNames = [];
  let hasSelectInto = false;

  walkNodes(result.raw, (node) => {
    for (const key of Object.keys(node)) {
      if (key === 'FuncCall') {
        const name = readFunctionName(node.FuncCall);
        if (name) functionNames.push(name);
      }
      // SELECT ... INTO sets a truthy `intoClause` on the SelectStmt.
      if (key === 'intoClause' && node.intoClause) hasSelectInto = true;
      if (key === 'IntoClause') hasSelectInto = true;
    }
  });

  const hasContextMutation = functionNames.some((name) =>
    CONTEXT_MUTATION_FUNCTIONS.has(name),
  );

  return {
    parseStatus: 'parsed',
    parseError: null,
    statementCount: result.statementCount,
    topLevelKinds,
    nestedStatementKinds,
    nestedWriteCount,
    functionNames,
    functionCallCount: summary.functionCallCount,
    utilityNodeCount: summary.utilityNodeCount,
    hasSelectInto,
    hasUtilityStatement: summary.utilityNodeCount > 0,
    hasContextMutation,
  };
}

function denyResult(reasonCode, parserVersion, parseStatus, facts) {
  return {
    decision: 'deny',
    reasonCode,
    parserVersion,
    parseStatus,
    facts,
  };
}

// Conservative, fail-closed evaluator. Deny reasons are checked in a fixed,
// explicit order so every fixture maps to a single stable reason code:
//   1. parse error      2. unsupported version   3. multiple statements
//   4. unknown top kind  5. utility statement     6. nested write
//   7. context mutation  8. select into           9. unsafe function
//  10. unsupported write
export async function evaluateAstPolicy(sql, options = {}) {
  const { parserVersion } = options;

  // 2. Unsupported parser version is refused before touching the parser/facts.
  if (!isSupportedVersion(parserVersion)) {
    return denyResult('unsupported_version', parserVersion, 'unsupported_version', emptyFacts());
  }

  const facts = await extractAstFacts(sql, { parserVersion });

  // 1. Parse error takes precedence over every fact-based rule.
  if (facts.parseStatus === 'parse_error') {
    return denyResult('parse_error', parserVersion, 'parse_error', facts);
  }

  const deny = (reasonCode) => denyResult(reasonCode, parserVersion, 'parsed', facts);
  const topKind = facts.topLevelKinds[0] ?? null;

  // 3. The prototype only reasons about a single statement at a time.
  if (facts.statementCount !== 1) {
    return deny('multiple_statements');
  }

  // 4. Anything the prototype does not explicitly recognize fails closed.
  const isKnownTopKind =
    topKind === 'SelectStmt' || WRITE_KINDS.has(topKind) || UTILITY_KINDS.has(topKind);
  if (!isKnownTopKind) {
    return deny('unknown_statement');
  }

  // 5. Utility/dangerous statements (DO, DDL, COPY, transaction control, ...).
  if (facts.hasUtilityStatement || UTILITY_KINDS.has(topKind)) {
    return deny('utility_statement');
  }

  // 6. A write nested inside a CTE/subquery under a top-level select.
  if (facts.nestedWriteCount > 0) {
    return deny('nested_write');
  }

  // 7. Session/connection context mutation via known functions (set_config).
  if (facts.hasContextMutation) {
    return deny('context_mutation');
  }

  // 8. SELECT ... INTO materializes a new relation.
  if (facts.hasSelectInto) {
    return deny('select_into');
  }

  // 9. Any function that is not a recognized context-mutation name is unknown
  //    behavior; safety is never inferred from syntax alone.
  const hasUnsafeFunction = facts.functionNames.some(
    (name) => !CONTEXT_MUTATION_FUNCTIONS.has(name),
  );
  if (hasUnsafeFunction) {
    return deny('unsafe_function');
  }

  // 10. Top-level writes are out of scope for this read-only prototype.
  if (WRITE_KINDS.has(topKind)) {
    return deny('write_not_supported');
  }

  // Remaining shape: a single read-only SelectStmt with no flagged facts.
  if (topKind === 'SelectStmt') {
    return {
      decision: 'allow',
      reasonCode: 'safe_read',
      parserVersion,
      parseStatus: 'parsed',
      facts,
    };
  }

  return deny('unsupported_shape');
}
