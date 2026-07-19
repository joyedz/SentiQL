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

// Conservative, fail-closed evaluator. Parse errors and unsupported versions are
// denied before any facts are inspected.
export async function evaluateAstPolicy(sql, options = {}) {
  const { parserVersion } = options;

  if (!isSupportedVersion(parserVersion)) {
    return denyResult('unsupported_version', parserVersion, 'unsupported_version', emptyFacts());
  }

  const facts = await extractAstFacts(sql, { parserVersion });

  if (facts.parseStatus === 'parse_error') {
    return denyResult('parse_error', parserVersion, 'parse_error', facts);
  }

  const isSafeRead =
    facts.statementCount === 1 &&
    facts.topLevelKinds.length === 1 &&
    facts.topLevelKinds[0] === 'SelectStmt' &&
    facts.nestedWriteCount === 0 &&
    !facts.hasUtilityStatement &&
    !facts.hasContextMutation &&
    !facts.hasSelectInto &&
    facts.functionNames.length === 0;

  if (isSafeRead) {
    return {
      decision: 'allow',
      reasonCode: 'safe_read',
      parserVersion,
      parseStatus: 'parsed',
      facts,
    };
  }

  return denyResult('unsupported_shape', parserVersion, 'parsed', facts);
}
