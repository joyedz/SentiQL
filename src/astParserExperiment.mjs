import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  Parser,
  getSupportedVersions,
  isSupportedVersion,
} = require('@pgsql/parser');
const SUPPORTED_VERSIONS = getSupportedVersions();

export function getSupportedAstParserVersions() {
  return [...SUPPORTED_VERSIONS];
}

// Normalize optional parser AST fields so unexpected shapes remain inspectable.
export function normalizeAstParserResult(parsed, parserVersion) {
  const statements = parsed.stmts ?? [];

  return {
    parserVersion,
    statementCount: statements.length,
    statements: statements.map((statement) => {
      const raw = statement?.stmt;
      const kind = raw ? Object.keys(raw)[0] : null;

      return {
        kind: kind ?? null,
        raw,
      };
    }),
    raw: parsed,
  };
}

function walk(value, visit) {
  if (!value || typeof value !== 'object') return;
  visit(value);

  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit);
    return;
  }

  for (const child of Object.values(value)) walk(child, visit);
}

export function summarizeAst(result) {
  const summary = {
    statementKinds: result.statements.map(({ kind }) => kind),
    nestedStatementKinds: [],
    writeNodeCount: 0,
    functionCallCount: 0,
    utilityNodeCount: 0,
  };
  const writeKinds = new Set(['InsertStmt', 'UpdateStmt', 'DeleteStmt', 'MergeStmt']);
  const utilityKinds = new Set([
    'CreateStmt',
    'AlterTableStmt',
    'DropStmt',
    'TruncateStmt',
    'CopyStmt',
    'DoStmt',
    'TransactionStmt',
  ]);
  const topLevelKinds = new Set(summary.statementKinds);

  walk(result.raw, node => {
    for (const key of Object.keys(node)) {
      if (writeKinds.has(key)) summary.writeNodeCount += 1;
      if (utilityKinds.has(key)) summary.utilityNodeCount += 1;
      if (key === 'FuncCall') summary.functionCallCount += 1;
      if (key.endsWith('Stmt') && !topLevelKinds.has(key)) summary.nestedStatementKinds.push(key);
    }
  });

  return summary;
}

export function createAstParser(version) {
  if (!isSupportedVersion(version)) {
    throw new Error(`Unsupported PostgreSQL parser version: ${version}`);
  }

  const parser = new Parser({ version });

  return {
    version: parser.version,
    ready: parser.ready,
    async parse(sql) {
      if (typeof sql !== 'string' || !sql.trim()) {
        throw new Error('SQL must be a non-empty string.');
      }
      const raw = sql.trim();

      const parsed = await parser.parse(raw);

      return normalizeAstParserResult(parsed, version);
    },
  };
}
