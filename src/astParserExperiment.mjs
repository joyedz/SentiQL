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
