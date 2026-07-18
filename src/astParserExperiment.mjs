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

      return {
        parserVersion: version,
        statementCount: parsed.stmts.length,
        statements: parsed.stmts.map((statement) => ({
          kind: Object.keys(statement.stmt)[0],
          raw: statement.stmt,
        })),
        raw: parsed,
      };
    },
  };
}
