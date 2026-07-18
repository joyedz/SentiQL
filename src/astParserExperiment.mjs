import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Parser } = require('@pgsql/parser');
const SUPPORTED_VERSIONS = [13, 14, 15, 16, 17, 18];

export function getSupportedAstParserVersions() {
  return [...SUPPORTED_VERSIONS];
}

export function createAstParser(version) {
  if (!SUPPORTED_VERSIONS.includes(version)) {
    throw new Error(`Unsupported PostgreSQL version: ${version}`);
  }

  const parser = new Parser({ version });

  return {
    version: parser.version,
    ready: parser.ready,
    async parse(sql) {
      const raw = sql?.trim();
      if (!raw) {
        throw new Error('SQL must be non-empty');
      }

      const parsed = await parser.parse(raw);
      const rawStatements = raw
        .split(';')
        .map((statement) => statement.trim())
        .filter(Boolean);

      return {
        parserVersion: version,
        statementCount: parsed.stmts.length,
        statements: parsed.stmts.map((statement, index) => ({
          kind: Object.keys(statement.stmt)[0],
          raw: rawStatements[index] ?? raw,
        })),
        raw,
      };
    },
  };
}
