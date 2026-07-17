import pg from 'pg';
import { evaluatePolicy } from './policyEngine.mjs';

const { Pool } = pg;

/**
 * Creates the PostgreSQL execution boundary used after policy approval.
 */
export function createDatabase({ connectionString, mode = 'read-only', pool } = {}) {
  if (mode !== 'read-only' && mode !== 'read-write') {
    throw new Error(`Unsupported database mode: ${mode}`);
  }

  const databasePool = pool ?? new Pool({ connectionString });

  async function executeAllowedQuery(sql) {
    if (mode === 'read-write') {
      return databasePool.query(sql);
    }

    const client = await databasePool.connect();
    let transactionOpen = false;
    try {
      await client.query('BEGIN READ ONLY');
      transactionOpen = true;
      const result = await client.query(sql);
      await client.query('COMMIT');
      transactionOpen = false;
      return result;
    } catch (error) {
      if (transactionOpen) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // Preserve the original execution error; the client is still released below.
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async function executeCompiled(compiled, principal) {
    const validCommands = new Set(['read', 'aggregate', 'mutate']);
    if (!compiled || !validCommands.has(compiled.command) || typeof compiled.text !== 'string' || !compiled.text.trim() || compiled.text.includes(';') || !Array.isArray(compiled.values)) {
      throw new Error('Invalid compiled query.');
    }
    if (compiled.command === 'mutate' && mode !== 'read-write') {
      throw new Error('Database is read-only.');
    }
    if (compiled.command === 'mutate' && (!Number.isInteger(compiled.maxRows) || compiled.maxRows <= 0)) {
      throw new Error('Invalid compiled mutation limit.');
    }
    if (!principal || typeof principal !== 'object'
      || !Object.hasOwn(principal, 'subject') || typeof principal.subject !== 'string' || !principal.subject.trim()
      || !Object.hasOwn(principal, 'organization') || typeof principal.organization !== 'string' || !principal.organization.trim()
      || !Object.hasOwn(principal, 'tenantId') || typeof principal.tenantId !== 'string' || !principal.tenantId.trim()) {
      throw new Error('Invalid database principal.');
    }
    const expectedStart = compiled.command === 'mutate' ? /^\s*UPDATE\b/i : /^\s*SELECT\b/i;
    if (!expectedStart.test(compiled.text)) throw new Error('Invalid compiled query.');
    const lexicalPolicy = evaluatePolicy(compiled.text, { mode: compiled.command === 'mutate' ? 'read-write' : 'read-only' });
    if (lexicalPolicy.decision !== 'allow') throw new Error('Invalid compiled query.');

    const client = await databasePool.connect();
    let transactionOpen = false;
    try {
      await client.query('BEGIN');
      transactionOpen = true;
      const readOnly = compiled.command === 'read' || compiled.command === 'aggregate';
      if (readOnly) await client.query('SET TRANSACTION READ ONLY');
      await client.query("SELECT set_config('app.subject', $1, true)", [principal.subject]);
      await client.query("SELECT set_config('app.organization', $1, true)", [principal.organization]);
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [principal.tenantId]);
      const result = await client.query(compiled.text, compiled.values);
      if (compiled.command === 'mutate' && result.rowCount > compiled.maxRows) {
        throw new Error('Mutation row limit exceeded.');
      }
      await client.query('COMMIT');
      transactionOpen = false;
      return result;
    } catch (error) {
      if (transactionOpen) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // Preserve the original failure while ensuring the client is released.
        }
      }
      if (error instanceof Error && (error.message === 'Mutation row limit exceeded.' || error.message === 'Invalid compiled query.')) throw error;
      throw new Error('Compiled query execution failed.');
    } finally {
      client.release();
    }
  }

  return {
    executeAllowedQuery,
    executeCompiled,
    close: () => databasePool.end(),
  };
}

/**
 * Produces the default production database without opening a connection until queried.
 */
export function createDefaultDatabase() {
  return createDatabase({
    connectionString: process.env.POSTGRES_URL,
    mode: process.env.POLICY_MODE ?? 'read-only',
  });
}
