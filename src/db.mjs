import pg from 'pg';

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

  return {
    executeAllowedQuery,
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
