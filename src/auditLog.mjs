import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const MAX_RECENT_ENTRIES = 500;

function normalizeLimit(limit) {
  const numericLimit = Number(limit);
  if (!Number.isFinite(numericLimit)) {
    return 100;
  }
  return Math.max(1, Math.min(MAX_RECENT_ENTRIES, Math.floor(numericLimit)));
}

/**
 * Creates the local append-only audit store used by the MCP server and dashboard.
 */
export function createAuditLog(filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  const database = new DatabaseSync(filePath);
  database.exec(`
    CREATE TABLE IF NOT EXISTS audit_entries (
      id INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      sql TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'error')),
      reason TEXT NOT NULL,
      session_id TEXT
    )
  `);

  const insertEntry = database.prepare(`
    INSERT INTO audit_entries (timestamp, sql, decision, reason, session_id)
    VALUES (?, ?, ?, ?, ?)
  `);
  const selectRecent = database.prepare(`
    SELECT id, timestamp, sql, decision, reason, session_id
    FROM audit_entries
    ORDER BY timestamp DESC, id DESC
    LIMIT ?
  `);

  return {
    record({ sql, decision, reason, sessionId = null, timestamp = new Date().toISOString() }) {
      insertEntry.run(timestamp, sql, decision, reason, sessionId);
    },

    listRecent(limit = 100) {
      return selectRecent.all(normalizeLimit(limit)).map((entry) => ({
        id: entry.id,
        timestamp: entry.timestamp,
        sql: entry.sql,
        decision: entry.decision,
        reason: entry.reason,
        sessionId: entry.session_id,
      }));
    },

    close() {
      database.close();
    },
  };
}
