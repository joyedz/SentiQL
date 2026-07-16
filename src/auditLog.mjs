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

const V2_SCHEMA = `
  id INTEGER PRIMARY KEY,
  timestamp TEXT NOT NULL,
  correlation_id TEXT,
  subject TEXT,
  organization TEXT,
  capability TEXT,
  purpose TEXT,
  resource TEXT,
  request_json TEXT,
  sql TEXT,
  decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'approval_required', 'error')),
  reason TEXT NOT NULL,
  policy_version TEXT,
  policy_hash TEXT,
  database_outcome TEXT,
  row_count INTEGER,
  session_id TEXT
`;

function createV2Table(database) {
  database.exec(`CREATE TABLE audit_entries (${V2_SCHEMA})`);
}

function migrateLegacyTable(database) {
  database.exec('BEGIN');
  try {
    database.exec(`CREATE TABLE audit_entries_v2 (${V2_SCHEMA})`);
    database.exec(`
      INSERT INTO audit_entries_v2 (id, timestamp, sql, decision, reason, session_id)
      SELECT id, timestamp, sql, decision, reason, session_id
      FROM audit_entries
      ORDER BY id ASC
    `);
    database.exec('DROP TABLE audit_entries');
    database.exec('ALTER TABLE audit_entries_v2 RENAME TO audit_entries');
    database.exec('COMMIT');
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // Preserve the migration error; rollback failure must not hide it.
    }
    throw error;
  }
}

function ensureV2Schema(database) {
  const columns = database.prepare("PRAGMA table_info('audit_entries')").all();
  if (columns.length === 0) {
    createV2Table(database);
    return;
  }
  if (!columns.some((column) => column.name === 'correlation_id')) {
    migrateLegacyTable(database);
  }
}

function parseRequest(requestJson) {
  if (requestJson === null || requestJson === undefined) {
    return null;
  }
  try {
    return JSON.parse(requestJson);
  } catch {
    return null;
  }
}

/**
 * Creates the local append-only audit store used by the MCP server and dashboard.
 */
export function createAuditLog(filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  const database = new DatabaseSync(filePath);
  try {
    ensureV2Schema(database);
  } catch (error) {
    database.close();
    throw error;
  }

  const insertEntry = database.prepare(`
    INSERT INTO audit_entries (
      timestamp, correlation_id, subject, organization, capability, purpose, resource,
      request_json, sql, decision, reason, policy_version, policy_hash,
      database_outcome, row_count, session_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const selectRecent = database.prepare(`
    SELECT id, timestamp, correlation_id, subject, organization, capability, purpose,
      resource, request_json, sql, decision, reason, policy_version, policy_hash,
      database_outcome, row_count, session_id
    FROM audit_entries
    ORDER BY timestamp DESC, id DESC
    LIMIT ?
  `);

  return {
    record({
      correlationId = null,
      subject = null,
      organization = null,
      capability = null,
      purpose = null,
      resource = null,
      request = null,
      sql = null,
      decision,
      reason,
      policyVersion = null,
      policyHash = null,
      databaseOutcome = null,
      rowCount = null,
      sessionId = null,
      timestamp = new Date().toISOString(),
    }) {
      const requestJson = request === null || request === undefined ? null : JSON.stringify(request);
      insertEntry.run(
        timestamp,
        correlationId,
        subject,
        organization,
        capability,
        purpose,
        resource,
        requestJson,
        sql,
        decision,
        reason,
        policyVersion,
        policyHash,
        databaseOutcome,
        rowCount,
        sessionId,
      );
    },

    listRecent(limit = 100) {
      return selectRecent.all(normalizeLimit(limit)).map((entry) => ({
        id: entry.id,
        timestamp: entry.timestamp,
        sql: entry.sql,
        decision: entry.decision,
        reason: entry.reason,
        correlationId: entry.correlation_id ?? null,
        subject: entry.subject ?? null,
        organization: entry.organization ?? null,
        capability: entry.capability ?? null,
        purpose: entry.purpose ?? null,
        resource: entry.resource ?? null,
        request: parseRequest(entry.request_json),
        policyVersion: entry.policy_version ?? null,
        policyHash: entry.policy_hash ?? null,
        databaseOutcome: entry.database_outcome ?? null,
        rowCount: entry.row_count ?? null,
        sessionId: entry.session_id ?? null,
      }));
    },

    close() {
      database.close();
    },
  };
}
