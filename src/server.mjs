#!/usr/bin/env node
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createAuditLog } from './auditLog.mjs';
import { createDefaultDatabase } from './db.mjs';
import { evaluatePolicy } from './policyEngine.mjs';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function resolveAuditPath(auditPath) {
  return isAbsolute(auditPath) ? auditPath : resolve(projectRoot, auditPath);
}

/**
 * Runs the governed policy-to-database flow. Collaborators are injected so this
 * function can be tested without starting an MCP transport or opening a DB.
 */
export async function processQuery(
  input,
  { mode = 'read-only', audit, execute, logError = (message) => console.error(message) },
) {
  const { sql, codexSessionId } = input;
  const sessionId = codexSessionId ?? null;
  const policy = evaluatePolicy(sql, { mode });

  if (policy.decision === 'deny') {
    try {
      audit.record({ sql, decision: 'deny', reason: policy.reason, sessionId });
    } catch (error) {
      logError(`Audit log failure while recording deny: ${errorMessage(error)}`);
      return {
        content: [{ type: 'text', text: `DENIED: ${policy.reason} (audit log unavailable.)` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: `DENIED: ${policy.reason}` }],
      isError: true,
    };
  }

  try {
    audit.record({ sql, decision: 'allow', reason: policy.reason, sessionId });
  } catch (error) {
    logError(`Audit log failure while recording allow: ${errorMessage(error)}`);
    return {
      content: [{ type: 'text', text: 'ERROR: audit log unavailable; query was not executed.' }],
      isError: true,
    };
  }

  try {
    const result = await execute(sql);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          rows: result.rows,
          command: result.command,
          rowCount: result.rowCount,
        }),
      }],
    };
  } catch (error) {
    logError(`Database execution failed: ${errorMessage(error)}`);
    try {
      audit.record({
        sql,
        decision: 'error',
        reason: 'Database execution failed.',
        sessionId,
      });
    } catch (auditError) {
      logError(`Audit log failure while recording error: ${errorMessage(auditError)}`);
    }
    return {
      content: [{ type: 'text', text: 'ERROR: database execution failed.' }],
      isError: true,
    };
  }
}

/** Starts the stdio MCP server only for the CLI entry point. */
export async function startServer() {
  const mode = process.env.POLICY_MODE ?? 'read-only';
  if (!process.env.POSTGRES_URL) {
    throw new Error('POSTGRES_URL is required to start SentiQL.');
  }
  const audit = createAuditLog(resolveAuditPath(process.env.AUDIT_DB_PATH ?? './data/audit.sqlite'));
  const database = createDefaultDatabase();
  const server = new McpServer({ name: 'sentiql', version: '1.0.0' });

  server.registerTool(
    'query',
    {
      title: 'Governed PostgreSQL query',
      description: 'Runs SQL only after SentiQL policy approval.',
      inputSchema: {
        sql: z.string(),
        codexSessionId: z.string().optional(),
      },
    },
    (input) => processQuery(input, {
      mode,
      audit,
      execute: database.executeAllowedQuery,
      logError: (message) => console.error(`[sentiql] ${message}`),
    }),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[sentiql] MCP server running');
  return { server, audit, database };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startServer();
}
