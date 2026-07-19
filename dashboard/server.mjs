#!/usr/bin/env node
import express from 'express';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuditLog } from '../src/auditLog.mjs';

const dashboardDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(dashboardDirectory, '..');

export function resolveAuditPath(auditPath) {
  return isAbsolute(auditPath) ? auditPath : resolve(projectRoot, auditPath);
}

const SHADOW_REVIEW_QUERY_KEYS = new Set([
  'from', 'to', 'source', 'mode', 'parserVersion', 'classification',
  'parseStatus', 'astReasonCode', 'recentLimit',
]);
const SHADOW_REVIEW_ENUMS = {
  source: new Set(['raw_query_compatibility', 'typed_capability']),
  mode: new Set(['read-only', 'read-write']),
  classification: new Set(['match', 'ast_deny_heuristic_allow', 'ast_allow_heuristic_deny', 'decision_match_reason_diff', 'parse_error', 'unsupported']),
  parseStatus: new Set(['parsed', 'parse_error', 'unsupported_version']),
  astReasonCode: new Set(['safe_read', 'parse_error', 'unsupported_version', 'multiple_statements', 'unknown_statement', 'utility_statement', 'nested_write', 'context_mutation', 'select_into', 'trivial_where', 'unknown_where', 'unsafe_function', 'write_not_supported', 'unsupported_shape', 'unknown']),
};

function shadowQueryValue(query, key) {
  const value = query[key];
  if (Array.isArray(value) || typeof value !== 'string' || value.length === 0) throw new Error('Invalid AST shadow review parameter.');
  return value;
}

const MAX_SHADOW_REVIEW_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;
const SHADOW_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?Z$/;

function validateShadowTimestamp(value) {
  const match = SHADOW_TIMESTAMP_PATTERN.exec(value);
  if (!match) throw new Error('Invalid AST shadow review timestamp.');
  const [, year, month, day, hour, minute, second] = match;
  const parsed = new Date(0);
  parsed.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  parsed.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (
    parsed.getUTCFullYear() !== Number(year)
    || parsed.getUTCMonth() !== Number(month) - 1
    || parsed.getUTCDate() !== Number(day)
    || parsed.getUTCHours() !== Number(hour)
    || parsed.getUTCMinutes() !== Number(minute)
    || parsed.getUTCSeconds() !== Number(second)
  ) throw new Error('Invalid AST shadow review timestamp.');
  return parsed.getTime();
}

function validateShadowWindow(options) {
  const from = options.from === undefined ? undefined : validateShadowTimestamp(options.from);
  const to = options.to === undefined ? undefined : validateShadowTimestamp(options.to);
  if (from !== undefined && to !== undefined && (to < from || to - from > MAX_SHADOW_REVIEW_WINDOW_MS)) {
    throw new Error('Invalid AST shadow review window.');
  }
}

export function parseShadowReviewQuery(query = {}) {
  const options = {};
  for (const key of Object.keys(query)) {
    if (!SHADOW_REVIEW_QUERY_KEYS.has(key)) throw new Error('Unknown AST shadow review parameter.');
  }
  for (const key of ['from', 'to']) {
    if (query[key] !== undefined) options[key] = shadowQueryValue(query, key);
  }
  for (const key of ['source', 'mode', 'classification', 'parseStatus', 'astReasonCode']) {
    if (query[key] === undefined) continue;
    const value = shadowQueryValue(query, key);
    if (!SHADOW_REVIEW_ENUMS[key].has(value)) throw new Error('Invalid AST shadow review parameter.');
    options[key] = value;
  }
  for (const key of ['parserVersion', 'recentLimit']) {
    if (query[key] === undefined) continue;
    const value = shadowQueryValue(query, key);
    const maximum = key === 'recentLimit' ? 100 : 999;
    if (!/^\d+$/.test(value) || Number(value) > maximum) throw new Error('Invalid AST shadow review parameter.');
    options[key] = Number(value);
  }
  validateShadowWindow(options);
  return options;
}

export function createDashboardApp(audit) {
  const app = express();

  app.get('/api/audit', (_request, response) => {
    response.json({ entries: audit.listRecent(200) });
  });
  app.get('/api/ast-shadow-review', (request, response) => {
    let options;
    try {
      options = parseShadowReviewQuery(request.query);
    } catch {
      response.status(400).json({ error: 'invalid_ast_shadow_review_request' });
      return;
    }
    if (!audit || typeof audit.getAstPolicyShadowReview !== 'function') {
      response.status(503).json({ error: 'ast_shadow_review_unavailable' });
      return;
    }
    try {
      response.set('Cache-Control', 'no-store');
      response.json(audit.getAstPolicyShadowReview(options));
    } catch {
      response.status(503).json({ error: 'ast_shadow_review_unavailable' });
    }
  });
  app.use(express.static(resolve(dashboardDirectory, 'public')));

  return app;
}

export function startDashboard() {
  const audit = createAuditLog(resolveAuditPath(process.env.AUDIT_DB_PATH ?? './data/audit.sqlite'));
  const app = createDashboardApp(audit);
  const host = process.env.DASHBOARD_HOST ?? '127.0.0.1';
  const port = Number(process.env.DASHBOARD_PORT ?? 3030);
  const server = app.listen(port, host, () => {
    console.error(`[sentiql-dashboard] listening on http://${host}:${port}`);
  });
  return { app, audit, server };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startDashboard();
}
