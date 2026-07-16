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

export function createDashboardApp(audit) {
  const app = express();

  app.get('/api/audit', (_request, response) => {
    response.json({ entries: audit.listRecent(200) });
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
