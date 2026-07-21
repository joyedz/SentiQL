#!/usr/bin/env node
import { resolve } from 'node:path';
import { createAuditLog } from '../src/auditLog.mjs';

const DEMO_EVENTS = [
  ['allow', 'Typed read allowed for tenant-scoped support cases.', 'SELECT completed', 12],
  ['allow', 'Filtered support-case read allowed.', 'SELECT completed', 3],
  ['deny', 'Requested field is outside the support-agent policy.', 'Not executed', 0],
  ['deny', 'Purpose marketing is not permitted for this capability.', 'Not executed', 0],
  ['allow', 'Bounded status mutation allowed by policy.', 'UPDATE completed', 1],
  ['approval_required', 'Escalation requires human approval before mutation.', 'Awaiting approval', 0],
  ['deny', 'Resource is not present in the policy bundle.', 'Not executed', 0],
  ['deny', 'Requested mutation field is not writable by this role.', 'Not executed', 0],
];

function parseDbPath(argv) {
  if (argv.length === 0) return resolve(process.env.AUDIT_DB_PATH ?? './data/audit.sqlite');
  if (argv.length === 2 && argv[0] === '--db' && argv[1]) return resolve(argv[1]);
  throw new Error('Usage: demo-seed [--db <path>]');
}

try {
  const auditPath = parseDbPath(process.argv.slice(2));
  const audit = createAuditLog(auditPath);
  try {
    DEMO_EVENTS.forEach(([decision, reason, databaseOutcome, rowCount], index) => {
      audit.record({
        timestamp: new Date(Date.now() - (DEMO_EVENTS.length - index) * 1000).toISOString(),
        subject: 'demo-support-agent',
        organization: 'demo-org',
        capability: index === 4 || index === 5 ? 'data.mutate' : 'data.read',
        purpose: 'customer_support',
        resource: 'crm.support_cases',
        request: { demo: true, caseNumber: index + 1 },
        sql: null,
        decision,
        reason: `DEMO: ${reason}`,
        policyVersion: '2026-07-17.1',
        policyHash: null,
        databaseOutcome,
        rowCount,
        sessionId: 'demo-session',
      });
    });
  } finally {
    audit.close();
  }
  process.stdout.write(`Seeded ${DEMO_EVENTS.length} demo audit events at ${auditPath}.\n`);
} catch (error) {
  process.stderr.write(`demo seed failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
