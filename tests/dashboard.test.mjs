import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { createDashboardApp } from '../dashboard/server.mjs';

test('returns recent audit entries from the dashboard API', async (t) => {
  const app = createDashboardApp({
    listRecent: (limit) => {
      assert.equal(limit, 200);
      return [{ id: 1, decision: 'deny' }];
    },
  });
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));

  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/audit`);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { entries: [{ id: 1, decision: 'deny' }] });
});

test('serves the dashboard console as static content', async (t) => {
  const app = createDashboardApp({ listRecent: () => [] });
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));

  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/`);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /SentiQL Audit Console/);
});

async function startTestServer(t, app) {
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));
  return server.address().port;
}

test('returns the bounded AST shadow review with allowlisted query options', async (t) => {
  let receivedOptions;
  const review = {
    totalRecords: 1,
    classificationCounts: { match: 1 },
    safetySignals: { ast_allow_heuristic_deny: 0, parse_errors: 0, unsupported_parser_results: 0 },
    recentEvents: [{ sqlDigest: 'sha256:opaque', classification: 'match' }],
  };
  const app = createDashboardApp({
    listRecent: () => [],
    getAstPolicyShadowReview: (options) => {
      receivedOptions = options;
      return review;
    },
  });
  const port = await startTestServer(t, app);

  const response = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?from=2026-07-20T00%3A00%3A00.000Z&to=2026-07-21T00%3A00%3A00.000Z&source=typed_capability&mode=read-only&parserVersion=16&classification=match&parseStatus=parsed&astReasonCode=safe_read&recentLimit=7`);

  assert.equal(response.status, 200);
  assert.deepEqual(receivedOptions, {
    from: '2026-07-20T00:00:00.000Z',
    to: '2026-07-21T00:00:00.000Z',
    source: 'typed_capability',
    mode: 'read-only',
    parserVersion: 16,
    classification: 'match',
    parseStatus: 'parsed',
    astReasonCode: 'safe_read',
    recentLimit: 7,
  });
  assert.deepEqual(await response.json(), review);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('passes an empty filter object for the default shadow review', async (t) => {
  let receivedOptions;
  const port = await startTestServer(t, createDashboardApp({
    listRecent: () => [],
    getAstPolicyShadowReview: (options) => {
      receivedOptions = options;
      return { recentEvents: [] };
    },
  }));

  const response = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review`);
  assert.equal(response.status, 200);
  assert.deepEqual(receivedOptions, {});
});

test('rejects unknown and malformed AST shadow review parameters without calling the reader', async (t) => {
  let calls = 0;
  const app = createDashboardApp({
    listRecent: () => [],
    getAstPolicyShadowReview: () => { calls += 1; return {}; },
  });
  const port = await startTestServer(t, app);

  const unknown = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?where=1%3D1`);
  const malformed = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?recentLimit=101`);
  const invalidTimestamp = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?from=2026-02-30T00%3A00%3A00.000Z`);
  const wideWindow = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?from=2026-07-01T00%3A00%3A00.000Z&to=2026-08-02T00%3A00%3A00.000Z`);
  assert.equal(unknown.status, 400);
  assert.deepEqual(await unknown.json(), { error: 'invalid_ast_shadow_review_request' });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: 'invalid_ast_shadow_review_request' });
  assert.equal(invalidTimestamp.status, 400);
  assert.deepEqual(await invalidTimestamp.json(), { error: 'invalid_ast_shadow_review_request' });
  assert.equal(wideWindow.status, 400);
  assert.deepEqual(await wideWindow.json(), { error: 'invalid_ast_shadow_review_request' });
  assert.equal(calls, 0);
});

test('contains a separate digest-only AST shadow review UI', async (t) => {
  const app = createDashboardApp({ listRecent: () => [], getAstPolicyShadowReview: () => ({ recentEvents: [] }) });
  const port = await startTestServer(t, app);
  const response = await fetch(`http://127.0.0.1:${port}/`);
  const html = await response.text();

  assert.match(html, /AST SHADOW REVIEW/);
  assert.match(html, /AUDIT SUMMARY/);
  assert.match(html, /audit-summary/);
  assert.match(html, /ast-shadow-review/);
  assert.match(html, /sqlDigest/);
  assert.doesNotMatch(html, /event\.sql\b/);
  assert.doesNotMatch(html, /event\.request\b/);
  assert.doesNotMatch(html, /event\.subject\b/);
});

test('returns a controlled error when the shadow reader fails', async (t) => {
  const port = await startTestServer(t, createDashboardApp({
    listRecent: () => [],
    getAstPolicyShadowReview: () => { throw new Error('private database detail'); },
  }));
  const response = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review`);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'ast_shadow_review_unavailable' });
});
