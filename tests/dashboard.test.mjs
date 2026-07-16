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
