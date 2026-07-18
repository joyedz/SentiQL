export const fixtures = [
  { name: 'small-select', category: 'small-read', sql: 'SELECT id FROM users WHERE id = $1' },
  { name: 'medium-join', category: 'medium-read', sql: 'SELECT u.id, count(o.id) FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE u.active = true GROUP BY u.id ORDER BY u.id LIMIT $1' },
  { name: 'complex-cte-window', category: 'complex-read', sql: 'WITH recent AS (SELECT user_id, total, row_number() OVER (PARTITION BY user_id ORDER BY created_at DESC) AS rn FROM orders WHERE created_at >= $1) SELECT user_id, total FROM recent WHERE rn = 1' },
  { name: 'bounded-update', category: 'safe-write', sql: 'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, role' },
  { name: 'writable-cte', category: 'nested-write', sql: 'WITH changed AS (UPDATE users SET role = $1 WHERE id = $2 RETURNING id) SELECT * FROM changed' },
  { name: 'drop-table', category: 'unsafe-utility', sql: 'DROP TABLE users' },
  { name: 'context-mutation', category: 'unsafe-function', sql: "SELECT set_config('app.tenant_id', $1, true)" },
  { name: 'stacked-statements', category: 'multi-statement', sql: 'SELECT 1; SELECT 2' },
  { name: 'dollar-quoted-literal', category: 'literal-stress', sql: 'SELECT $$DROP TABLE users;$$ AS message' },
  { name: 'malformed', category: 'malformed', sql: 'SELECT FROM' },
];
