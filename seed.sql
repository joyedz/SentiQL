CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  role TEXT NOT NULL
);

CREATE TABLE orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  total_cents INTEGER NOT NULL
);

INSERT INTO users (email, role) VALUES
  ('alex@example.com', 'admin'),
  ('bea@example.com', 'analyst');

INSERT INTO orders (user_id, total_cents) VALUES
  (1, 2599),
  (1, 4999),
  (2, 1250);
