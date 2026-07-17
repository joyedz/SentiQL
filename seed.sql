-- Bootstrap runs as the distinct POSTGRES_USER owner (sentiql_bootstrap).
CREATE SCHEMA IF NOT EXISTS crm;

CREATE TABLE crm.support_cases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  status TEXT NOT NULL,
  assignee_id TEXT,
  priority INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The application role is deliberately non-owner and cannot bypass RLS.
DO $$
BEGIN
  CREATE ROLE sentiql_app LOGIN PASSWORD 'sentiql_app'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
  ALTER ROLE sentiql_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
END
$$;

GRANT USAGE ON SCHEMA crm TO sentiql_app;
GRANT SELECT, UPDATE ON TABLE crm.support_cases TO sentiql_app;

ALTER TABLE crm.support_cases ENABLE ROW LEVEL SECURITY;

CREATE POLICY support_cases_tenant_select ON crm.support_cases
  FOR SELECT TO sentiql_app
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY support_cases_tenant_update ON crm.support_cases
  FOR UPDATE TO sentiql_app
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Seed as the bootstrap owner before FORCE RLS is enabled.
INSERT INTO crm.support_cases (id, tenant_id, status, assignee_id, priority, created_at) VALUES
  ('case-a-001', 'tenant-a', 'open', 'agent-a', 2, '2026-07-01T09:00:00Z'),
  ('case-a-002', 'tenant-a', 'escalated', 'agent-a', 1, '2026-07-02T09:00:00Z'),
  ('case-b-001', 'tenant-b', 'open', 'agent-b', 3, '2026-07-03T09:00:00Z'),
  ('case-b-002', 'tenant-b', 'closed', 'agent-b', 4, '2026-07-04T09:00:00Z');

ALTER TABLE crm.support_cases FORCE ROW LEVEL SECURITY;
