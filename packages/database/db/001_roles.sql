-- @role: root
-- Role separation. This file is the reason row-level security means anything.
--
-- PostgreSQL lets a table's OWNER bypass RLS, and any role with BYPASSRLS or
-- SUPERUSER ignores it entirely. An application that connects as the owner is not
-- protected by the policies in 003_rls.sql; it just cannot see that it is not.
-- architecture.md §6.1 and ORG-01.
--
-- Four roles, three of them used:
--   trustos_root       bootstrap superuser. Creates the others. Never used again.
--   trustos_migrator   owns every table. Runs migrations. Not used at runtime.
--   trustos_app        the application. Non-owner, NOSUPERUSER, NOBYPASSRLS.
--   trustos_dispatcher cross-tenant job scheduling only (§6.1). Reads claim columns,
--                      never business rows; processing re-enters a scoped transaction.


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trustos_migrator') THEN
    CREATE ROLE trustos_migrator LOGIN PASSWORD 'local_dev_only'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trustos_app') THEN
    CREATE ROLE trustos_app LOGIN PASSWORD 'local_dev_only'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trustos_dispatcher') THEN
    CREATE ROLE trustos_dispatcher LOGIN PASSWORD 'local_dev_only'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;
END
$$;

-- The migrator owns the schema; the app may use it but never create in it, so a
-- compromised app role cannot shadow a table with one of its own.
ALTER SCHEMA public OWNER TO trustos_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO trustos_app, trustos_dispatcher;

-- No ambient privilege from the PUBLIC pseudo-role.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Future tables created by the migrator are reachable by the app by default, so a
-- new table is never accidentally left unreadable (or, worse, granted to PUBLIC).
-- RLS still governs which ROWS it sees; this is table-level reach only.
ALTER DEFAULT PRIVILEGES FOR ROLE trustos_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trustos_app;
ALTER DEFAULT PRIVILEGES FOR ROLE trustos_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO trustos_app;
