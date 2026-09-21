-- Row-level security (architecture.md §6.1, ORG-01, INVARIANT 5).
--
-- Scope comes from transaction-local settings, never from a query parameter the
-- caller influenced. The application sets them with set_config(..., true) INSIDE the
-- transaction; the 'true' is what makes it transaction-local, which is the only safe
-- form under a connection pool. Connection-level SET leaks scope to whoever gets the
-- connection next.
--
-- Fail-closed by construction: with no setting, current_tenant_id() is NULL, every
-- comparison is NULL rather than true, and both USING and WITH CHECK reject. An
-- unscoped query returns zero rows and an unscoped insert errors. It does not see
-- everything.
--
-- Policies are generated in a loop on purpose. Twenty-seven hand-copied blocks is
-- twenty-seven chances to paste the wrong column name and leave a table open.


CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT nullif(current_setting('trustos.tenant_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION current_environment_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT nullif(current_setting('trustos.environment_id', true), '')::uuid $$;

REVOKE ALL ON FUNCTION current_tenant_id(), current_environment_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION current_tenant_id(), current_environment_id()
  TO trustos_app, trustos_dispatcher;

DO $$
DECLARE
  t record;
  has_env boolean;
  predicate text;
BEGIN
  FOR t IN
    SELECT c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      -- Every table carrying tenant_id is in scope. organizations is handled after
      -- the loop: its own id IS the tenant id.
      AND EXISTS (
        SELECT 1 FROM pg_attribute a
        WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
      )
    ORDER BY c.relname
  LOOP
    SELECT EXISTS (
      SELECT 1 FROM pg_attribute a
      JOIN pg_class c2 ON c2.oid = a.attrelid
      JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
      WHERE n2.nspname = 'public' AND c2.relname = t.table_name
        AND a.attname = 'environment_id' AND a.attnum > 0 AND NOT a.attisdropped
    ) INTO has_env;

    -- Tenant is always strict. Environment narrows further WHEN the setting is
    -- present; the decision path always sets it. Tenant isolation never depends on
    -- the environment setting being remembered.
    predicate := 'tenant_id = current_tenant_id()';
    IF has_env THEN
      predicate := predicate ||
        ' AND (current_environment_id() IS NULL OR environment_id IS NOT DISTINCT FROM current_environment_id())';
    END IF;

    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.table_name);
    -- FORCE applies the policy to the table OWNER as well. Without it, migrations
    -- and any accidental owner connection silently see every tenant.
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t.table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', t.table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON public.%I FOR ALL TO trustos_app USING (%s) WITH CHECK (%s)',
      t.table_name, predicate, predicate
    );
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO trustos_app', t.table_name);
  END LOOP;
END
$$;

-- organizations is the tenant root: its primary key IS the tenant id.
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.organizations;
CREATE POLICY tenant_isolation ON public.organizations FOR ALL TO trustos_app
  USING (id = current_tenant_id()) WITH CHECK (id = current_tenant_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organizations TO trustos_app;

-- The dispatcher may see only enough of the outbox to schedule work. Processing
-- re-enters a normally scoped transaction as trustos_app (§6.1).
GRANT SELECT (id, tenant_id, environment_id, dispatch_state, claimed_until, created_at)
  ON public.outbox_events TO trustos_dispatcher;
