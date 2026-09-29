-- @role: root
-- Credential resolution (architecture.md §5.2).
--
-- A bootstrapping problem the schema creates and must therefore solve: every scoped
-- query needs a tenant, and the tenant is discovered by looking up the caller's
-- credential -- in credential_bindings, which is itself tenant-scoped. With FORCE
-- ROW LEVEL SECURITY the table owner cannot read it either, so a plain
-- SECURITY DEFINER function does not help.
--
-- The options and why this one:
--
--   * grant trustos_app unscoped SELECT on credential_bindings
--     -> lets the application enumerate every tenant's client ids. Rejected.
--   * give the app role BYPASSRLS
--     -> disables tenant isolation everywhere to solve one lookup. Rejected.
--   * a dedicated resolver role with a narrow policy, reached only through a
--     SECURITY DEFINER function that requires an EXACT issuer + client id
--     -> the application can only ever learn the mapping for a credential it
--        already holds. Taken.
--
-- The function returns the minimum needed to establish scope. It deliberately does
-- not expose secrets (none are stored), other bindings, or any way to enumerate.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trustos_resolver') THEN
    -- NOLOGIN: nothing connects as this role. It exists only to own the function
    -- below, so its privileges are reachable through that one entry point.
    CREATE ROLE trustos_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO trustos_resolver;
GRANT SELECT ON public.credential_bindings, public.principals TO trustos_resolver;

DROP POLICY IF EXISTS credential_resolution ON public.credential_bindings;
CREATE POLICY credential_resolution ON public.credential_bindings
  FOR SELECT TO trustos_resolver USING (true);

DROP POLICY IF EXISTS credential_resolution ON public.principals;
CREATE POLICY credential_resolution ON public.principals
  FOR SELECT TO trustos_resolver USING (true);

CREATE OR REPLACE FUNCTION public.resolve_credential(p_issuer text, p_client_id text)
RETURNS TABLE (
  principal_id     uuid,
  tenant_id        uuid,
  environment_id   uuid,
  principal_type   text,
  binding_status   text,
  principal_status text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
-- Pinned: a SECURITY DEFINER function without a fixed search_path can be hijacked by
-- a caller-created schema shadowing these tables.
SET search_path = public, pg_temp
AS $$
  SELECT cb.principal_id, cb.tenant_id, cb.environment_id,
         p.type, cb.status, p.status
  FROM credential_bindings cb
  JOIN principals p ON p.tenant_id = cb.tenant_id AND p.id = cb.principal_id
  -- Exact match on both. No pattern, no partial, nothing enumerable.
  WHERE cb.issuer = p_issuer AND cb.provider_client_id = p_client_id
  LIMIT 1;
$$;

ALTER FUNCTION public.resolve_credential(text, text) OWNER TO trustos_resolver;
REVOKE ALL ON FUNCTION public.resolve_credential(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_credential(text, text) TO trustos_app;
