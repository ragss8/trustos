-- @role: root
-- Human session resolution, the console's equivalent of 006.
--
-- Same bootstrapping problem: a console token carries a user identity, and finding
-- which tenant that user belongs to means reading memberships, which is tenant-scoped.
--
-- Narrower than the credential resolver in one respect and wider in another:
--   * requires an exact user_id, so nothing is enumerable
--   * MAY return several rows, because one person can belong to several tenants.
--     The caller then picks a tenant explicitly and every later query is scoped to
--     it, so this returns candidates rather than granting anything.

GRANT SELECT ON public.memberships, public.organizations TO trustos_resolver;

DROP POLICY IF EXISTS membership_resolution ON public.memberships;
CREATE POLICY membership_resolution ON public.memberships
  FOR SELECT TO trustos_resolver USING (true);

DROP POLICY IF EXISTS membership_resolution ON public.organizations;
CREATE POLICY membership_resolution ON public.organizations
  FOR SELECT TO trustos_resolver USING (true);

CREATE OR REPLACE FUNCTION public.resolve_memberships(p_user_id text)
RETURNS TABLE (
  membership_id uuid,
  tenant_id     uuid,
  tenant_name   text,
  role          text,
  status        text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT m.id, m.tenant_id, o.name, m.role, m.status
  FROM memberships m
  JOIN organizations o ON o.id = m.tenant_id
  WHERE m.user_id = p_user_id AND m.status = 'active'
  ORDER BY o.name;
$$;

ALTER FUNCTION public.resolve_memberships(text) OWNER TO trustos_resolver;
REVOKE ALL ON FUNCTION public.resolve_memberships(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_memberships(text) TO trustos_app;
