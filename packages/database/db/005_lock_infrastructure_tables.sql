-- @role: root
-- schema_migrations is infrastructure, not tenant data: it has no tenant_id, so a
-- row-level policy on it would be meaningless. The correct control is that the
-- application role cannot reach it at all.
--
-- The isolation suite asserts every table is EITHER covered by RLS+FORCE OR
-- unreachable by trustos_app. This file satisfies the second branch, and exists as a
-- separate migration because 001-004 are already applied and checksummed: editing an
-- applied migration is how environments silently diverge (expand/migrate/contract).

REVOKE ALL ON TABLE public.schema_migrations FROM trustos_app, trustos_dispatcher, PUBLIC;
