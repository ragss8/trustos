import { Pool } from 'pg';

/**
 * The application pool. Connects as trustos_app: a non-owner role with neither
 * SUPERUSER nor BYPASSRLS, so the policies in db/004_rls.sql actually apply to it.
 * Connecting as the owner or as trustos_root silently disables tenant isolation.
 */
export function createPool(connectionString: string): Pool {
  return new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    // Fail fast rather than queueing behind an exhausted pool: INVARIANT 1 prefers a
    // 503 to an unbounded wait on the decision path.
    connectionTimeoutMillis: 5_000,
    application_name: 'trustos',
  });
}
