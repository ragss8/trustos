import type { Pool, PoolClient } from 'pg';

/**
 * Tenant-scoped transactions (architecture.md §6.1, INVARIANT 5).
 *
 * Every scoped query goes through here. The rules this enforces are the ones that are
 * easy to get wrong in a way nothing visibly fails on:
 *
 * 1. Scope is set with set_config(..., is_local => true), so it lives and dies with
 *    the transaction. A plain `SET` would persist on the pooled connection and hand
 *    the next borrower another tenant's scope.
 *
 * 2. The SAME client runs every statement. Taking a second connection from the pool
 *    mid-transaction gets one with no scope set, where RLS correctly returns nothing
 *    and the bug surfaces as mysterious empty results.
 *
 * 3. Scope is never interpolated into SQL. It is passed as a bound parameter and
 *    validated as a UUID first.
 */

/** UUID v1-v8, any variant. Rejects anything that is not one. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface TenantScope {
  readonly tenantId: string;
  /** Omit for tenant-level work (memberships, org settings). */
  readonly environmentId?: string;
}

export class InvalidTenantScopeError extends Error {
  constructor(field: string, value: unknown) {
    super(`${field} must be a UUID, received ${JSON.stringify(value)}`);
    this.name = 'InvalidTenantScopeError';
  }
}

/**
 * A client already inside a scoped transaction. Handed to the callback so callers
 * cannot accidentally use the bare pool and escape the scope.
 */
export interface ScopedClient {
  query: PoolClient['query'];
  readonly scope: TenantScope;
}

function assertScope(scope: TenantScope): void {
  if (typeof scope.tenantId !== 'string' || !UUID.test(scope.tenantId)) {
    throw new InvalidTenantScopeError('tenantId', scope.tenantId);
  }
  if (scope.environmentId !== undefined && !UUID.test(scope.environmentId)) {
    throw new InvalidTenantScopeError('environmentId', scope.environmentId);
  }
}

export async function withTenantTransaction<T>(
  pool: Pool,
  scope: TenantScope,
  fn: (client: ScopedClient) => Promise<T>,
): Promise<T> {
  // Validate BEFORE taking a connection: a bad scope should not consume pool capacity.
  assertScope(scope);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // is_local => true. This is the entire safety property under a pool.
    await client.query('SELECT set_config($1, $2, true)', ['trustos.tenant_id', scope.tenantId]);
    await client.query('SELECT set_config($1, $2, true)', [
      'trustos.environment_id',
      scope.environmentId ?? '',
    ]);

    const scoped: ScopedClient = {
      query: client.query.bind(client) as PoolClient['query'],
      scope,
    };

    const result = await fn(scoped);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    // Best-effort rollback: if the connection is already broken this throws, and the
    // original error is the one worth surfacing.
    try {
      await client.query('ROLLBACK');
    } catch {
      /* connection unusable; release() below discards it */
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Bootstrapping an organization is the one case where scope cannot be read from an
 * existing row: the tenant does not exist yet. The caller generates the ID, scopes the
 * transaction to it, and the RLS WITH CHECK still applies, so the insert is only
 * permitted when the row's own id matches the scope it declared.
 *
 * This deliberately avoids a privileged bootstrap role that bypasses RLS.
 */
export async function withNewTenantTransaction<T>(
  pool: Pool,
  tenantId: string,
  fn: (client: ScopedClient) => Promise<T>,
): Promise<T> {
  return withTenantTransaction(pool, { tenantId }, fn);
}
