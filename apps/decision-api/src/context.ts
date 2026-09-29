import type { Pool } from 'pg';
import { type TokenValidator, type ValidatedToken } from '@trustos/auth';
import { withTenantTransaction, type ScopedClient } from '@trustos/database';

/**
 * Caller context (architecture.md §5.2, INVARIANT 5).
 *
 * Tenant and environment are resolved from the credential's server-side mapping.
 * Nothing the caller sends contributes to scope: no body field, no header hint, no
 * query parameter. A supplied hint that disagrees is rejected rather than honoured.
 */

export class AuthenticationError extends Error {
  constructor(
    readonly code: 'INVALID_CREDENTIAL' | 'CALLER_SCOPE_DENIED',
    message: string,
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export interface CallerContext {
  readonly principalId: string;
  readonly tenantId: string;
  readonly environmentId: string;
  readonly principalType: 'agent' | 'gateway' | 'service' | 'human';
  readonly clientId: string;
  readonly token: ValidatedToken;
}

/**
 * Maps a validated token to a principal.
 *
 * Goes through resolve_credential() rather than querying credential_bindings, because
 * that table is tenant-scoped and this lookup is what DISCOVERS the tenant. See
 * db/006_credential_resolver.sql: the function requires an exact issuer + client id,
 * so the application can only learn the mapping for a credential it already holds,
 * and it still cannot read the table itself.
 */
export async function resolveCaller(
  pool: Pool,
  validator: TokenValidator,
  authorizationHeader: string | undefined,
): Promise<CallerContext> {
  if (!authorizationHeader?.startsWith('Bearer ')) {
    throw new AuthenticationError('INVALID_CREDENTIAL', 'missing bearer token');
  }
  const token = await validator.validate(authorizationHeader.slice(7));

  if (token.type !== 'machine' || !token.clientId) {
    // The decision API is a machine surface. A human session here would mean a
    // console token being replayed against the enforcement path.
    throw new AuthenticationError('CALLER_SCOPE_DENIED', 'machine credential required');
  }

  const r = await pool.query<{
    principal_id: string;
    tenant_id: string;
    environment_id: string;
    principal_type: CallerContext['principalType'];
    binding_status: string;
    principal_status: string;
  }>(`SELECT * FROM resolve_credential($1, $2)`, [token.issuer, token.clientId]);

  const row = r.rows[0];
  // Unknown client and revoked credential are the same answer to the caller: a
  // difference here tells an attacker which client ids exist.
  if (!row || row.binding_status !== 'active' || row.principal_status !== 'active') {
    throw new AuthenticationError('INVALID_CREDENTIAL', 'credential is not active');
  }

  return {
    principalId: row.principal_id,
    tenantId: row.tenant_id,
    environmentId: row.environment_id,
    principalType: row.principal_type,
    clientId: token.clientId,
    token,
  };
}

/** Every handler runs inside the caller's scope. There is no unscoped path. */
export function inCallerScope<T>(
  pool: Pool,
  caller: CallerContext,
  fn: (client: ScopedClient) => Promise<T>,
): Promise<T> {
  return withTenantTransaction(
    pool,
    { tenantId: caller.tenantId, environmentId: caller.environmentId },
    fn,
  );
}
