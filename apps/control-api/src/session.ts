import type { Pool } from 'pg';
import { type TokenValidator, type ValidatedToken } from '@trustos/auth';
import { withTenantTransaction, type ScopedClient } from '@trustos/database';

/**
 * Console sessions (architecture.md §5.1).
 *
 * Role comes from the SERVER's membership record, never from a token claim. A
 * provider role claim says what the identity provider believes; the membership row is
 * what this organization actually granted, and it can be revoked without waiting for
 * a token to expire.
 */

export class SessionError extends Error {
  constructor(
    readonly code: 'INVALID_CREDENTIAL' | 'NO_MEMBERSHIP' | 'FORBIDDEN' | 'STEP_UP_REQUIRED',
    message: string,
  ) {
    super(message);
    this.name = 'SessionError';
  }
}

export type ConsoleRole =
  'org_admin' | 'security_admin' | 'developer' | 'approver' | 'operator' | 'auditor';

export interface ConsoleSession {
  readonly membershipId: string;
  readonly tenantId: string;
  readonly tenantName: string;
  readonly role: ConsoleRole;
  readonly userId: string;
  readonly token: ValidatedToken;
}

export async function resolveSession(
  pool: Pool,
  validator: TokenValidator,
  authorizationHeader: string | undefined,
  requestedTenantId?: string,
): Promise<ConsoleSession> {
  if (!authorizationHeader?.startsWith('Bearer ')) {
    throw new SessionError('INVALID_CREDENTIAL', 'missing bearer token');
  }
  const token = await validator.validate(authorizationHeader.slice(7));

  // A machine token must not open a console session: §5.1 gates are written for an
  // interactively authenticated human, and a service account satisfying them would
  // defeat the approval workflow entirely.
  if (token.type !== 'human') {
    throw new SessionError('INVALID_CREDENTIAL', 'interactive session required');
  }

  const userId =
    typeof token.raw['preferred_username'] === 'string'
      ? token.raw['preferred_username']
      : token.subject;

  const r = await pool.query<{
    membership_id: string;
    tenant_id: string;
    tenant_name: string;
    role: ConsoleRole;
  }>(`SELECT * FROM resolve_memberships($1)`, [userId]);

  if (r.rows.length === 0) {
    throw new SessionError('NO_MEMBERSHIP', 'no active membership for this user');
  }

  // With several memberships the caller states which tenant; without one, and with
  // exactly one membership, it is unambiguous.
  const chosen = requestedTenantId
    ? r.rows.find((row) => row.tenant_id === requestedTenantId)
    : r.rows.length === 1
      ? r.rows[0]
      : undefined;

  if (!chosen) {
    throw new SessionError('FORBIDDEN', 'specify which organization to act in');
  }

  return {
    membershipId: chosen.membership_id,
    tenantId: chosen.tenant_id,
    tenantName: chosen.tenant_name,
    role: chosen.role,
    userId,
    token,
  };
}

/** Role gates (prd.md §4.1). Checked server-side against current membership. */
const ALL_ROLES: readonly ConsoleRole[] = [
  'org_admin',
  'security_admin',
  'developer',
  'approver',
  'operator',
  'auditor',
];

const PERMITTED: Record<string, readonly ConsoleRole[]> = {
  // Reading your own session is not a privilege. Gating it behind a resource
  // permission locks an approver out of the app before they can see anything.
  'session:read': ALL_ROLES,
  'agents:read': ['org_admin', 'security_admin', 'developer', 'operator', 'auditor'],
  'agents:contain': ['org_admin', 'security_admin', 'operator'],
  'approvals:read': ['org_admin', 'security_admin', 'approver', 'auditor'],
  // Approver eligibility is NOT implied by administrative status (prd.md §4.1), and
  // separation of duties is re-checked at resolution regardless of this gate.
  'approvals:resolve': ['approver'],
  'policies:read': ['org_admin', 'security_admin', 'developer', 'auditor'],
  'policies:publish': ['org_admin', 'security_admin'],
  'audit:read': ['org_admin', 'security_admin', 'operator', 'auditor'],
};

export function requirePermission(session: ConsoleSession, permission: string): void {
  const roles = PERMITTED[permission];
  if (!roles?.includes(session.role)) {
    throw new SessionError('FORBIDDEN', `role ${session.role} may not ${permission}`);
  }
}

export function inSessionScope<T>(
  pool: Pool,
  session: ConsoleSession,
  fn: (client: ScopedClient) => Promise<T>,
): Promise<T> {
  return withTenantTransaction(pool, { tenantId: session.tenantId }, fn);
}
