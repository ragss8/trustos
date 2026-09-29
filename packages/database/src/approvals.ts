import type { ScopedClient } from './tenant-transaction.js';
import { appendAuditEvent, publishOutboxEvent } from './audit.js';
import { issueGrant } from './grants.js';

/**
 * Approval resolution (APR-01..APR-03, architecture.md §8.2).
 *
 * Three properties carry the weight:
 *
 * 1. At most ONE terminal resolution. The first approve or reject wins; a racing
 *    second one is a conflict, not a second outcome.
 * 2. Eligibility and separation of duties are checked AT RESOLUTION, not only when
 *    the request was routed. Membership changes between routing and approval, and the
 *    check that matters is the one at the moment authority is granted (APR-03).
 * 3. Expiry uses server time at resolution. A late expiry worker must never make a
 *    dead request approvable (APR-01).
 *
 * Resolution events are append-only; only the current-state projection is mutated.
 */

export type ApprovalState = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled';

export type ResolutionRefusal =
  | 'NOT_FOUND'
  | 'ALREADY_RESOLVED'
  | 'EXPIRED'
  | 'NOT_ELIGIBLE'
  | 'SELF_APPROVAL'
  | 'APPROVER_INACTIVE';

export class ResolutionRefusedError extends Error {
  constructor(
    readonly code: ResolutionRefusal,
    message: string,
    readonly currentState?: ApprovalState,
  ) {
    super(message);
    this.name = 'ResolutionRefusedError';
  }
}

export interface CreateApprovalInput {
  readonly environmentId: string;
  readonly decisionId: string;
  readonly groupKey: string;
  readonly timeoutSeconds: number;
  /** A request may not outlive the business deadline it was raised for. */
  readonly businessDeadline?: Date | null;
}

export async function createApprovalRequest(
  client: ScopedClient,
  input: CreateApprovalInput,
): Promise<{ approvalId: string; expiresAt: Date }> {
  const group = await client.query<{ id: string }>(
    `SELECT id FROM approver_groups
     WHERE tenant_id = $1 AND group_key = $2 AND status = 'active'`,
    [client.scope.tenantId, input.groupKey],
  );
  const groupId = group.rows[0]?.id;
  if (!groupId) {
    // POL-06 routes to a group by key. A route to a group that does not exist would
    // create an approval nobody can ever resolve.
    throw new ResolutionRefusedError('NOT_FOUND', `approver group ${input.groupKey} not found`);
  }

  const byTimeout = new Date(Date.now() + input.timeoutSeconds * 1000);
  const expiresAt =
    input.businessDeadline && input.businessDeadline < byTimeout
      ? input.businessDeadline
      : byTimeout;

  const r = await client.query<{ id: string; expires_at: Date }>(
    `INSERT INTO approval_requests (tenant_id, environment_id, decision_id, group_id, expires_at)
     VALUES ($1,$2,$3,$4,$5) RETURNING id, expires_at`,
    [client.scope.tenantId, input.environmentId, input.decisionId, groupId, expiresAt],
  );

  await appendAuditEvent(client, {
    environmentId: input.environmentId,
    actorType: 'system',
    eventType: 'approval.requested',
    subjectType: 'approval',
    subjectId: r.rows[0]!.id,
    safePayload: { decision_id: input.decisionId, group_key: input.groupKey },
  });
  await publishOutboxEvent(client, input.environmentId, 'approval.requested', {
    approval_id: r.rows[0]!.id,
    decision_id: input.decisionId,
    group_key: input.groupKey,
  });

  return { approvalId: r.rows[0]!.id, expiresAt: r.rows[0]!.expires_at };
}

export interface ResolveApprovalInput {
  readonly approvalId: string;
  readonly actorMembershipId: string;
  readonly effect: 'approved' | 'rejected';
  readonly reason?: string;
  readonly sessionEvidence?: Record<string, unknown>;
  /** Grant lifetime when approving. prd.md §8.1 default is 60 seconds. */
  readonly grantTtlSeconds?: number;
  readonly gatewayAudience?: string;
}

export interface ResolutionOutcome {
  readonly approvalId: string;
  readonly state: ApprovalState;
  readonly grantId: string | null;
  /** False when this call replayed an identical earlier resolution. */
  readonly resolvedNow: boolean;
}

export async function resolveApproval(
  client: ScopedClient,
  input: ResolveApprovalInput,
): Promise<ResolutionOutcome> {
  const { tenantId } = client.scope;

  // Lock the projection for the whole transaction. Compare-and-set alone would let
  // two resolvers both pass their eligibility checks before either wrote.
  const r = await client.query<{
    id: string;
    environment_id: string;
    decision_id: string;
    group_id: string;
    state: ApprovalState;
    version: number;
    expired: boolean;
  }>(
    `SELECT id, environment_id, decision_id, group_id, state, version,
            (expires_at <= now()) AS expired
     FROM approval_requests
     WHERE tenant_id = $1 AND id = $2
     FOR UPDATE`,
    [tenantId, input.approvalId],
  );

  const request = r.rows[0];
  if (!request) throw new ResolutionRefusedError('NOT_FOUND', 'approval request not found');

  if (request.state !== 'pending') {
    return replayResolution(client, request.id, request.state, input);
  }

  // Server time decides, not the stored state. APR-01: "expiry checks use server
  // time even if scheduler is delayed", so a request whose projection still reads
  // 'pending' is refused here the moment its deadline passes.
  //
  // Deliberately no state write on this path: we are about to throw, and the throw
  // rolls the transaction back, so any transition written here would be silently
  // discarded. The projection is caught up by expirePendingApprovals(), and the
  // authoritative answer in the meantime is this refusal.
  if (request.expired) {
    throw new ResolutionRefusedError('EXPIRED', 'approval request expired', 'expired');
  }

  await assertEligible(client, request.group_id, request.decision_id, input.actorMembershipId);

  // version guards against a concurrent writer that slipped between our read and
  // write; with FOR UPDATE held this is belt and braces, and cheap.
  const updated = await client.query<{ id: string }>(
    `UPDATE approval_requests
     SET state = $3, resolved_at = now(), version = version + 1
     WHERE tenant_id = $1 AND id = $2 AND state = 'pending' AND version = $4
     RETURNING id`,
    [tenantId, request.id, input.effect, request.version],
  );
  if (updated.rows.length === 0) {
    throw new ResolutionRefusedError('ALREADY_RESOLVED', 'approval was resolved concurrently');
  }

  await recordEvent(
    client,
    request.id,
    input.actorMembershipId,
    input.effect,
    input.reason ?? null,
    input.sessionEvidence ?? {},
  );

  let grantId: string | null = null;
  if (input.effect === 'approved') {
    // Same transaction as the resolution (§8.2). A webhook failure afterwards cannot
    // undo a committed approval, and an approval without its grant would strand the
    // caller with no way to act on a decision that says yes.
    grantId = await issueGrantForDecision(
      client,
      request.environment_id,
      request.decision_id,
      input,
    );
  }

  await appendAuditEvent(client, {
    environmentId: request.environment_id,
    actorType: 'human',
    actorId: input.actorMembershipId,
    eventType: `approval.${input.effect}`,
    subjectType: 'approval',
    subjectId: request.id,
    safePayload: { decision_id: request.decision_id, reason: input.reason ?? null },
  });
  await publishOutboxEvent(client, request.environment_id, 'approval.resolved', {
    approval_id: request.id,
    decision_id: request.decision_id,
    effect: input.effect,
  });

  return { approvalId: request.id, state: input.effect, grantId, resolvedNow: true };
}

/**
 * APR-03. Eligibility is membership in the routed group AND separation of duties.
 *
 * The separation check is the one that matters: prd.md §4.1 requires disallowing
 * approval by the request initiator or the agent owner. Someone who can both request
 * and approve has an approval workflow in name only.
 */
async function assertEligible(
  client: ScopedClient,
  groupId: string,
  decisionId: string,
  actorMembershipId: string,
): Promise<void> {
  const membership = await client.query<{ status: string }>(
    `SELECT m.status
     FROM approver_group_members agm
     JOIN memberships m ON m.tenant_id = agm.tenant_id AND m.id = agm.membership_id
     WHERE agm.tenant_id = $1 AND agm.group_id = $2 AND agm.membership_id = $3
       AND agm.status = 'active'`,
    [client.scope.tenantId, groupId, actorMembershipId],
  );
  const member = membership.rows[0];
  if (!member) {
    throw new ResolutionRefusedError('NOT_ELIGIBLE', 'actor is not in the routed approver group');
  }
  // Checked now, not at routing: membership can be revoked in between.
  if (member.status !== 'active') {
    throw new ResolutionRefusedError('APPROVER_INACTIVE', 'approver membership is not active');
  }

  const owner = await client.query<{ owner_membership_id: string | null }>(
    `SELECT p.owner_membership_id
     FROM decisions d
     JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
     JOIN principals p ON p.tenant_id = r.tenant_id AND p.id = r.principal_id
     WHERE d.tenant_id = $1 AND d.id = $2`,
    [client.scope.tenantId, decisionId],
  );
  if (owner.rows[0]?.owner_membership_id === actorMembershipId) {
    // prd.md §18: "Owner attempts own sensitive approval -> rejected by server."
    throw new ResolutionRefusedError(
      'SELF_APPROVAL',
      'the agent owner may not approve its own action',
    );
  }
}

async function issueGrantForDecision(
  client: ScopedClient,
  environmentId: string,
  decisionId: string,
  input: ResolveApprovalInput,
): Promise<string> {
  const d = await client.query<{
    request_hash: string;
    bundle_revision: number;
    principal_epoch: number;
    credential_epoch: number;
    business_deadline: Date | null;
  }>(
    `SELECT r.request_hash, d.bundle_revision, d.principal_epoch, d.credential_epoch,
            r.business_deadline
     FROM decisions d
     JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
     WHERE d.tenant_id = $1 AND d.id = $2`,
    [client.scope.tenantId, decisionId],
  );
  const row = d.rows[0];
  if (!row) throw new ResolutionRefusedError('NOT_FOUND', 'decision not found');

  const { grantId } = await issueGrant(client, {
    environmentId,
    decisionId,
    gatewayAudience: input.gatewayAudience ?? 'default',
    requestHash: row.request_hash,
    bundleRevision: row.bundle_revision,
    principalEpoch: row.principal_epoch,
    credentialEpoch: row.credential_epoch,
    ttlSeconds: input.grantTtlSeconds ?? 60,
    businessDeadline: row.business_deadline,
  });
  return grantId;
}

/**
 * Already terminal. An exact retry by the same actor with the same effect returns the
 * prior resolution; anything else is a conflict (§8.2).
 */
async function replayResolution(
  client: ScopedClient,
  approvalId: string,
  state: ApprovalState,
  input: ResolveApprovalInput,
): Promise<ResolutionOutcome> {
  const prior = await client.query<{ actor_id: string | null; effect: string }>(
    `SELECT actor_id, effect FROM approval_events
     WHERE tenant_id = $1 AND request_id = $2
     ORDER BY created_at DESC LIMIT 1`,
    [client.scope.tenantId, approvalId],
  );
  const event = prior.rows[0];

  if (event && event.actor_id === input.actorMembershipId && event.effect === input.effect) {
    const g = await client.query<{ id: string }>(
      `SELECT g.id FROM execution_grants g
       JOIN approval_requests a ON a.decision_id = g.decision_id AND a.tenant_id = g.tenant_id
       WHERE g.tenant_id = $1 AND a.id = $2`,
      [client.scope.tenantId, approvalId],
    );
    return {
      approvalId,
      state,
      grantId: g.rows[0]?.id ?? null,
      resolvedNow: false,
    };
  }

  // prd.md §18: "Two approval resolutions race -> one winner, other gets
  // terminal-state response."
  throw new ResolutionRefusedError('ALREADY_RESOLVED', `approval is already ${state}`, state);
}

async function transitionToTerminal(
  client: ScopedClient,
  approvalId: string,
  state: ApprovalState,
  version: number,
): Promise<void> {
  await client.query(
    `UPDATE approval_requests
     SET state = $3, resolved_at = now(), version = version + 1
     WHERE tenant_id = $1 AND id = $2 AND version = $4`,
    [client.scope.tenantId, approvalId, state, version],
  );
}

async function recordEvent(
  client: ScopedClient,
  requestId: string,
  actorId: string | null,
  effect: string,
  reason: string | null,
  sessionEvidence: Record<string, unknown>,
): Promise<void> {
  // Append-only. The projection above is what changes; history never does.
  await client.query(
    `INSERT INTO approval_events (tenant_id, request_id, actor_id, effect, reason, session_evidence)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [client.scope.tenantId, requestId, actorId, effect, reason, JSON.stringify(sessionEvidence)],
  );
}

/** Expiry sweep. Server time decides; this only records what is already true. */
export async function expirePendingApprovals(client: ScopedClient, limit = 100): Promise<string[]> {
  const due = await client.query<{ id: string; version: number; environment_id: string }>(
    `SELECT id, version, environment_id FROM approval_requests
     WHERE tenant_id = $1 AND state = 'pending' AND expires_at <= now()
     ORDER BY expires_at LIMIT $2
     FOR UPDATE SKIP LOCKED`,
    [client.scope.tenantId, limit],
  );

  const expired: string[] = [];
  for (const row of due.rows) {
    await transitionToTerminal(client, row.id, 'expired', row.version);
    await recordEvent(client, row.id, null, 'expired', 'server deadline reached', {});
    await appendAuditEvent(client, {
      environmentId: row.environment_id,
      actorType: 'system',
      eventType: 'approval.expired',
      subjectType: 'approval',
      subjectId: row.id,
      safePayload: {},
    });
    expired.push(row.id);
  }
  return expired;
}
