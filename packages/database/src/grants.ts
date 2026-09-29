import type { ScopedClient } from './tenant-transaction.js';
import { appendAuditEvent, publishOutboxEvent } from './audit.js';

/**
 * Execution grants and consumption (AUT-07, architecture.md §8.3).
 *
 * This is the enforcement boundary. A decision says "permitted"; only a CONSUMED
 * grant authorises a destination write, and a grant may be consumed exactly once.
 *
 * That uniqueness is a database constraint (consumption_receipts.grant_id UNIQUE),
 * not a check in this file. Everything here arranges for the constraint to be the
 * thing that decides, so two concurrent gateways cannot both win.
 *
 * What this cannot do: stop a buggy gateway calling the destination twice after one
 * successful consume, and stop an in-flight execution once consumed. Both are stated
 * limits (§8.3), not oversights.
 */

export type ConsumeRefusal =
  | 'GRANT_NOT_FOUND'
  | 'GRANT_ALREADY_CONSUMED'
  | 'GRANT_EXPIRED'
  | 'GRANT_REVOKED'
  | 'WRONG_AUDIENCE'
  | 'REQUEST_HASH_MISMATCH'
  | 'AUTHORITY_STALE'
  | 'POLICY_CHANGED'
  | 'RESOURCE_CHANGED'
  | 'EXECUTION_KEY_REUSED';

export class ConsumeRefusedError extends Error {
  constructor(
    readonly code: ConsumeRefusal,
    message: string,
  ) {
    super(message);
    this.name = 'ConsumeRefusedError';
  }
}

export interface IssueGrantInput {
  readonly environmentId: string;
  readonly decisionId: string;
  readonly gatewayAudience: string;
  readonly requestHash: string;
  readonly bundleRevision: number;
  readonly principalEpoch: number;
  readonly credentialEpoch: number;
  readonly ttlSeconds: number;
  /** A grant never outlives the request's business deadline (§8.3). */
  readonly businessDeadline?: Date | null;
}

export async function issueGrant(
  client: ScopedClient,
  input: IssueGrantInput,
): Promise<{ grantId: string; expiresAt: Date }> {
  // Shadow mode must never reach here. Checked at the source rather than trusted:
  // INVARIANT 3 says a non-enforcing evaluation cannot produce execution authority.
  const mode = await client.query<{ mode: string; enforcement: string }>(
    `SELECT d.mode, e.enforcement
     FROM decisions d JOIN environments e ON e.tenant_id = d.tenant_id AND e.id = d.environment_id
     WHERE d.tenant_id = $1 AND d.id = $2`,
    [client.scope.tenantId, input.decisionId],
  );
  const row = mode.rows[0];
  if (!row) throw new ConsumeRefusedError('GRANT_NOT_FOUND', 'decision not found');
  if (row.mode !== 'enforced' || row.enforcement !== 'enforced') {
    throw new ConsumeRefusedError(
      'AUTHORITY_STALE',
      'shadow decisions cannot produce an executable grant',
    );
  }

  const ttlMs = input.ttlSeconds * 1000;
  const byTtl = new Date(Date.now() + ttlMs);
  const expiresAt =
    input.businessDeadline && input.businessDeadline < byTtl ? input.businessDeadline : byTtl;

  const g = await client.query<{ id: string; expires_at: Date }>(
    `INSERT INTO execution_grants
       (tenant_id, environment_id, decision_id, gateway_audience, request_hash,
        bundle_revision, principal_epoch, credential_epoch, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING id, expires_at`,
    [
      client.scope.tenantId,
      input.environmentId,
      input.decisionId,
      input.gatewayAudience,
      input.requestHash,
      input.bundleRevision,
      input.principalEpoch,
      input.credentialEpoch,
      expiresAt,
    ],
  );

  return { grantId: g.rows[0]!.id, expiresAt: g.rows[0]!.expires_at };
}

export interface ConsumeGrantInput {
  readonly grantId: string;
  readonly gatewayPrincipalId: string;
  readonly gatewayAudience: string;
  readonly requestHash: string;
  /** The gateway's durable handle on one execution intent. */
  readonly executionKey: string;
  readonly resourceVersion?: string | null;
}

export interface ConsumptionReceipt {
  readonly receiptId: string;
  readonly grantId: string;
  readonly decisionId: string;
  readonly executionKey: string;
  readonly consumedAt: Date;
  /** False when an earlier identical call already consumed it and this recovered the
   *  original receipt. Recovery is not new authority and must not lead to a second
   *  destination call. */
  readonly consumedNow: boolean;
}

export async function consumeGrant(
  client: ScopedClient,
  input: ConsumeGrantInput,
): Promise<ConsumptionReceipt> {
  const { tenantId } = client.scope;

  // Lock the grant first and hold it for the whole transaction. Every check below
  // reads state that a concurrent suspension or publication could change.
  const g = await client.query<{
    id: string;
    decision_id: string;
    environment_id: string;
    gateway_audience: string;
    request_hash: string;
    state: string;
    bundle_revision: number;
    principal_epoch: number;
    credential_epoch: number;
    expired: boolean;
  }>(
    `SELECT id, decision_id, environment_id, gateway_audience, request_hash, state,
            bundle_revision, principal_epoch, credential_epoch,
            (expires_at <= now()) AS expired
     FROM execution_grants
     WHERE tenant_id = $1 AND id = $2
     FOR UPDATE`,
    [tenantId, input.grantId],
  );

  const grant = g.rows[0];
  if (!grant) throw new ConsumeRefusedError('GRANT_NOT_FOUND', 'grant not found');

  if (grant.state === 'consumed') {
    return recoverReceipt(client, grant.id, input);
  }

  // Audience and fingerprint before anything else: a grant presented by the wrong
  // gateway, or for a different request, is not a stale grant — it is the attack the
  // binding exists to stop.
  if (grant.gateway_audience !== input.gatewayAudience) {
    throw new ConsumeRefusedError('WRONG_AUDIENCE', 'grant is bound to a different gateway');
  }
  if (grant.request_hash !== input.requestHash) {
    throw new ConsumeRefusedError('REQUEST_HASH_MISMATCH', 'grant is bound to a different request');
  }
  if (grant.state === 'revoked') {
    throw new ConsumeRefusedError('GRANT_REVOKED', 'grant was revoked');
  }
  // Server time, never a caller-supplied timestamp.
  if (grant.expired) {
    await client.query(
      `UPDATE execution_grants SET state = 'expired' WHERE tenant_id = $1 AND id = $2`,
      [tenantId, input.grantId],
    );
    throw new ConsumeRefusedError('GRANT_EXPIRED', 'grant expired before consumption');
  }

  // Re-read current authority. The decision recorded epochs at the time it was made;
  // if anything moved since, the grant is stale (§8.3 step 3).
  const authority = await client.query<{
    principal_epoch: number;
    credential_epoch: number;
    agent_status: string;
    owner_status: string | null;
    kill_switch_engaged: boolean;
    env_status: string;
    current_bundle_revision: number;
  }>(
    `SELECT p.auth_epoch AS principal_epoch,
            COALESCE(cb.credential_epoch, $3) AS credential_epoch,
            p.status AS agent_status,
            m.status AS owner_status,
            e.kill_switch_engaged, e.status AS env_status, e.current_bundle_revision
     FROM execution_grants g
     JOIN decisions d ON d.tenant_id = g.tenant_id AND d.id = g.decision_id
     JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
     JOIN principals p ON p.tenant_id = r.tenant_id AND p.id = r.principal_id
     JOIN environments e ON e.tenant_id = g.tenant_id AND e.id = g.environment_id
     LEFT JOIN memberships m ON m.tenant_id = p.tenant_id AND m.id = p.owner_membership_id
     LEFT JOIN credential_bindings cb
       ON cb.tenant_id = p.tenant_id AND cb.principal_id = p.id AND cb.status = 'active'
     WHERE g.tenant_id = $1 AND g.id = $2
     LIMIT 1`,
    [tenantId, input.grantId, grant.credential_epoch],
  );

  const now = authority.rows[0];
  if (!now) throw new ConsumeRefusedError('AUTHORITY_STALE', 'authority could not be established');

  if (now.kill_switch_engaged || now.env_status !== 'active') {
    throw new ConsumeRefusedError('AUTHORITY_STALE', 'environment is not accepting executions');
  }
  if (now.agent_status !== 'active' || now.owner_status !== 'active') {
    throw new ConsumeRefusedError('AUTHORITY_STALE', 'agent or owner is no longer active');
  }
  if (
    now.principal_epoch !== grant.principal_epoch ||
    now.credential_epoch !== grant.credential_epoch
  ) {
    // OPS-01: a suspension that committed after issuance lands here.
    throw new ConsumeRefusedError(
      'AUTHORITY_STALE',
      'authority changed after the grant was issued',
    );
  }
  // ADR-009: publishing a revision invalidates unconsumed grants. A new decision is
  // required, and if it still needs approval, a new approval.
  if (now.current_bundle_revision !== grant.bundle_revision) {
    throw new ConsumeRefusedError(
      'POLICY_CHANGED',
      'policy was published after the grant was issued',
    );
  }

  // Conditional update: an approved action must not land on a record that changed
  // after the decision was made (§8.3 step 4).
  if (input.resourceVersion !== undefined && input.resourceVersion !== null) {
    const expected = await client.query<{ resource_version: string | null }>(
      `SELECT r.resource_version
       FROM decisions d JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
       WHERE d.tenant_id = $1 AND d.id = $2`,
      [tenantId, grant.decision_id],
    );
    const decided = expected.rows[0]?.resource_version ?? null;
    if (decided !== null && decided !== input.resourceVersion) {
      throw new ConsumeRefusedError('RESOURCE_CHANGED', 'resource changed since the decision');
    }
  }

  // Mark consumed and write the receipt together. The UNIQUE constraint on grant_id
  // is what makes this safe under concurrency; if a racing transaction committed
  // first, this INSERT fails and we recover their receipt rather than issuing a
  // second authority.
  await client.query(
    `UPDATE execution_grants SET state = 'consumed' WHERE tenant_id = $1 AND id = $2`,
    [tenantId, input.grantId],
  );

  let receipt: { id: string; consumed_at: Date };
  try {
    const r = await client.query<{ id: string; consumed_at: Date }>(
      `INSERT INTO consumption_receipts (tenant_id, grant_id, gateway_id, execution_key)
       VALUES ($1,$2,$3,$4) RETURNING id, consumed_at`,
      [tenantId, input.grantId, input.gatewayPrincipalId, input.executionKey],
    );
    receipt = r.rows[0]!;
  } catch (error) {
    const pg = error as { code?: string; constraint?: string };
    if (pg.code === '23505') {
      // Two DIFFERENT unique constraints can fire here and they mean different
      // things. Reporting both as GRANT_ALREADY_CONSUMED hides a gateway bug:
      //
      //   grant_id          another transaction consumed this grant first
      //   ...execution_key  THIS gateway already used that execution key for a
      //                     DIFFERENT grant, which means its operation ledger is
      //                     reusing handles and it may be about to execute twice
      if (pg.constraint?.includes('execution_key')) {
        throw new ConsumeRefusedError(
          'EXECUTION_KEY_REUSED',
          'execution key already used by this gateway for a different grant',
        );
      }
      throw new ConsumeRefusedError('GRANT_ALREADY_CONSUMED', 'grant was already consumed');
    }
    throw error;
  }

  await appendAuditEvent(client, {
    environmentId: grant.environment_id,
    actorType: 'gateway',
    actorId: input.gatewayPrincipalId,
    eventType: 'grant.consumed',
    subjectType: 'grant',
    subjectId: input.grantId,
    safePayload: { decision_id: grant.decision_id, execution_key: input.executionKey },
  });
  await publishOutboxEvent(client, grant.environment_id, 'grant.consumed', {
    grant_id: input.grantId,
    decision_id: grant.decision_id,
  });

  return {
    receiptId: receipt.id,
    grantId: input.grantId,
    decisionId: grant.decision_id,
    executionKey: input.executionKey,
    consumedAt: receipt.consumed_at,
    consumedNow: true,
  };
}

/**
 * Already consumed. The same gateway presenting the same execution key is recovering
 * a lost response and gets the original receipt back; anyone else gets refused.
 *
 * Recovery is explicitly NOT new authority (§8.3) — it exists so a gateway that lost
 * the response can learn what already happened instead of guessing.
 */
async function recoverReceipt(
  client: ScopedClient,
  grantId: string,
  input: ConsumeGrantInput,
): Promise<ConsumptionReceipt> {
  const r = await client.query<{
    id: string;
    gateway_id: string;
    execution_key: string;
    consumed_at: Date;
    decision_id: string;
  }>(
    `SELECT cr.id, cr.gateway_id, cr.execution_key, cr.consumed_at, g.decision_id
     FROM consumption_receipts cr
     JOIN execution_grants g ON g.tenant_id = cr.tenant_id AND g.id = cr.grant_id
     WHERE cr.tenant_id = $1 AND cr.grant_id = $2`,
    [client.scope.tenantId, grantId],
  );
  const existing = r.rows[0];
  if (!existing)
    throw new ConsumeRefusedError('GRANT_ALREADY_CONSUMED', 'grant was already consumed');

  if (
    existing.gateway_id !== input.gatewayPrincipalId ||
    existing.execution_key !== input.executionKey
  ) {
    // A different caller, or the same caller with a different intent. Either way this
    // is a second execution attempt, not a recovery.
    throw new ConsumeRefusedError('GRANT_ALREADY_CONSUMED', 'grant was already consumed');
  }

  return {
    receiptId: existing.id,
    grantId,
    decisionId: existing.decision_id,
    executionKey: existing.execution_key,
    consumedAt: existing.consumed_at,
    consumedNow: false,
  };
}
