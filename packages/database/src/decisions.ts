import type { ScopedClient } from './tenant-transaction.js';
import { appendAuditEvent, publishOutboxEvent } from './audit.js';

/**
 * Durable decision recording with idempotency (AUT-02, architecture.md §8.1).
 *
 * The guarantee: for one (tenant, environment, caller, route, key), exactly one
 * decision is ever created. A retry with the same body returns that original
 * decision; a retry with a DIFFERENT body is a conflict, never a second decision.
 *
 * PostgreSQL owns this, not Redis and not application logic (INVARIANT 2). The unique
 * constraint on idempotency_records is what holds under concurrency; everything below
 * is arrangement around it.
 */

export class IdempotencyConflictError extends Error {
  constructor(readonly existingDecisionId: string | null) {
    super('idempotency key was used with a different request body');
    this.name = 'IdempotencyConflictError';
    this.code = 'IDEMPOTENCY_CONFLICT';
  }
  readonly code: string;
}

export interface RecordDecisionInput {
  readonly environmentId: string;
  readonly callerId: string;
  readonly route: string;
  readonly idempotencyKeyHash: string;
  readonly requestHash: string;

  readonly principalId: string;
  readonly gatewayPrincipalId?: string | null;
  readonly actionKey: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly resourceVersion?: string | null;
  readonly businessDeadline?: string | null;

  readonly effect: 'allow' | 'deny' | 'approval_required';
  readonly mode: 'shadow' | 'enforced';
  readonly reasonCodes: readonly string[];
  readonly obligations: readonly string[];
  readonly bundleRevision: number;
  readonly principalEpoch: number;
  readonly credentialEpoch: number;
  readonly orgEpoch: number;
  readonly expiresAt: Date;
}

export interface RecordedDecision {
  readonly decisionId: string;
  readonly requestId: string;
  /** True when this call created the decision; false when it replayed an earlier one. */
  readonly created: boolean;
}

export async function recordDecision(
  client: ScopedClient,
  input: RecordDecisionInput,
): Promise<RecordedDecision> {
  const { tenantId } = client.scope;

  // Claim the key. ON CONFLICT DO NOTHING means exactly one concurrent caller gets a
  // row back; everyone else falls through to the replay path below.
  const claim = await client.query<{ id: string }>(
    `INSERT INTO idempotency_records
       (tenant_id, environment_id, caller_id, route, key_hash, request_hash, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6, now() + interval '24 hours')
     ON CONFLICT (tenant_id, environment_id, caller_id, route, key_hash) DO NOTHING
     RETURNING id`,
    [
      tenantId,
      input.environmentId,
      input.callerId,
      input.route,
      input.idempotencyKeyHash,
      input.requestHash,
    ],
  );

  if (claim.rows.length === 0) {
    return replayExisting(client, input);
  }

  const idempotencyId = claim.rows[0]!.id;

  const request = await client.query<{ id: string }>(
    `INSERT INTO authorization_requests
       (tenant_id, environment_id, principal_id, gateway_principal_id, action_key,
        resource_type, resource_id, resource_version, request_hash, business_deadline)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING id`,
    [
      tenantId,
      input.environmentId,
      input.principalId,
      input.gatewayPrincipalId ?? null,
      input.actionKey,
      input.resourceType,
      input.resourceId,
      input.resourceVersion ?? null,
      input.requestHash,
      input.businessDeadline ?? null,
    ],
  );
  const requestId = request.rows[0]!.id;

  const decision = await client.query<{ id: string }>(
    `INSERT INTO decisions
       (tenant_id, environment_id, request_id, effect, mode, reason_codes, obligations,
        bundle_revision, principal_epoch, credential_epoch, org_epoch, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING id`,
    [
      tenantId,
      input.environmentId,
      requestId,
      input.effect,
      input.mode,
      input.reasonCodes,
      input.obligations,
      input.bundleRevision,
      input.principalEpoch,
      input.credentialEpoch,
      input.orgEpoch,
      input.expiresAt,
    ],
  );
  const decisionId = decision.rows[0]!.id;

  await client.query(
    `UPDATE idempotency_records SET response_ref = $2, status_code = 200 WHERE id = $1`,
    [idempotencyId, decisionId],
  );

  // Same transaction as the decision. A decision nobody can audit did not happen.
  await appendAuditEvent(client, {
    environmentId: input.environmentId,
    actorType: 'agent',
    actorId: input.principalId,
    eventType: 'decision.created',
    subjectType: 'decision',
    subjectId: decisionId,
    safePayload: {
      effect: input.effect,
      mode: input.mode,
      action: input.actionKey,
      reason_codes: input.reasonCodes,
      bundle_revision: input.bundleRevision,
    },
  });

  await publishOutboxEvent(client, input.environmentId, 'decision.created', {
    decision_id: decisionId,
    effect: input.effect,
    mode: input.mode,
  });

  return { decisionId, requestId, created: true };
}

/**
 * The key already exists. Either a concurrent caller is mid-flight, or an earlier one
 * finished.
 *
 * FOR SHARE blocks until the winning transaction commits or rolls back, which is what
 * makes a concurrent duplicate wait for the original decision rather than racing past
 * it and creating a second one.
 */
async function replayExisting(
  client: ScopedClient,
  input: RecordDecisionInput,
): Promise<RecordedDecision> {
  const existing = await client.query<{
    request_hash: string;
    response_ref: string | null;
  }>(
    `SELECT request_hash, response_ref FROM idempotency_records
     WHERE tenant_id = $1 AND environment_id = $2 AND caller_id = $3
       AND route = $4 AND key_hash = $5
     FOR SHARE`,
    [tenantId(client), input.environmentId, input.callerId, input.route, input.idempotencyKeyHash],
  );

  const row = existing.rows[0];
  if (!row) {
    // The winner rolled back and released the key. Nothing was committed, so the
    // caller may legitimately try again.
    throw new Error('IDEMPOTENCY_RETRY');
  }

  // Same key, different body. AUT-02 requires 409: issuing a second decision under a
  // key the caller believes is settled is how one intent becomes two actions.
  if (row.request_hash !== input.requestHash) {
    throw new IdempotencyConflictError(row.response_ref);
  }

  if (!row.response_ref) {
    // Claimed but not yet resolved. Only reachable if the winner committed the claim
    // without the decision, which the single transaction above prevents.
    throw new Error('IDEMPOTENCY_RETRY');
  }

  const decision = await client.query<{ request_id: string }>(
    `SELECT request_id FROM decisions WHERE tenant_id = $1 AND id = $2`,
    [tenantId(client), row.response_ref],
  );

  return {
    decisionId: row.response_ref,
    requestId: decision.rows[0]?.request_id ?? '',
    created: false,
  };
}

function tenantId(client: ScopedClient): string {
  return client.scope.tenantId;
}
