import { createHash } from 'node:crypto';
import type { ScopedClient } from './tenant-transaction.js';

/**
 * Audit append (architecture.md §10.2, AUD-01, INVARIANT 6).
 *
 * Called INSIDE the business transaction. If this fails, the transaction fails and
 * nothing is acknowledged: "audit database write fails -> no success/grant
 * acknowledgement" (prd.md §18). Moving it after commit, or onto a queue, converts a
 * guarantee into a hope.
 *
 * Sequence allocation and hash chaining happen under a per-stream row lock, so two
 * concurrent writers cannot take the same sequence or fork the chain. That lock is a
 * known throughput ceiling (§13.1) and is meant to be measured before load increases.
 */

export interface AuditEventInput {
  readonly environmentId: string;
  readonly actorType: 'human' | 'agent' | 'service' | 'gateway' | 'system';
  readonly actorId?: string | null;
  readonly eventType: string;
  readonly subjectType: string;
  readonly subjectId?: string | null;
  /** Must already be masked. Never raw prompts, payloads or secrets (INVARIANT 13). */
  readonly safePayload: Record<string, unknown>;
}

export interface AppendedAuditEvent {
  readonly id: string;
  readonly sequence: string;
  readonly payloadHash: string;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((k) => [k, canonical((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

export async function appendAuditEvent(
  client: ScopedClient,
  input: AuditEventInput,
): Promise<AppendedAuditEvent> {
  const { tenantId } = client.scope;

  // Create the stream head on first use, then lock it. ON CONFLICT DO NOTHING keeps
  // two concurrent first-writers from racing on creation.
  await client.query(
    `INSERT INTO audit_stream_heads (tenant_id, environment_id)
     VALUES ($1, $2) ON CONFLICT (tenant_id, environment_id) DO NOTHING`,
    [tenantId, input.environmentId],
  );

  const head = await client.query<{ next_sequence: string; previous_hash: string | null }>(
    `SELECT next_sequence, previous_hash FROM audit_stream_heads
     WHERE tenant_id = $1 AND environment_id = $2
     FOR UPDATE`,
    [tenantId, input.environmentId],
  );
  const current = head.rows[0];
  if (!current) throw new Error('audit stream head missing after upsert');

  const sequence = current.next_sequence;
  const body = {
    sequence,
    actor_type: input.actorType,
    actor_id: input.actorId ?? null,
    event_type: input.eventType,
    subject_type: input.subjectType,
    subject_id: input.subjectId ?? null,
    safe_payload: canonical(input.safePayload),
    previous_hash: current.previous_hash,
  };
  const payloadHash = `sha256:${createHash('sha256')
    .update(JSON.stringify(canonical(body)))
    .digest('hex')}`;

  const inserted = await client.query<{ id: string }>(
    `INSERT INTO audit_events
       (tenant_id, environment_id, sequence, actor_type, actor_id, event_type,
        subject_type, subject_id, safe_payload, previous_hash, payload_hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     RETURNING id`,
    [
      tenantId,
      input.environmentId,
      sequence,
      input.actorType,
      input.actorId ?? null,
      input.eventType,
      input.subjectType,
      input.subjectId ?? null,
      JSON.stringify(input.safePayload),
      current.previous_hash,
      payloadHash,
    ],
  );

  await client.query(
    `UPDATE audit_stream_heads
     SET next_sequence = next_sequence + 1, previous_hash = $3, updated_at = now()
     WHERE tenant_id = $1 AND environment_id = $2`,
    [tenantId, input.environmentId, payloadHash],
  );

  return { id: inserted.rows[0]!.id, sequence, payloadHash };
}

/** Publishes to the outbox in the SAME transaction (§10.1). A committed decision whose
 *  event was never enqueued is not recoverable; this is why the outbox is a table. */
export async function publishOutboxEvent(
  client: ScopedClient,
  environmentId: string,
  eventType: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const r = await client.query<{ id: string }>(
    `INSERT INTO outbox_events (tenant_id, environment_id, event_type, payload)
     VALUES ($1,$2,$3,$4) RETURNING id`,
    [client.scope.tenantId, environmentId, eventType, JSON.stringify(payload)],
  );
  return r.rows[0]!.id;
}
