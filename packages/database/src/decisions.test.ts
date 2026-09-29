import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createPool } from './pool.js';
import { withNewTenantTransaction, withTenantTransaction } from './tenant-transaction.js';
import { IdempotencyConflictError, recordDecision, type RecordDecisionInput } from './decisions.js';
import { appendAuditEvent } from './audit.js';

const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgresql://trustos_app:local_dev_only@localhost:55432/trustos';

let pool: Pool;
const tenant = randomUUID();
let environmentId: string;
let principalId: string;

beforeAll(async () => {
  pool = createPool(APP_URL);
  await withNewTenantTransaction(pool, tenant, async (c) => {
    await c.query('INSERT INTO organizations (id, name, region) VALUES ($1,$2,$3)', [
      tenant,
      'Concurrency Co',
      'IN',
    ]);
    const env = await c.query<{ id: string }>(
      `INSERT INTO environments (tenant_id, name, mode, enforcement)
       VALUES ($1,'sandbox','sandbox','enforced') RETURNING id`,
      [tenant],
    );
    environmentId = env.rows[0]!.id;
    const p = await c.query<{ id: string }>(
      `INSERT INTO principals (tenant_id, environment_id, type, name)
       VALUES ($1,$2,'agent','test agent') RETURNING id`,
      [tenant, environmentId],
    );
    principalId = p.rows[0]!.id;
  });
});

afterAll(async () => {
  await pool?.end();
});

function decisionInput(over: Partial<RecordDecisionInput> = {}): RecordDecisionInput {
  return {
    environmentId,
    callerId: principalId,
    route: 'POST /v1/authorize',
    idempotencyKeyHash: `sha256:${'a'.repeat(64)}`,
    requestHash: `sha256:${'b'.repeat(64)}`,
    principalId,
    actionKey: 'crm.discount.apply',
    resourceType: 'crm.lead',
    resourceId: 'lead_1',
    resourceVersion: '17',
    effect: 'allow',
    mode: 'enforced',
    reasonCodes: ['discount_within_authority'],
    obligations: ['execution_report_required'],
    bundleRevision: 1,
    principalEpoch: 1,
    credentialEpoch: 1,
    orgEpoch: 1,
    expiresAt: new Date(Date.now() + 60_000),
    ...over,
  };
}

async function countDecisions(): Promise<number> {
  return withTenantTransaction(pool, { tenantId: tenant }, async (c) =>
    Number((await c.query<{ n: string }>('SELECT count(*) AS n FROM decisions')).rows[0]!.n),
  );
}

describe('idempotency (AUT-02)', () => {
  it('returns the original decision for the same key and body', async () => {
    const key = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
    const first = await withTenantTransaction(pool, { tenantId: tenant }, (c) =>
      recordDecision(c, decisionInput({ idempotencyKeyHash: key })),
    );
    const second = await withTenantTransaction(pool, { tenantId: tenant }, (c) =>
      recordDecision(c, decisionInput({ idempotencyKeyHash: key })),
    );

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.decisionId).toBe(first.decisionId);
  });

  it('rejects the same key with a different body rather than deciding twice', async () => {
    const key = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
    await withTenantTransaction(pool, { tenantId: tenant }, (c) =>
      recordDecision(
        c,
        decisionInput({ idempotencyKeyHash: key, requestHash: `sha256:${'1'.repeat(64)}` }),
      ),
    );
    await expect(
      withTenantTransaction(pool, { tenantId: tenant }, (c) =>
        recordDecision(
          c,
          decisionInput({ idempotencyKeyHash: key, requestHash: `sha256:${'2'.repeat(64)}` }),
        ),
      ),
    ).rejects.toBeInstanceOf(IdempotencyConflictError);
  });

  it('creates exactly ONE decision under 16 concurrent identical requests', async () => {
    // The gate. Sixteen callers race on one key; the unique constraint decides.
    const key = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
    const before = await countDecisions();

    const results = await Promise.allSettled(
      Array.from({ length: 16 }, () =>
        withTenantTransaction(pool, { tenantId: tenant }, (c) =>
          recordDecision(c, decisionInput({ idempotencyKeyHash: key })),
        ),
      ),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const created = fulfilled.filter((r) => r.value.created);
    const replayed = fulfilled.filter((r) => !r.value.created);

    expect(created).toHaveLength(1);
    expect(replayed.length).toBeGreaterThan(0);
    // Every replay must point at the one decision that was actually created.
    const id = created[0]!.value.decisionId;
    for (const r of replayed) expect(r.value.decisionId).toBe(id);
    expect(await countDecisions()).toBe(before + 1);
  });

  it('keeps decisions separate across different keys', async () => {
    const before = await countDecisions();
    await Promise.all(
      Array.from({ length: 5 }, () =>
        withTenantTransaction(pool, { tenantId: tenant }, (c) =>
          recordDecision(
            c,
            decisionInput({
              idempotencyKeyHash: `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`,
            }),
          ),
        ),
      ),
    );
    expect(await countDecisions()).toBe(before + 5);
  });
});

describe('audit atomicity (AUD-01, INVARIANT 6)', () => {
  it('writes an audit event in the same transaction as the decision', async () => {
    const key = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
    const { decisionId } = await withTenantTransaction(pool, { tenantId: tenant }, (c) =>
      recordDecision(c, decisionInput({ idempotencyKeyHash: key })),
    );
    const rows = await withTenantTransaction(
      pool,
      { tenantId: tenant },
      async (c) =>
        (
          await c.query('SELECT 1 FROM audit_events WHERE subject_id = $1 AND event_type = $2', [
            decisionId,
            'decision.created',
          ])
        ).rows,
    );
    expect(rows).toHaveLength(1);
  });

  it('rolls the decision back when the audit write fails', async () => {
    // prd.md §18: "Audit database write fails -> no success/grant acknowledgement".
    const before = await countDecisions();
    await expect(
      withTenantTransaction(pool, { tenantId: tenant }, async (c) => {
        await recordDecision(
          c,
          decisionInput({
            idempotencyKeyHash: `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`,
          }),
        );
        // Violates the payload_hash CHECK, standing in for any audit failure.
        await c.query(
          `INSERT INTO audit_events (tenant_id, environment_id, sequence, actor_type,
             event_type, subject_type, payload_hash)
           VALUES ($1,$2,999999,'system','forced.failure','test','not-a-valid-hash')`,
          [tenant, environmentId],
        );
      }),
    ).rejects.toThrow();
    expect(await countDecisions()).toBe(before);
  });

  it('chains sequences contiguously without forking under concurrency', async () => {
    await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        withTenantTransaction(pool, { tenantId: tenant }, (c) =>
          appendAuditEvent(c, {
            environmentId,
            actorType: 'system',
            eventType: 'test.concurrent',
            subjectType: 'test',
            safePayload: { i },
          }),
        ),
      ),
    );

    const rows = await withTenantTransaction(
      pool,
      { tenantId: tenant },
      async (c) =>
        (
          await c.query<{ sequence: string; previous_hash: string | null; payload_hash: string }>(
            `SELECT sequence, previous_hash, payload_hash FROM audit_events
           WHERE environment_id = $1 ORDER BY sequence`,
            [environmentId],
          )
        ).rows,
    );

    // No duplicates, no gaps: the per-stream lock serialized every writer.
    const sequences = rows.map((r) => Number(r.sequence));
    expect(new Set(sequences).size).toBe(sequences.length);
    for (let i = 1; i < sequences.length; i += 1) {
      expect(sequences[i]).toBe(sequences[i - 1]! + 1);
    }
    // Each event's previous_hash is its predecessor's payload_hash.
    for (let i = 1; i < rows.length; i += 1) {
      expect(rows[i]!.previous_hash).toBe(rows[i - 1]!.payload_hash);
    }
  });
});

describe('tenant scope on the decision path', () => {
  it('hides another tenant’s decisions', async () => {
    const other = randomUUID();
    await withNewTenantTransaction(pool, other, async (c) => {
      await c.query('INSERT INTO organizations (id, name, region) VALUES ($1,$2,$3)', [
        other,
        'Other Co',
        'IN',
      ]);
    });
    const n = await withTenantTransaction(pool, { tenantId: other }, async (c) =>
      Number((await c.query<{ n: string }>('SELECT count(*) AS n FROM decisions')).rows[0]!.n),
    );
    expect(n).toBe(0);
  });
});
