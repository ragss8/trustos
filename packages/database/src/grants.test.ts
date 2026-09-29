import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createPool } from './pool.js';
import { withNewTenantTransaction, withTenantTransaction } from './tenant-transaction.js';
import { consumeGrant, ConsumeRefusedError, issueGrant } from './grants.js';

const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgresql://trustos_app:local_dev_only@localhost:55432/trustos';

let pool: Pool;
const tenant = randomUUID();
let environmentId: string;
let agentId: string;
let gatewayId: string;
const AUDIENCE = 'gateway_demo';

const tx = <T>(fn: Parameters<typeof withTenantTransaction<T>>[2]): Promise<T> =>
  withTenantTransaction(pool, { tenantId: tenant }, fn);

beforeAll(async () => {
  pool = createPool(APP_URL);
  await withNewTenantTransaction(pool, tenant, async (c) => {
    await c.query('INSERT INTO organizations (id,name,region) VALUES ($1,$2,$3)', [
      tenant,
      'Grants Co',
      'IN',
    ]);
    environmentId = (
      await c.query<{ id: string }>(
        `INSERT INTO environments (tenant_id,name,mode,enforcement,current_bundle_revision)
         VALUES ($1,'production','production','enforced',7) RETURNING id`,
        [tenant],
      )
    ).rows[0]!.id;
    const owner = (
      await c.query<{ id: string }>(
        `INSERT INTO memberships (tenant_id,user_id,role) VALUES ($1,$2,'developer') RETURNING id`,
        [tenant, `owner-${randomUUID()}`],
      )
    ).rows[0]!.id;
    agentId = (
      await c.query<{ id: string }>(
        `INSERT INTO principals (tenant_id,environment_id,type,name,owner_membership_id,status,owner_acknowledged_at)
         VALUES ($1,$2,'agent','grant agent',$3,'active',now()) RETURNING id`,
        [tenant, environmentId, owner],
      )
    ).rows[0]!.id;
    gatewayId = (
      await c.query<{ id: string }>(
        `INSERT INTO principals (tenant_id,environment_id,type,name,status)
         VALUES ($1,$2,'gateway','reference gateway','active') RETURNING id`,
        [tenant, environmentId],
      )
    ).rows[0]!.id;
  });
});

afterAll(async () => {
  await pool?.end();
});

interface Fixture {
  grantId: string;
  requestHash: string;
}

async function grantFor(
  opts: { ttlSeconds?: number; resourceVersion?: string | null; bundleRevision?: number } = {},
): Promise<Fixture> {
  const requestHash = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
  const grantId = await tx(async (c) => {
    const req = await c.query<{ id: string }>(
      `INSERT INTO authorization_requests
         (tenant_id,environment_id,principal_id,action_key,resource_type,resource_id,resource_version,request_hash)
       VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','lead_1',$4,$5) RETURNING id`,
      [tenant, environmentId, agentId, opts.resourceVersion ?? '17', requestHash],
    );
    const dec = await c.query<{ id: string }>(
      `INSERT INTO decisions
         (tenant_id,environment_id,request_id,effect,mode,bundle_revision,
          principal_epoch,credential_epoch,org_epoch,expires_at)
       VALUES ($1,$2,$3,'allow','enforced',$4,1,1,1, now() + interval '5 minutes') RETURNING id`,
      [tenant, environmentId, req.rows[0]!.id, opts.bundleRevision ?? 7],
    );
    const { grantId } = await issueGrant(c, {
      environmentId,
      decisionId: dec.rows[0]!.id,
      gatewayAudience: AUDIENCE,
      requestHash,
      bundleRevision: opts.bundleRevision ?? 7,
      principalEpoch: 1,
      credentialEpoch: 1,
      ttlSeconds: opts.ttlSeconds ?? 60,
    });
    return grantId;
  });
  return { grantId, requestHash };
}

const consume = (f: Fixture, over: Partial<Parameters<typeof consumeGrant>[1]> = {}) =>
  tx((c) =>
    consumeGrant(c, {
      grantId: f.grantId,
      gatewayPrincipalId: gatewayId,
      gatewayAudience: AUDIENCE,
      requestHash: f.requestHash,
      executionKey: `crm-op-${randomUUID()}`,
      ...over,
    }),
  );

describe('single consumption (INVARIANT 4, AUT-07)', () => {
  it('consumes once and issues a receipt', async () => {
    const f = await grantFor();
    const r = await consume(f);
    expect(r.consumedNow).toBe(true);
    expect(r.grantId).toBe(f.grantId);
  });

  it('never lets two concurrent gateways both consume one grant', async () => {
    // prd.md §18: "Two gateways consume one grant -> only one consumption receipt
    // authorizes one execution intent."
    const f = await grantFor();
    const results = await Promise.allSettled([
      consume(f, { executionKey: 'op-A' }),
      consume(f, { executionKey: 'op-B' }),
    ]);
    const won = results.filter((r) => r.status === 'fulfilled' && r.value.consumedNow);
    expect(won).toHaveLength(1);

    const receipts = await tx(
      async (c) =>
        (
          await c.query<{ n: string }>(
            'SELECT count(*) AS n FROM consumption_receipts WHERE grant_id = $1',
            [f.grantId],
          )
        ).rows[0]!.n,
    );
    expect(Number(receipts)).toBe(1);
  });

  it('recovers the original receipt for the same caller and execution key', async () => {
    // prd.md §18: "Consumption response lost -> same consumer/key can retrieve
    // receipt; no second consume."
    const f = await grantFor();
    const first = await consume(f, { executionKey: 'op-lost' });
    const again = await consume(f, { executionKey: 'op-lost' });
    expect(again.receiptId).toBe(first.receiptId);
    expect(again.consumedNow).toBe(false); // recovery, not new authority
  });

  it('refuses the same gateway presenting a different execution key', async () => {
    const f = await grantFor();
    await consume(f, { executionKey: 'op-1' });
    await expect(consume(f, { executionKey: 'op-2' })).rejects.toMatchObject({
      code: 'GRANT_ALREADY_CONSUMED',
    });
  });
});

describe('binding', () => {
  it('refuses a grant presented by the wrong gateway', async () => {
    const f = await grantFor();
    await expect(consume(f, { gatewayAudience: 'other_gateway' })).rejects.toMatchObject({
      code: 'WRONG_AUDIENCE',
    });
  });

  it('refuses a grant presented for a different request', async () => {
    const f = await grantFor();
    await expect(consume(f, { requestHash: `sha256:${'f'.repeat(64)}` })).rejects.toMatchObject({
      code: 'REQUEST_HASH_MISMATCH',
    });
  });

  it('checks audience and fingerprint before expiry, so a misuse is not reported as staleness', async () => {
    const f = await grantFor({ ttlSeconds: -1 });
    await expect(consume(f, { gatewayAudience: 'other' })).rejects.toMatchObject({
      code: 'WRONG_AUDIENCE',
    });
  });
});

describe('freshness', () => {
  it('refuses an expired grant using server time', async () => {
    const f = await grantFor({ ttlSeconds: -1 });
    await expect(consume(f)).rejects.toMatchObject({ code: 'GRANT_EXPIRED' });
  });

  it('refuses after the agent is suspended (OPS-01)', async () => {
    // prd.md §18: "Agent suspended after approval -> new authorize/consume blocked."
    const f = await grantFor();
    await tx((c) =>
      c.query(`UPDATE principals SET status='suspended', auth_epoch=auth_epoch+1 WHERE id=$1`, [
        agentId,
      ]),
    );
    await expect(consume(f)).rejects.toMatchObject({ code: 'AUTHORITY_STALE' });
    await tx((c) =>
      c.query(`UPDATE principals SET status='active', auth_epoch=1 WHERE id=$1`, [agentId]),
    );
  });

  it('refuses after a policy publication (ADR-009)', async () => {
    // prd.md §18: "Policy published while grant waits -> consumption rejected."
    const f = await grantFor({ bundleRevision: 7 });
    await tx((c) =>
      c.query(`UPDATE environments SET current_bundle_revision = 8 WHERE id = $1`, [environmentId]),
    );
    await expect(consume(f)).rejects.toMatchObject({ code: 'POLICY_CHANGED' });
    await tx((c) =>
      c.query(`UPDATE environments SET current_bundle_revision = 7 WHERE id = $1`, [environmentId]),
    );
  });

  it('refuses when the resource changed since the decision', async () => {
    const f = await grantFor({ resourceVersion: '17' });
    await expect(consume(f, { resourceVersion: '18' })).rejects.toMatchObject({
      code: 'RESOURCE_CHANGED',
    });
  });

  it('reports a reused execution key distinctly from an already-consumed grant', async () => {
    // A gateway reusing a handle across grants has a broken operation ledger and may
    // be about to execute twice. That deserves its own signal, not the generic one.
    const a = await grantFor();
    const b = await grantFor();
    await consume(a, { executionKey: 'shared-key' });
    await expect(consume(b, { executionKey: 'shared-key' })).rejects.toMatchObject({
      code: 'EXECUTION_KEY_REUSED',
    });
  });

  it('accepts a matching resource version', async () => {
    const f = await grantFor({ resourceVersion: '17' });
    await expect(consume(f, { resourceVersion: '17' })).resolves.toMatchObject({
      consumedNow: true,
    });
  });

  it('refuses when the kill switch is engaged', async () => {
    const f = await grantFor();
    await tx((c) =>
      c.query(`UPDATE environments SET kill_switch_engaged=true WHERE id=$1`, [environmentId]),
    );
    await expect(consume(f)).rejects.toMatchObject({ code: 'AUTHORITY_STALE' });
    await tx((c) =>
      c.query(`UPDATE environments SET kill_switch_engaged=false WHERE id=$1`, [environmentId]),
    );
  });
});

describe('shadow mode (INVARIANT 3, AUT-08)', () => {
  it('refuses to issue an executable grant for a shadow decision', async () => {
    await expect(
      tx(async (c) => {
        const req = await c.query<{ id: string }>(
          `INSERT INTO authorization_requests
             (tenant_id,environment_id,principal_id,action_key,resource_type,resource_id,request_hash)
           VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','lead_1',$4) RETURNING id`,
          [tenant, environmentId, agentId, `sha256:${'9'.repeat(64)}`],
        );
        const dec = await c.query<{ id: string }>(
          `INSERT INTO decisions
             (tenant_id,environment_id,request_id,effect,mode,bundle_revision,
              principal_epoch,credential_epoch,org_epoch,expires_at)
           VALUES ($1,$2,$3,'allow','shadow',7,1,1,1, now() + interval '5 minutes') RETURNING id`,
          [tenant, environmentId, req.rows[0]!.id],
        );
        return issueGrant(c, {
          environmentId,
          decisionId: dec.rows[0]!.id,
          gatewayAudience: AUDIENCE,
          requestHash: `sha256:${'9'.repeat(64)}`,
          bundleRevision: 7,
          principalEpoch: 1,
          credentialEpoch: 1,
          ttlSeconds: 60,
        });
      }),
    ).rejects.toBeInstanceOf(ConsumeRefusedError);
  });
});

describe('lifetime', () => {
  it('never issues a grant outliving the business deadline', async () => {
    const deadline = new Date(Date.now() + 5_000);
    const expiry = await tx(async (c) => {
      const req = await c.query<{ id: string }>(
        `INSERT INTO authorization_requests
           (tenant_id,environment_id,principal_id,action_key,resource_type,resource_id,request_hash,business_deadline)
         VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','lead_1',$4,$5) RETURNING id`,
        [tenant, environmentId, agentId, `sha256:${'7'.repeat(64)}`, deadline],
      );
      const dec = await c.query<{ id: string }>(
        `INSERT INTO decisions
           (tenant_id,environment_id,request_id,effect,mode,bundle_revision,
            principal_epoch,credential_epoch,org_epoch,expires_at)
         VALUES ($1,$2,$3,'allow','enforced',7,1,1,1,$4) RETURNING id`,
        [tenant, environmentId, req.rows[0]!.id, deadline],
      );
      // 60s TTL, but the deadline is 5s away: the deadline must win.
      const g = await issueGrant(c, {
        environmentId,
        decisionId: dec.rows[0]!.id,
        gatewayAudience: AUDIENCE,
        requestHash: `sha256:${'7'.repeat(64)}`,
        bundleRevision: 7,
        principalEpoch: 1,
        credentialEpoch: 1,
        ttlSeconds: 60,
        businessDeadline: deadline,
      });
      return g.expiresAt;
    });
    expect(expiry.getTime()).toBeLessThanOrEqual(deadline.getTime());
  });
});
