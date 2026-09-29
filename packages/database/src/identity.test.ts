import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createPool } from './pool.js';
import { withNewTenantTransaction, withTenantTransaction } from './tenant-transaction.js';
import {
  acknowledgeOwnership,
  assertAuthority,
  AuthorityRefusedError,
  AgentNotFoundError,
  registerAgent,
  suspendAgentsOwnedBy,
  transitionAgent,
  TransitionRefusedError,
} from './identity.js';

const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgresql://trustos_app:local_dev_only@localhost:55432/trustos';

let pool: Pool;
const tenant = randomUUID();
let environmentId: string;
let ownerId: string;

beforeAll(async () => {
  pool = createPool(APP_URL);
  await withNewTenantTransaction(pool, tenant, async (c) => {
    await c.query('INSERT INTO organizations (id, name, region) VALUES ($1,$2,$3)', [
      tenant,
      'Identity Co',
      'IN',
    ]);
    environmentId = (
      await c.query<{ id: string }>(
        `INSERT INTO environments (tenant_id, name, mode) VALUES ($1,'sandbox','sandbox') RETURNING id`,
        [tenant],
      )
    ).rows[0]!.id;
    ownerId = (
      await c.query<{ id: string }>(
        `INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1,$2,'developer') RETURNING id`,
        [tenant, `owner-${randomUUID()}`],
      )
    ).rows[0]!.id;
  });
});

afterAll(async () => {
  await pool?.end();
});

const tx = <T>(fn: Parameters<typeof withTenantTransaction<T>>[2]): Promise<T> =>
  withTenantTransaction(pool, { tenantId: tenant }, fn);

async function activeAgent(owner = ownerId): Promise<string> {
  return tx(async (c) => {
    const { agentId } = await registerAgent(c, {
      environmentId,
      name: `agent-${randomUUID()}`,
      ownerMembershipId: owner,
    });
    await acknowledgeOwnership(c, agentId, owner);
    await transitionAgent(c, agentId, 'activate', { type: 'human', id: owner });
    return agentId;
  });
}

describe('registration and activation', () => {
  it('registers in draft, which confers no authority', async () => {
    const agentId = await tx(
      async (c) =>
        (await registerAgent(c, { environmentId, name: 'draft agent', ownerMembershipId: ownerId }))
          .agentId,
    );
    await expect(tx((c) => assertAuthority(c, agentId))).rejects.toMatchObject({
      code: 'AGENT_NOT_ACTIVE',
    });
  });

  it('refuses activation before the owner acknowledges (IDN-02)', async () => {
    const agentId = await tx(
      async (c) =>
        (await registerAgent(c, { environmentId, name: 'unacked', ownerMembershipId: ownerId }))
          .agentId,
    );
    await expect(
      tx((c) => transitionAgent(c, agentId, 'activate', { type: 'human', id: ownerId })),
    ).rejects.toMatchObject({ reason: 'OWNER_ACKNOWLEDGEMENT_REQUIRED' });
  });

  it('refuses acknowledgement from anyone but the assigned owner', async () => {
    const other = await tx(
      async (c) =>
        (
          await c.query<{ id: string }>(
            `INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1,$2,'developer') RETURNING id`,
            [tenant, `other-${randomUUID()}`],
          )
        ).rows[0]!.id,
    );
    const agentId = await tx(
      async (c) =>
        (await registerAgent(c, { environmentId, name: 'a', ownerMembershipId: ownerId })).agentId,
    );
    await expect(tx((c) => acknowledgeOwnership(c, agentId, other))).rejects.toBeInstanceOf(
      TransitionRefusedError,
    );
  });

  it('grants authority once activated', async () => {
    const agentId = await activeAgent();
    const authority = await tx((c) => assertAuthority(c, agentId));
    expect(authority.agentId).toBe(agentId);
    expect(authority.principalEpoch).toBe(1);
  });
});

describe('containment (OPS-01, IDN-04)', () => {
  it('blocks authority immediately on suspension and bumps the epoch', async () => {
    const agentId = await activeAgent();
    const before = await tx((c) => assertAuthority(c, agentId));

    const outcome = await tx((c) =>
      transitionAgent(c, agentId, 'suspend', { type: 'human', id: ownerId, reason: 'incident' }),
    );

    // NFR-03 wants blocking within 10 seconds. The epoch bump commits with the
    // suspension, so the boundary is the transaction, not a propagation delay.
    expect(outcome.authEpoch).toBe(before.principalEpoch + 1);
    await expect(tx((c) => assertAuthority(c, agentId))).rejects.toMatchObject({
      code: 'AGENT_NOT_ACTIVE',
    });
  });

  it('revokes grants that were already issued', async () => {
    const agentId = await activeAgent();
    const grantId = await tx(async (c) => {
      const req = await c.query<{ id: string }>(
        `INSERT INTO authorization_requests
           (tenant_id, environment_id, principal_id, action_key, resource_type, resource_id, request_hash)
         VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','lead_1',$4) RETURNING id`,
        [tenant, environmentId, agentId, `sha256:${'c'.repeat(64)}`],
      );
      const dec = await c.query<{ id: string }>(
        `INSERT INTO decisions
           (tenant_id, environment_id, request_id, effect, mode, bundle_revision,
            principal_epoch, credential_epoch, org_epoch, expires_at)
         VALUES ($1,$2,$3,'allow','enforced',1,1,1,1, now() + interval '1 minute') RETURNING id`,
        [tenant, environmentId, req.rows[0]!.id],
      );
      const g = await c.query<{ id: string }>(
        `INSERT INTO execution_grants
           (tenant_id, environment_id, decision_id, gateway_audience, request_hash,
            bundle_revision, principal_epoch, credential_epoch, expires_at)
         VALUES ($1,$2,$3,'gw',$4,1,1,1, now() + interval '60 seconds') RETURNING id`,
        [tenant, environmentId, dec.rows[0]!.id, `sha256:${'c'.repeat(64)}`],
      );
      return g.rows[0]!.id;
    });

    await tx((c) => transitionAgent(c, agentId, 'suspend', { type: 'human', id: ownerId }));

    const state = await tx(
      async (c) =>
        (
          await c.query<{ state: string }>('SELECT state FROM execution_grants WHERE id = $1', [
            grantId,
          ])
        ).rows[0]!.state,
    );
    // An issued-but-unusable grant showing as 'issued' would mislead an operator
    // reading the console during an incident.
    expect(state).toBe('revoked');
  });

  it('bumps the epoch again on resume, so pre-suspension grants stay dead', async () => {
    const agentId = await activeAgent();
    await tx((c) => transitionAgent(c, agentId, 'suspend', { type: 'human', id: ownerId }));
    const resumed = await tx((c) =>
      transitionAgent(c, agentId, 'resume', { type: 'human', id: ownerId }),
    );
    expect(resumed.status).toBe('active');
    expect(resumed.authEpoch).toBe(3); // 1 activate, +1 suspend, +1 resume
  });

  it('keeps revocation terminal', async () => {
    const agentId = await activeAgent();
    await tx((c) => transitionAgent(c, agentId, 'revoke', { type: 'human', id: ownerId }));
    for (const t of ['activate', 'resume', 'suspend', 'revoke'] as const) {
      await expect(
        tx((c) => transitionAgent(c, agentId, t, { type: 'human', id: ownerId })),
      ).rejects.toMatchObject({ reason: 'TERMINAL_STATE' });
    }
  });

  it('lets only one of two concurrent suspensions win', async () => {
    const agentId = await activeAgent();
    const results = await Promise.allSettled([
      tx((c) => transitionAgent(c, agentId, 'suspend', { type: 'human', id: ownerId })),
      tx((c) => transitionAgent(c, agentId, 'suspend', { type: 'human', id: ownerId })),
    ]);
    const ok = results.filter((r) => r.status === 'fulfilled');
    expect(ok).toHaveLength(1);
    // The loser must see ALREADY_IN_STATE, not a second epoch bump.
    const epoch = await tx(
      async (c) =>
        (
          await c.query<{ auth_epoch: number }>('SELECT auth_epoch FROM principals WHERE id = $1', [
            agentId,
          ])
        ).rows[0]!.auth_epoch,
    );
    expect(epoch).toBe(2);
  });
});

describe('owner departure (prd.md §6.2)', () => {
  it('suspends every active agent the departing owner held', async () => {
    const leaving = await tx(
      async (c) =>
        (
          await c.query<{ id: string }>(
            `INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1,$2,'developer') RETURNING id`,
            [tenant, `leaving-${randomUUID()}`],
          )
        ).rows[0]!.id,
    );
    const a = await activeAgent(leaving);
    const b = await activeAgent(leaving);

    const suspended = await tx(async (c) => {
      await c.query(`UPDATE memberships SET status = 'removed' WHERE id = $1`, [leaving]);
      return suspendAgentsOwnedBy(c, leaving);
    });

    expect(suspended.sort()).toEqual([a, b].sort());
    for (const id of [a, b]) {
      await expect(tx((c) => assertAuthority(c, id))).rejects.toBeInstanceOf(AuthorityRefusedError);
    }
  });

  it('refuses authority when the owner goes inactive, even before suspension runs', async () => {
    // The scheduled suspension may lag. An agent with no accountable human must not
    // keep acting in the meantime.
    const leaving = await tx(
      async (c) =>
        (
          await c.query<{ id: string }>(
            `INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1,$2,'developer') RETURNING id`,
            [tenant, `lag-${randomUUID()}`],
          )
        ).rows[0]!.id,
    );
    const agentId = await activeAgent(leaving);
    await tx((c) => c.query(`UPDATE memberships SET status='suspended' WHERE id=$1`, [leaving]));
    await expect(tx((c) => assertAuthority(c, agentId))).rejects.toMatchObject({
      code: 'OWNER_INACTIVE',
    });
  });
});

describe('emergency stops precede agent checks (prd.md §8)', () => {
  it('refuses on kill switch even for a healthy agent', async () => {
    const agentId = await activeAgent();
    await tx((c) =>
      c.query(`UPDATE environments SET kill_switch_engaged = true WHERE id = $1`, [environmentId]),
    );
    await expect(tx((c) => assertAuthority(c, agentId))).rejects.toMatchObject({
      code: 'KILL_SWITCH',
    });
    await tx((c) =>
      c.query(`UPDATE environments SET kill_switch_engaged = false WHERE id = $1`, [environmentId]),
    );
  });
});

describe('cross-tenant', () => {
  it('reports another tenant’s agent as not found, disclosing nothing', async () => {
    const other = randomUUID();
    await withNewTenantTransaction(pool, other, async (c) => {
      await c.query('INSERT INTO organizations (id, name, region) VALUES ($1,$2,$3)', [
        other,
        'Other',
        'IN',
      ]);
    });
    const mine = await activeAgent();
    await expect(
      withTenantTransaction(pool, { tenantId: other }, (c) => assertAuthority(c, mine)),
    ).rejects.toBeInstanceOf(AgentNotFoundError);
  });
});
