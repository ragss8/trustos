import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createPool } from './pool.js';
import { withNewTenantTransaction, withTenantTransaction } from './tenant-transaction.js';
import {
  createApprovalRequest,
  expirePendingApprovals,
  resolveApproval,
  ResolutionRefusedError,
} from './approvals.js';

const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgresql://trustos_app:local_dev_only@localhost:55432/trustos';

let pool: Pool;
const tenant = randomUUID();
let environmentId: string;
let agentOwnerId: string;
let approverId: string;
let groupId: string;
let agentId: string;

const tx = <T>(fn: Parameters<typeof withTenantTransaction<T>>[2]): Promise<T> =>
  withTenantTransaction(pool, { tenantId: tenant }, fn);

async function member(role: string, prefix: string): Promise<string> {
  return tx(
    async (c) =>
      (
        await c.query<{ id: string }>(
          `INSERT INTO memberships (tenant_id,user_id,role) VALUES ($1,$2,$3) RETURNING id`,
          [tenant, `${prefix}-${randomUUID()}`, role],
        )
      ).rows[0]!.id,
  );
}

beforeAll(async () => {
  pool = createPool(APP_URL);
  await withNewTenantTransaction(pool, tenant, async (c) => {
    await c.query('INSERT INTO organizations (id,name,region) VALUES ($1,$2,$3)', [
      tenant,
      'Approvals Co',
      'IN',
    ]);
    environmentId = (
      await c.query<{ id: string }>(
        `INSERT INTO environments (tenant_id,name,mode,enforcement,current_bundle_revision)
         VALUES ($1,'production','production','enforced',7) RETURNING id`,
        [tenant],
      )
    ).rows[0]!.id;
    groupId = (
      await c.query<{ id: string }>(
        `INSERT INTO approver_groups (tenant_id,group_key,name)
         VALUES ($1,'regional_sales_manager','Regional Sales Managers') RETURNING id`,
        [tenant],
      )
    ).rows[0]!.id;
  });

  agentOwnerId = await member('developer', 'owner');
  approverId = await member('approver', 'approver');

  await tx(async (c) => {
    await c.query(
      `INSERT INTO approver_group_members (tenant_id,group_id,membership_id) VALUES ($1,$2,$3)`,
      [tenant, groupId, approverId],
    );
    // The agent owner is ALSO in the group, so separation of duties is what stops
    // them approving, not a missing membership.
    await c.query(
      `INSERT INTO approver_group_members (tenant_id,group_id,membership_id) VALUES ($1,$2,$3)`,
      [tenant, groupId, agentOwnerId],
    );
    agentId = (
      await c.query<{ id: string }>(
        `INSERT INTO principals (tenant_id,environment_id,type,name,owner_membership_id,status,owner_acknowledged_at)
         VALUES ($1,$2,'agent','sales agent',$3,'active',now()) RETURNING id`,
        [tenant, environmentId, agentOwnerId],
      )
    ).rows[0]!.id;
  });
});

afterAll(async () => {
  await pool?.end();
});

async function pendingApproval(
  timeoutSeconds = 600,
): Promise<{ approvalId: string; decisionId: string }> {
  return tx(async (c) => {
    const hash = `sha256:${randomUUID().replace(/-/g, '').padEnd(64, '0')}`;
    const req = await c.query<{ id: string }>(
      `INSERT INTO authorization_requests
         (tenant_id,environment_id,principal_id,action_key,resource_type,resource_id,request_hash)
       VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','lead_1',$4) RETURNING id`,
      [tenant, environmentId, agentId, hash],
    );
    const dec = await c.query<{ id: string }>(
      `INSERT INTO decisions
         (tenant_id,environment_id,request_id,effect,mode,bundle_revision,
          principal_epoch,credential_epoch,org_epoch,expires_at)
       VALUES ($1,$2,$3,'approval_required','enforced',7,1,1,1, now() + interval '10 minutes')
       RETURNING id`,
      [tenant, environmentId, req.rows[0]!.id],
    );
    const { approvalId } = await createApprovalRequest(c, {
      environmentId,
      decisionId: dec.rows[0]!.id,
      groupKey: 'regional_sales_manager',
      timeoutSeconds,
    });
    return { approvalId, decisionId: dec.rows[0]!.id };
  });
}

describe('resolution (APR-02)', () => {
  it('approves and issues the grant in the same transaction', async () => {
    const { approvalId } = await pendingApproval();
    const r = await tx((c) =>
      resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
    );
    expect(r.state).toBe('approved');
    // An approval without its grant would strand the caller holding a yes they
    // cannot act on.
    expect(r.grantId).not.toBeNull();
  });

  it('rejects without issuing a grant', async () => {
    const { approvalId } = await pendingApproval();
    const r = await tx((c) =>
      resolveApproval(c, {
        approvalId,
        actorMembershipId: approverId,
        effect: 'rejected',
        reason: 'margin too thin',
      }),
    );
    expect(r.state).toBe('rejected');
    expect(r.grantId).toBeNull();
  });

  it('lets only one of two concurrent resolutions win', async () => {
    // prd.md §18: "Two approval resolutions race -> one winner, other gets
    // terminal-state response."
    const { approvalId } = await pendingApproval();
    const second = await member('approver', 'approver2');
    await tx((c) =>
      c.query(
        `INSERT INTO approver_group_members (tenant_id,group_id,membership_id) VALUES ($1,$2,$3)`,
        [tenant, groupId, second],
      ),
    );

    const results = await Promise.allSettled([
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
      ),
      tx((c) => resolveApproval(c, { approvalId, actorMembershipId: second, effect: 'rejected' })),
    ]);

    const won = results.filter((r) => r.status === 'fulfilled' && r.value.resolvedNow);
    expect(won).toHaveLength(1);

    const events = await tx(
      async (c) =>
        (
          await c.query<{ n: string }>(
            `SELECT count(*) AS n FROM approval_events WHERE request_id = $1 AND effect IN ('approved','rejected')`,
            [approvalId],
          )
        ).rows[0]!.n,
    );
    // One terminal resolution, one event. Not two.
    expect(Number(events)).toBe(1);
  });

  it('returns the prior resolution on an exact retry', async () => {
    const { approvalId } = await pendingApproval();
    const first = await tx((c) =>
      resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
    );
    const again = await tx((c) =>
      resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
    );
    expect(again.resolvedNow).toBe(false);
    expect(again.grantId).toBe(first.grantId); // not a second grant
  });

  it('conflicts when the same approver flips their answer', async () => {
    const { approvalId } = await pendingApproval();
    await tx((c) =>
      resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
    );
    await expect(
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'rejected' }),
      ),
    ).rejects.toMatchObject({ code: 'ALREADY_RESOLVED' });
  });
});

describe('eligibility and separation of duties (APR-03)', () => {
  it('refuses the agent owner even though they are in the group', async () => {
    // prd.md §18: "Owner attempts own sensitive approval -> rejected by server."
    const { approvalId } = await pendingApproval();
    await expect(
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: agentOwnerId, effect: 'approved' }),
      ),
    ).rejects.toMatchObject({ code: 'SELF_APPROVAL' });
  });

  it('refuses someone outside the routed group', async () => {
    const outsider = await member('approver', 'outsider');
    const { approvalId } = await pendingApproval();
    await expect(
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: outsider, effect: 'approved' }),
      ),
    ).rejects.toMatchObject({ code: 'NOT_ELIGIBLE' });
  });

  it('refuses an approver whose membership was revoked after routing', async () => {
    // APR-03: the check that matters is at RESOLUTION. Eligibility at routing time
    // proves nothing about eligibility now.
    const temp = await member('approver', 'temp');
    await tx((c) =>
      c.query(
        `INSERT INTO approver_group_members (tenant_id,group_id,membership_id) VALUES ($1,$2,$3)`,
        [tenant, groupId, temp],
      ),
    );
    const { approvalId } = await pendingApproval();
    await tx((c) => c.query(`UPDATE memberships SET status='removed' WHERE id=$1`, [temp]));
    await expect(
      tx((c) => resolveApproval(c, { approvalId, actorMembershipId: temp, effect: 'approved' })),
    ).rejects.toMatchObject({ code: 'APPROVER_INACTIVE' });
  });

  it('refuses routing to a group that does not exist', async () => {
    await expect(
      tx(async (c) => {
        const req = await c.query<{ id: string }>(
          `INSERT INTO authorization_requests
             (tenant_id,environment_id,principal_id,action_key,resource_type,resource_id,request_hash)
           VALUES ($1,$2,$3,'crm.discount.apply','crm.lead','l',$4) RETURNING id`,
          [tenant, environmentId, agentId, `sha256:${'3'.repeat(64)}`],
        );
        const dec = await c.query<{ id: string }>(
          `INSERT INTO decisions
             (tenant_id,environment_id,request_id,effect,mode,bundle_revision,
              principal_epoch,credential_epoch,org_epoch,expires_at)
           VALUES ($1,$2,$3,'approval_required','enforced',7,1,1,1, now()+interval '5 minutes')
           RETURNING id`,
          [tenant, environmentId, req.rows[0]!.id],
        );
        return createApprovalRequest(c, {
          environmentId,
          decisionId: dec.rows[0]!.id,
          groupKey: 'nonexistent_group',
          timeoutSeconds: 600,
        });
      }),
    ).rejects.toBeInstanceOf(ResolutionRefusedError);
  });
});

describe('expiry (APR-01)', () => {
  it('refuses an expired request even if the sweep has not run', async () => {
    // prd.md §18: "Approval expires while notification is delayed -> cannot approve."
    const { approvalId } = await pendingApproval(-1);
    await expect(
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
      ),
    ).rejects.toMatchObject({ code: 'EXPIRED' });
  });

  it('refuses on server time while the projection still reads pending', async () => {
    // This IS the "even if scheduler is delayed" case in APR-01. The stored state
    // lags; the deadline does not. Refusing has to depend on the clock, not on a
    // worker having run.
    const { approvalId } = await pendingApproval(-1);
    const stateBefore = await tx(
      async (c) =>
        (
          await c.query<{ state: string }>('SELECT state FROM approval_requests WHERE id=$1', [
            approvalId,
          ])
        ).rows[0]!.state,
    );
    expect(stateBefore).toBe('pending');

    await expect(
      tx((c) =>
        resolveApproval(c, { approvalId, actorMembershipId: approverId, effect: 'approved' }),
      ),
    ).rejects.toMatchObject({ code: 'EXPIRED' });

    // The sweep reconciles the projection afterwards.
    await tx((c) => expirePendingApprovals(c));
    const stateAfter = await tx(
      async (c) =>
        (
          await c.query<{ state: string }>('SELECT state FROM approval_requests WHERE id=$1', [
            approvalId,
          ])
        ).rows[0]!.state,
    );
    expect(stateAfter).toBe('expired');
  });

  it('sweeps due requests and leaves live ones alone', async () => {
    const due = await pendingApproval(-1);
    const live = await pendingApproval(600);
    const expired = await tx((c) => expirePendingApprovals(c));
    expect(expired).toContain(due.approvalId);
    expect(expired).not.toContain(live.approvalId);
  });

  it('never issues a grant outliving the approval deadline', async () => {
    const { approvalId } = await pendingApproval(600);
    const r = await tx((c) =>
      resolveApproval(c, {
        approvalId,
        actorMembershipId: approverId,
        effect: 'approved',
        grantTtlSeconds: 60,
      }),
    );
    const expiry = await tx(
      async (c) =>
        (
          await c.query<{ expires_at: Date }>(
            'SELECT expires_at FROM execution_grants WHERE id=$1',
            [r.grantId],
          )
        ).rows[0]!.expires_at,
    );
    expect(expiry.getTime()).toBeLessThanOrEqual(Date.now() + 61_000);
  });
});
