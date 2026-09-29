import {
  canTransition,
  type AgentState,
  type AgentStatus,
  type AgentTransition,
  type TransitionRefusal,
} from '@trustos/domain';
import type { ScopedClient } from './tenant-transaction.js';
import { appendAuditEvent, publishOutboxEvent } from './audit.js';

/**
 * Agent identity lifecycle (IDN-01..IDN-04, OPS-01).
 *
 * Every transition takes a row lock and re-reads state INSIDE the transaction before
 * deciding. Reading state, deciding in application code, then writing is a
 * time-of-check/time-of-use gap: two concurrent operators could both see 'active' and
 * both act on it. The lock is what makes the first one win and the second one see the
 * result.
 */

export class TransitionRefusedError extends Error {
  constructor(
    readonly reason: TransitionRefusal,
    readonly currentStatus: AgentStatus,
  ) {
    super(`transition refused: ${reason} (agent is ${currentStatus})`);
    this.name = 'TransitionRefusedError';
  }
}

export class AgentNotFoundError extends Error {
  constructor(id: string) {
    // Same error whether the agent belongs to another tenant or does not exist.
    // Distinguishing them discloses existence across the boundary (§9.5).
    super(`agent ${id} not found`);
    this.name = 'AgentNotFoundError';
  }
}

export interface RegisterAgentInput {
  readonly environmentId: string;
  readonly name: string;
  readonly ownerMembershipId: string;
  readonly metadata?: Record<string, unknown>;
}

export async function registerAgent(
  client: ScopedClient,
  input: RegisterAgentInput,
): Promise<{ agentId: string }> {
  const r = await client.query<{ id: string }>(
    `INSERT INTO principals
       (tenant_id, environment_id, type, name, owner_membership_id, status, metadata)
     VALUES ($1,$2,'agent',$3,$4,'draft',$5)
     RETURNING id`,
    [
      client.scope.tenantId,
      input.environmentId,
      input.name,
      input.ownerMembershipId,
      // IDN-05: runtime metadata is self-reported. Stored for investigation, never
      // read as an authorization input.
      JSON.stringify(input.metadata ?? {}),
    ],
  );
  const agentId = r.rows[0]!.id;

  await appendAuditEvent(client, {
    environmentId: input.environmentId,
    actorType: 'human',
    actorId: input.ownerMembershipId,
    eventType: 'agent.registered',
    subjectType: 'agent',
    subjectId: agentId,
    safePayload: { name: input.name, owner_membership_id: input.ownerMembershipId },
  });

  return { agentId };
}

interface AgentRow {
  id: string;
  environment_id: string;
  status: AgentStatus;
  auth_epoch: number;
  owner_membership_id: string | null;
  owner_acknowledged_at: Date | null;
  owner_status: string | null;
}

/** Locks the agent and reads the owner in one statement, so the owner's status cannot
 *  change between the two reads. */
async function lockAgent(client: ScopedClient, agentId: string): Promise<AgentRow> {
  const r = await client.query<AgentRow>(
    `SELECT p.id, p.environment_id, p.status, p.auth_epoch,
            p.owner_membership_id, p.owner_acknowledged_at, m.status AS owner_status
     FROM principals p
     LEFT JOIN memberships m
       ON m.tenant_id = p.tenant_id AND m.id = p.owner_membership_id
     WHERE p.tenant_id = $1 AND p.id = $2 AND p.type = 'agent'
     FOR UPDATE OF p`,
    [client.scope.tenantId, agentId],
  );
  const row = r.rows[0];
  if (!row) throw new AgentNotFoundError(agentId);
  return row;
}

function toState(row: AgentRow): AgentState {
  return {
    status: row.status,
    hasOwner: row.owner_membership_id !== null,
    ownerAcknowledged: row.owner_acknowledged_at !== null,
    ownerActive: row.owner_status === 'active',
  };
}

export async function acknowledgeOwnership(
  client: ScopedClient,
  agentId: string,
  membershipId: string,
): Promise<void> {
  const row = await lockAgent(client, agentId);
  if (row.owner_membership_id !== membershipId) {
    // Only the assigned owner may accept accountability. Anyone else acknowledging
    // would produce an agent nobody actually agreed to answer for.
    throw new TransitionRefusedError('OWNER_REQUIRED', row.status);
  }
  await client.query(
    `UPDATE principals SET owner_acknowledged_at = now(), updated_at = now()
     WHERE tenant_id = $1 AND id = $2`,
    [client.scope.tenantId, agentId],
  );
  await appendAuditEvent(client, {
    environmentId: row.environment_id,
    actorType: 'human',
    actorId: membershipId,
    eventType: 'agent.ownership_acknowledged',
    subjectType: 'agent',
    subjectId: agentId,
    safePayload: { membership_id: membershipId },
  });
}

/** Explicit, because string-building these produced "agent.suspendd". Audit event
 *  types are queried and alerted on, so a typo is a silent gap in an investigation. */
const AUDIT_EVENT_TYPE: Record<AgentTransition, string> = {
  activate: 'agent.activated',
  suspend: 'agent.suspended',
  resume: 'agent.resumed',
  revoke: 'agent.revoked',
};

export interface TransitionOutcome {
  readonly status: AgentStatus;
  readonly authEpoch: number;
}

export async function transitionAgent(
  client: ScopedClient,
  agentId: string,
  transition: AgentTransition,
  actor: { type: 'human' | 'system'; id?: string | null; reason?: string },
): Promise<TransitionOutcome> {
  const row = await lockAgent(client, agentId);
  const verdict = canTransition(toState(row), transition);
  if (!verdict.allowed) throw new TransitionRefusedError(verdict.reason, row.status);

  // OPS-01: the epoch bump is the containment mechanism. Decisions and grant
  // consumption compare against the current epoch, so anything issued earlier stops
  // being usable the moment this commits — no waiting for a token to expire (IDN-04).
  const updated = await client.query<{ auth_epoch: number }>(
    `UPDATE principals
     SET status = $3,
         auth_epoch = auth_epoch + CASE WHEN $4 THEN 1 ELSE 0 END,
         updated_at = now()
     WHERE tenant_id = $1 AND id = $2
     RETURNING auth_epoch`,
    [client.scope.tenantId, agentId, verdict.nextStatus, verdict.bumpEpoch],
  );

  if (verdict.bumpEpoch) {
    // Grants already issued are invalid by epoch; marking them keeps the console
    // honest about why, instead of showing an issued grant that can never be used.
    await client.query(
      `UPDATE execution_grants g
       SET state = 'revoked'
       FROM decisions d, authorization_requests r
       WHERE g.tenant_id = $1 AND g.decision_id = d.id AND d.request_id = r.id
         AND r.principal_id = $2 AND g.state = 'issued'`,
      [client.scope.tenantId, agentId],
    );
  }

  await appendAuditEvent(client, {
    environmentId: row.environment_id,
    actorType: actor.type,
    actorId: actor.id ?? null,
    eventType: AUDIT_EVENT_TYPE[transition],
    subjectType: 'agent',
    subjectId: agentId,
    safePayload: {
      from: row.status,
      to: verdict.nextStatus,
      epoch_bumped: verdict.bumpEpoch,
      reason: actor.reason ?? null,
    },
  });

  await publishOutboxEvent(client, row.environment_id, `agent.${verdict.nextStatus}`, {
    agent_id: agentId,
    status: verdict.nextStatus,
  });

  return { status: verdict.nextStatus, authEpoch: updated.rows[0]!.auth_epoch };
}

/**
 * Owner departure (prd.md §6.2). Suspends every active agent the departing member
 * owns, unless ownership was transferred first. Returns the agents it contained.
 */
export async function suspendAgentsOwnedBy(
  client: ScopedClient,
  membershipId: string,
): Promise<string[]> {
  const owned = await client.query<{ id: string }>(
    `SELECT id FROM principals
     WHERE tenant_id = $1 AND type = 'agent' AND owner_membership_id = $2
       AND status = 'active'
     FOR UPDATE`,
    [client.scope.tenantId, membershipId],
  );

  const suspended: string[] = [];
  for (const { id } of owned.rows) {
    await transitionAgent(client, id, 'suspend', {
      type: 'system',
      reason: 'owner departed',
    });
    suspended.push(id);
  }
  return suspended;
}

/**
 * The check the decision path runs before evaluating policy (prd.md §8, step 2).
 * Returns the epochs recorded on the decision, so consumption can later detect that
 * authority changed underneath an issued grant (§8.3 step 3).
 */
export interface Authority {
  readonly agentId: string;
  readonly environmentId: string;
  readonly principalEpoch: number;
  readonly orgEpoch: number;
}

export class AuthorityRefusedError extends Error {
  constructor(
    readonly code: 'AGENT_NOT_ACTIVE' | 'OWNER_INACTIVE' | 'KILL_SWITCH' | 'ENVIRONMENT_SUSPENDED',
    message: string,
  ) {
    super(message);
    this.name = 'AuthorityRefusedError';
  }
}

export async function assertAuthority(client: ScopedClient, agentId: string): Promise<Authority> {
  const r = await client.query<{
    environment_id: string;
    status: AgentStatus;
    auth_epoch: number;
    owner_status: string | null;
    org_epoch: number;
    kill_switch_engaged: boolean;
    env_status: string;
  }>(
    `SELECT p.environment_id, p.status, p.auth_epoch,
            m.status AS owner_status,
            o.auth_epoch AS org_epoch,
            e.kill_switch_engaged, e.status AS env_status
     FROM principals p
     JOIN organizations o ON o.id = p.tenant_id
     JOIN environments e ON e.tenant_id = p.tenant_id AND e.id = p.environment_id
     LEFT JOIN memberships m ON m.tenant_id = p.tenant_id AND m.id = p.owner_membership_id
     WHERE p.tenant_id = $1 AND p.id = $2 AND p.type = 'agent'
     FOR SHARE OF p`,
    [client.scope.tenantId, agentId],
  );

  const row = r.rows[0];
  if (!row) throw new AgentNotFoundError(agentId);

  // Order matters: emergency stops are checked before anything about the agent, so a
  // kill switch contains an otherwise-healthy agent (prd.md §8, step 2).
  if (row.kill_switch_engaged) {
    throw new AuthorityRefusedError('KILL_SWITCH', 'environment kill switch engaged');
  }
  if (row.env_status !== 'active') {
    throw new AuthorityRefusedError('ENVIRONMENT_SUSPENDED', 'environment is suspended');
  }
  if (row.status !== 'active') {
    throw new AuthorityRefusedError('AGENT_NOT_ACTIVE', `agent is ${row.status}`);
  }
  // IDN-02 again at decision time: an agent whose owner left between activation and
  // now has no accountable human, even though its own status still says active.
  if (row.owner_status !== 'active') {
    throw new AuthorityRefusedError('OWNER_INACTIVE', 'agent owner is not active');
  }

  return {
    agentId,
    environmentId: row.environment_id,
    principalEpoch: row.auth_epoch,
    orgEpoch: row.org_epoch,
  };
}
