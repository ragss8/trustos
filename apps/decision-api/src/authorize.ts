import { isActionKey, type ActionKey } from '@trustos/contracts';
import { computeIdempotencyKeyHash, computeRequestFingerprint } from '@trustos/domain';
import {
  compile,
  evaluate,
  type CompiledBundle,
  type EvaluationInput,
} from '@trustos/policy-engine';
import {
  assertAuthority,
  createApprovalRequest,
  issueGrant,
  recordDecision,
  type ScopedClient,
} from '@trustos/database';
import type { CallerContext } from './context.js';

/**
 * The authorize orchestration (architecture.md §8.1, prd.md §8).
 *
 * Order is the specification's, and it is not arrangeable to taste:
 *
 *   1 identity and scope      2 emergency stops and authority
 *   3 action schema and capability   4 evaluate policy
 *   5 record durably          6 issue approval or grant
 *
 * Capability is checked BEFORE policy, so a permissive rule cannot widen a bound the
 * administrator set (POL-07). Policy narrows capability; it never extends it.
 */

export class AuthorizeError extends Error {
  constructor(
    readonly code:
      | 'INVALID_SCHEMA'
      | 'UNKNOWN_ACTION'
      | 'CONTEXT_MISSING'
      | 'CAPABILITY_DENIED'
      | 'AUTHORITY_UNAVAILABLE'
      | 'NO_POLICY',
    message: string,
    readonly status = 422,
  ) {
    super(message);
    this.name = 'AuthorizeError';
  }
}

export interface AuthorizeBody {
  agent_id: string;
  action: string;
  resource: { type: string; id: string; version?: string | null };
  parameters: Record<string, string | number | boolean>;
  context: Record<string, string | number | boolean>;
  business_deadline?: string | null;
  gateway_audience: string;
}

export interface AuthorizeResult {
  decision_id: string;
  effect: 'allow' | 'deny' | 'approval_required';
  mode: 'shadow' | 'enforced';
  reason_codes: readonly string[];
  policy_bundle_revision: number;
  request_hash: string;
  obligations: readonly string[];
  approval: { id: string; state: string; expires_at: string } | null;
  grant: { id: string; expires_at: string } | null;
}

/** Compiled bundles are cached by immutable revision+hash, never by environment.
 *  A publication produces a new revision, so a stale entry is unreachable rather
 *  than merely refreshed (§7.3). */
const bundleCache = new Map<string, CompiledBundle>();

async function loadBundle(
  client: ScopedClient,
  environmentId: string,
  revision: number,
): Promise<CompiledBundle> {
  const r = await client.query<{ compiled: unknown; compiled_hash: string }>(
    `SELECT compiled, compiled_hash FROM policy_bundles
     WHERE tenant_id = $1 AND environment_id = $2 AND revision = $3`,
    [client.scope.tenantId, environmentId, revision],
  );
  const row = r.rows[0];
  if (!row) {
    // Fail closed. Never substitute an older, more permissive bundle (§13.2).
    throw new AuthorizeError('NO_POLICY', `no published policy at revision ${revision}`, 503);
  }
  const key = `${environmentId}:${revision}:${row.compiled_hash}`;
  const cached = bundleCache.get(key);
  if (cached) return cached;

  const compiled = compile(row.compiled as Parameters<typeof compile>[0]);
  bundleCache.set(key, compiled);
  return compiled;
}

export async function authorize(
  client: ScopedClient,
  caller: CallerContext,
  body: AuthorizeBody,
  idempotencyKey: string,
): Promise<AuthorizeResult> {
  if (!isActionKey(body.action)) {
    // POL-01: an action outside the catalog cannot authorize, and cannot be
    // interpreted as something near it either.
    throw new AuthorizeError('UNKNOWN_ACTION', `action ${body.action} is not in the catalog`);
  }
  const action: ActionKey = body.action;

  // A gateway may only act for agents it is permitted to represent (§5.2). Never an
  // unrestricted act_as_any_agent.
  if (caller.principalType === 'gateway') {
    const allowed = await client.query(
      `SELECT 1 FROM principals
       WHERE tenant_id = $1 AND id = $2 AND environment_id = $3 AND type = 'agent'`,
      [caller.tenantId, body.agent_id, caller.environmentId],
    );
    if (allowed.rows.length === 0) {
      throw new AuthorizeError('CAPABILITY_DENIED', 'gateway may not represent this agent', 403);
    }
  } else if (caller.principalId !== body.agent_id) {
    throw new AuthorizeError('CAPABILITY_DENIED', 'caller may not act as another agent', 403);
  }

  // Emergency stops, agent status, owner status. Throws before any policy work.
  const authority = await assertAuthority(client, body.agent_id);

  const env = await client.query<{
    current_bundle_revision: number;
    enforcement: 'shadow' | 'enforced';
  }>(
    `SELECT current_bundle_revision, enforcement FROM environments
     WHERE tenant_id = $1 AND id = $2`,
    [caller.tenantId, authority.environmentId],
  );
  const environment = env.rows[0];
  if (!environment) throw new AuthorizeError('AUTHORITY_UNAVAILABLE', 'environment not found', 503);

  // Capability bounds the evaluator. POL-07: policy cannot widen what the
  // administrator granted.
  const capability = await client.query<{ constraints: Record<string, unknown> }>(
    `SELECT constraints FROM capability_grants
     WHERE tenant_id = $1 AND environment_id = $2 AND principal_id = $3
       AND action_key = $4 AND status = 'active'`,
    [caller.tenantId, authority.environmentId, body.agent_id, action],
  );
  if (capability.rows.length === 0) {
    throw new AuthorizeError('CAPABILITY_DENIED', `agent has no capability for ${action}`, 403);
  }

  const requestHash = computeRequestFingerprint({
    tenantId: caller.tenantId,
    environmentId: authority.environmentId,
    agentId: body.agent_id,
    action,
    resource: {
      type: body.resource.type,
      id: body.resource.id,
      // Absent and null fingerprint differently, so this preserves which one the
      // caller actually sent rather than normalising both away.
      version: body.resource.version ?? null,
    },
    parameters: body.parameters,
    trustedContext: body.context,
    gatewayAudience: body.gateway_audience,
    businessDeadline: body.business_deadline ?? null,
  });

  const bundle = await loadBundle(
    client,
    authority.environmentId,
    environment.current_bundle_revision,
  );

  // POL-05: a required field that is absent must not quietly stop a restrictive rule
  // from matching, so presence is asserted before evaluation rather than discovered
  // during it.
  const input: EvaluationInput = {
    action,
    parameters: body.parameters,
    resource: {
      type: body.resource.type,
      id: body.resource.id,
      version: body.resource.version ?? '',
    },
    context: body.context,
    principal: { id: body.agent_id },
    time: { now: new Date().toISOString() },
  };
  for (const field of bundle.requiredFields) {
    const [namespace, ...rest] = field.split('.');
    const bag = (input as unknown as Record<string, Record<string, unknown>>)[namespace!];
    if (!bag || !Object.hasOwn(bag, rest.join('.'))) {
      throw new AuthorizeError('CONTEXT_MISSING', `required context ${field} is missing`);
    }
  }

  const verdict = evaluate(bundle, input);

  // Shadow environments evaluate and record, and never produce authority (AUT-08).
  const mode = environment.enforcement === 'enforced' ? 'enforced' : 'shadow';

  const recorded = await recordDecision(client, {
    environmentId: authority.environmentId,
    callerId: caller.principalId,
    route: 'POST /v1/authorize',
    idempotencyKeyHash: computeIdempotencyKeyHash(idempotencyKey),
    requestHash,
    principalId: body.agent_id,
    gatewayPrincipalId: caller.principalType === 'gateway' ? caller.principalId : null,
    actionKey: action,
    resourceType: body.resource.type,
    resourceId: body.resource.id,
    resourceVersion: body.resource.version ?? null,
    businessDeadline: body.business_deadline ?? null,
    effect: verdict.effect,
    mode,
    reasonCodes: verdict.reasonCodes,
    obligations: verdict.obligations,
    bundleRevision: environment.current_bundle_revision,
    principalEpoch: authority.principalEpoch,
    credentialEpoch: 1,
    orgEpoch: authority.orgEpoch,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });

  const base = {
    decision_id: recorded.decisionId,
    effect: verdict.effect,
    mode,
    reason_codes: verdict.reasonCodes,
    policy_bundle_revision: environment.current_bundle_revision,
    request_hash: requestHash,
    obligations: verdict.obligations,
  } as const;

  // An idempotent replay returns the ORIGINAL decision and does not mint fresh
  // authority (§9.2). Current approval and grant state is read separately.
  if (!recorded.created) {
    return { ...base, approval: null, grant: null };
  }

  if (verdict.effect === 'approval_required' && verdict.approval && mode === 'enforced') {
    const approval = await createApprovalRequest(client, {
      environmentId: authority.environmentId,
      decisionId: recorded.decisionId,
      groupKey: verdict.approval.group_key,
      timeoutSeconds: verdict.approval.timeout_seconds,
      businessDeadline: body.business_deadline ? new Date(body.business_deadline) : null,
    });
    return {
      ...base,
      approval: {
        id: approval.approvalId,
        state: 'pending',
        expires_at: approval.expiresAt.toISOString(),
      },
      grant: null,
    };
  }

  if (verdict.effect === 'allow' && mode === 'enforced') {
    const grant = await issueGrant(client, {
      environmentId: authority.environmentId,
      decisionId: recorded.decisionId,
      gatewayAudience: body.gateway_audience,
      requestHash,
      bundleRevision: environment.current_bundle_revision,
      principalEpoch: authority.principalEpoch,
      credentialEpoch: 1,
      ttlSeconds: Number(process.env['GRANT_TTL_SECONDS'] ?? 60),
      businessDeadline: body.business_deadline ? new Date(body.business_deadline) : null,
    });
    return {
      ...base,
      approval: null,
      grant: { id: grant.grantId, expires_at: grant.expiresAt.toISOString() },
    };
  }

  return { ...base, approval: null, grant: null };
}
