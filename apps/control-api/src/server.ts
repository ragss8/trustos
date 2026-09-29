import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { TokenValidationError, TokenValidator } from '@trustos/auth';
import { parseStrictJson, StrictJsonError } from '@trustos/domain';
import {
  createPool,
  currentOutcome,
  resolveApproval,
  ResolutionRefusedError,
  transitionAgent,
  TransitionRefusedError,
  AgentNotFoundError,
} from '@trustos/database';
import {
  inSessionScope,
  requirePermission,
  resolveSession,
  SessionError,
  type ConsoleSession,
} from './session.js';

/** Control API: registry, approvals, audit. Human surface (architecture.md §9.4). */

function mapError(error: unknown): { status: number; body: { code: string; message: string } } {
  if (error instanceof SessionError) {
    const status = error.code === 'INVALID_CREDENTIAL' ? 401 : 403;
    return { status, body: { code: error.code, message: error.message } };
  }
  if (error instanceof TokenValidationError) {
    return { status: 401, body: { code: 'INVALID_CREDENTIAL', message: 'invalid credential' } };
  }
  if (error instanceof StrictJsonError) {
    return { status: 400, body: { code: 'INVALID_SCHEMA', message: error.message } };
  }
  if (error instanceof ResolutionRefusedError) {
    // A refusal is a state, not a malformed request: the caller needs the code to
    // tell "someone beat you to it" from "you are not allowed".
    const status = error.code === 'NOT_FOUND' ? 404 : error.code === 'ALREADY_RESOLVED' ? 409 : 403;
    return { status, body: { code: error.code, message: error.message } };
  }
  if (error instanceof TransitionRefusedError) {
    return { status: 409, body: { code: error.reason, message: error.message } };
  }
  if (error instanceof AgentNotFoundError) {
    return { status: 404, body: { code: 'NOT_FOUND', message: 'not found' } };
  }
  return { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE', message: 'unavailable' } };
}

export function buildServer(deps: { pool: Pool; validator: TokenValidator }): FastifyInstance {
  const app = Fastify({ logger: false, bodyLimit: 64 * 1024 });

  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    try {
      done(null, (body as string).length === 0 ? {} : parseStrictJson(body as string));
    } catch (error) {
      done(error as Error, undefined);
    }
  });

  async function withSession(
    request: FastifyRequest,
    reply: FastifyReply,
    permission: string,
    handler: (session: ConsoleSession) => Promise<unknown>,
  ): Promise<void> {
    try {
      const session = await resolveSession(
        deps.pool,
        deps.validator,
        request.headers.authorization,
        (request.headers['x-trustos-organization'] as string | undefined) ?? undefined,
      );
      requirePermission(session, permission);
      await reply.code(200).send(await handler(session));
    } catch (error) {
      const { status, body } = mapError(error);
      await reply.code(status).send(body);
    }
  }

  app.get('/health', async () => ({ status: 'ok' }));

  app.get('/v1/session', async (request, reply) => {
    await withSession(request, reply, 'session:read', async (s) => ({
      membership_id: s.membershipId,
      organization: { id: s.tenantId, name: s.tenantName },
      role: s.role,
      user_id: s.userId,
    }));
  });

  // ── Approvals ──────────────────────────────────────────────────────────────

  app.get('/v1/approvals', async (request, reply) => {
    await withSession(request, reply, 'approvals:read', (session) =>
      inSessionScope(deps.pool, session, async (c) => {
        const r = await c.query(
          `SELECT a.id, a.state, a.expires_at, a.created_at,
                  d.id AS decision_id, d.effect, d.reason_codes,
                  r.action_key, r.resource_type, r.resource_id, r.resource_version,
                  p.name AS agent_name, p.id AS agent_id,
                  owner.user_id AS agent_owner,
                  (a.expires_at <= now()) AS overdue
           FROM approval_requests a
           JOIN decisions d ON d.tenant_id = a.tenant_id AND d.id = a.decision_id
           JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
           JOIN principals p ON p.tenant_id = r.tenant_id AND p.id = r.principal_id
           LEFT JOIN memberships owner ON owner.tenant_id = p.tenant_id AND owner.id = p.owner_membership_id
           WHERE a.tenant_id = $1 AND a.state = 'pending'
           ORDER BY a.expires_at ASC
           LIMIT 50`,
          [session.tenantId],
        );
        return { approvals: r.rows };
      }),
    );
  });

  for (const [path, effect] of [
    ['approve', 'approved'],
    ['reject', 'rejected'],
  ] as const) {
    app.post(`/v1/approvals/:id/${path}`, async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as { reason?: string };
      await withSession(request, reply, 'approvals:resolve', (session) =>
        inSessionScope(deps.pool, session, async (c) => {
          const outcome = await resolveApproval(c, {
            approvalId: id,
            actorMembershipId: session.membershipId,
            effect,
            reason: body.reason ?? '',
            // Recorded with the resolution as evidence of who acted and how (APR-02).
            sessionEvidence: {
              user_id: session.userId,
              amr: session.token.amr,
              authenticated_at: session.token.authenticatedAt?.toISOString() ?? null,
            },
            gatewayAudience: 'trustos-gateway',
          });
          return {
            approval_id: outcome.approvalId,
            state: outcome.state,
            grant_issued: outcome.grantId !== null,
            replayed: !outcome.resolvedNow,
          };
        }),
      );
    });
  }

  // ── Registry ───────────────────────────────────────────────────────────────

  app.get('/v1/agents', async (request, reply) => {
    await withSession(request, reply, 'agents:read', (session) =>
      inSessionScope(deps.pool, session, async (c) => {
        const r = await c.query(
          `SELECT p.id, p.name, p.status, p.auth_epoch, p.environment_id,
                  m.user_id AS owner, p.owner_acknowledged_at,
                  (SELECT count(*) FROM capability_grants cg
                    WHERE cg.tenant_id = p.tenant_id AND cg.principal_id = p.id
                      AND cg.status = 'active') AS capabilities,
                  (SELECT max(r2.created_at) FROM authorization_requests r2
                    WHERE r2.tenant_id = p.tenant_id AND r2.principal_id = p.id) AS last_activity
           FROM principals p
           LEFT JOIN memberships m ON m.tenant_id = p.tenant_id AND m.id = p.owner_membership_id
           WHERE p.tenant_id = $1 AND p.type = 'agent'
           ORDER BY p.created_at DESC LIMIT 50`,
          [session.tenantId],
        );
        return { agents: r.rows };
      }),
    );
  });

  for (const action of ['suspend', 'resume', 'revoke'] as const) {
    app.post(`/v1/agents/:id/${action}`, async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as { reason?: string };
      await withSession(request, reply, 'agents:contain', (session) =>
        inSessionScope(deps.pool, session, async (c) => {
          const outcome = await transitionAgent(c, id, action, {
            type: 'human',
            id: session.membershipId,
            reason: body.reason ?? '',
          });
          return { agent_id: id, status: outcome.status, auth_epoch: outcome.authEpoch };
        }),
      );
    });
  }

  // ── Evidence ───────────────────────────────────────────────────────────────

  /** Request -> decision -> approval -> grant -> consumption -> outcome (prd.md §10). */
  app.get('/v1/decisions/:id/timeline', async (request, reply) => {
    const { id } = request.params as { id: string };
    await withSession(request, reply, 'audit:read', (session) =>
      inSessionScope(deps.pool, session, async (c) => {
        const r = await c.query(
          `SELECT d.id AS decision_id, d.effect, d.mode, d.reason_codes, d.obligations,
                  d.bundle_revision, d.created_at AS decided_at,
                  r.action_key, r.resource_type, r.resource_id, r.request_hash,
                  p.name AS agent_name,
                  a.id AS approval_id, a.state AS approval_state, a.resolved_at,
                  g.id AS grant_id, g.state AS grant_state, g.expires_at AS grant_expires_at,
                  cr.id AS receipt_id, cr.execution_key, cr.consumed_at
           FROM decisions d
           JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
           JOIN principals p ON p.tenant_id = r.tenant_id AND p.id = r.principal_id
           LEFT JOIN approval_requests a ON a.tenant_id = d.tenant_id AND a.decision_id = d.id
           LEFT JOIN execution_grants g ON g.tenant_id = d.tenant_id AND g.decision_id = d.id
           LEFT JOIN consumption_receipts cr ON cr.tenant_id = g.tenant_id AND cr.grant_id = g.id
           WHERE d.tenant_id = $1 AND d.id = $2`,
          [session.tenantId, id],
        );
        const row = r.rows[0];
        if (!row) throw new AgentNotFoundError(id);

        const events = await c.query(
          `SELECT sequence, event_type, actor_type, occurred_at, safe_payload
           FROM audit_events
           WHERE tenant_id = $1 AND subject_id IN ($2, $3, $4)
           ORDER BY sequence`,
          [session.tenantId, id, row['approval_id'] ?? id, row['grant_id'] ?? id],
        );

        return {
          decision: row,
          execution: await currentOutcome(c, id),
          audit: events.rows,
        };
      }),
    );
  });

  app.get('/v1/audit-events', async (request, reply) => {
    const q = request.query as { cursor?: string; limit?: string };
    // Cursor pagination, capped. No unbounded offsets (§9.1).
    const limit = Math.min(Number(q.limit ?? 50), 200);
    await withSession(request, reply, 'audit:read', (session) =>
      inSessionScope(deps.pool, session, async (c) => {
        const r = await c.query(
          `SELECT id, sequence, event_type, actor_type, actor_id, subject_type,
                  subject_id, safe_payload, occurred_at
           FROM audit_events
           WHERE tenant_id = $1 AND ($2::bigint IS NULL OR sequence < $2::bigint)
           ORDER BY sequence DESC
           LIMIT $3`,
          [session.tenantId, q.cursor ?? null, limit],
        );
        const rows = r.rows as { sequence: string }[];
        return {
          events: rows,
          next_cursor: rows.length === limit ? rows[rows.length - 1]!.sequence : null,
        };
      }),
    );
  });

  app.get('/v1/overview', async (request, reply) => {
    await withSession(request, reply, 'audit:read', (session) =>
      inSessionScope(deps.pool, session, async (c) => {
        const r = await c.query<Record<string, string>>(
          `SELECT
             (SELECT count(*) FROM decisions WHERE tenant_id = $1) AS evaluated,
             (SELECT count(*) FROM decisions WHERE tenant_id = $1 AND effect = 'deny') AS denied,
             (SELECT count(*) FROM approval_requests WHERE tenant_id = $1 AND state = 'pending') AS pending_approvals,
             (SELECT count(*) FROM consumption_receipts WHERE tenant_id = $1) AS consumed_grants,
             (SELECT count(*) FROM execution_outcomes WHERE tenant_id = $1 AND state = 'succeeded') AS succeeded,
             (SELECT count(*) FROM consumption_receipts cr
               WHERE cr.tenant_id = $1
                 AND NOT EXISTS (SELECT 1 FROM execution_outcomes eo
                                  WHERE eo.tenant_id = cr.tenant_id AND eo.receipt_id = cr.id)
             ) AS missing_outcomes`,
          [session.tenantId],
        );
        // missing_outcomes is reported separately and never folded into success:
        // a consumed grant with no report is visibly unknown (AUT-04, prd.md §13).
        return r.rows[0];
      }),
    );
  });

  return app;
}

export async function start(): Promise<void> {
  const pool = createPool(process.env['DATABASE_URL'] ?? '');
  const validator = new TokenValidator({
    issuer: process.env['OIDC_ISSUER_URL'] ?? '',
    audience: process.env['OIDC_AUDIENCE'] ?? 'trustos-api',
  });
  const app = buildServer({ pool, validator });
  await app.register(await import('@fastify/cors').then((m) => m.default), {
    origin: [`http://localhost:${process.env['CONSOLE_PORT'] ?? 5173}`],
    credentials: true,
  });
  const port = Number(process.env['CONTROL_API_PORT'] ?? 53001);
  await app.listen({ port, host: '0.0.0.0' });
  process.stdout.write(`control-api listening on ${port}\n`);
}
