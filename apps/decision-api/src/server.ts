import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { Pool } from 'pg';
import { TokenValidator, TokenValidationError } from '@trustos/auth';
import { parseStrictJson, StrictJsonError } from '@trustos/domain';
import {
  AgentNotFoundError,
  AuthorityRefusedError,
  ConsumeRefusedError,
  consumeGrant,
  createPool,
  currentOutcome,
  IdempotencyConflictError,
  OutcomeRefusedError,
  reportOutcome,
} from '@trustos/database';
import { authorize, AuthorizeError, type AuthorizeBody } from './authorize.js';
import {
  AuthenticationError,
  inCallerScope,
  resolveCaller,
  type CallerContext,
} from './context.js';

/**
 * Decision API (architecture.md §9).
 *
 * Framework note: the spec names NestJS. Fastify is used instead because Nest's DI
 * relies on emitDecoratorMetadata, which conflicts with this repo's
 * verbatimModuleSyntax/isolatedModules settings, and module boundaries here are
 * already enforced by dependency-cruiser rather than by a framework's module system.
 * Recorded as a deviation for review.
 */

interface ErrorShape {
  code: string;
  message: string;
}

/**
 * Error mapping (§9.5). Two rules matter more than the table itself:
 *   - A technical failure NEVER carries a grant.
 *   - A valid decision, including deny, is 200. Only failures are non-2xx.
 */
function mapError(error: unknown): { status: number; body: ErrorShape } {
  if (error instanceof AuthenticationError) {
    return {
      status: error.code === 'INVALID_CREDENTIAL' ? 401 : 403,
      body: { code: error.code, message: error.message },
    };
  }
  if (error instanceof TokenValidationError) {
    return { status: 401, body: { code: 'INVALID_CREDENTIAL', message: 'invalid credential' } };
  }
  if (error instanceof StrictJsonError) {
    return { status: 400, body: { code: 'INVALID_SCHEMA', message: error.message } };
  }
  if (error instanceof IdempotencyConflictError) {
    return { status: 409, body: { code: 'IDEMPOTENCY_CONFLICT', message: error.message } };
  }
  if (error instanceof AuthorizeError) {
    return { status: error.status, body: { code: error.code, message: error.message } };
  }
  if (error instanceof AuthorityRefusedError) {
    // Containment is not a client error to be corrected; it is authority withdrawn.
    return { status: 403, body: { code: error.code, message: error.message } };
  }
  if (error instanceof AgentNotFoundError) {
    return { status: 404, body: { code: 'NOT_FOUND', message: 'not found' } };
  }
  if (error instanceof ConsumeRefusedError) {
    const status =
      error.code === 'GRANT_NOT_FOUND'
        ? 404
        : error.code === 'GRANT_EXPIRED' ||
            error.code === 'POLICY_CHANGED' ||
            error.code === 'AUTHORITY_STALE'
          ? 410 // Gone: reauthorize. Retrying this exact call can never succeed.
          : 409;
    return { status, body: { code: error.code, message: error.message } };
  }
  if (error instanceof OutcomeRefusedError) {
    return { status: 409, body: { code: error.code, message: error.message } };
  }
  return {
    status: 503,
    body: { code: 'AUTHORITY_UNAVAILABLE', message: 'authority could not be established' },
  };
}

export interface ServerDeps {
  readonly pool: Pool;
  readonly validator: TokenValidator;
}

export function buildServer(deps: ServerDeps): FastifyInstance {
  const app = Fastify({
    logger: false,
    // Bounded before parsing (§7.1). A 16 KiB ceiling is part of the latency budget.
    bodyLimit: 16 * 1024,
  });

  // Parse with the strict parser, not JSON.parse: duplicate keys must be refused
  // before anything is hashed or evaluated.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    try {
      done(null, parseStrictJson(body as string));
    } catch (error) {
      done(error as Error, undefined);
    }
  });

  async function withCaller(
    request: FastifyRequest,
    reply: FastifyReply,
    handler: (caller: CallerContext) => Promise<unknown>,
  ): Promise<void> {
    try {
      const caller = await resolveCaller(deps.pool, deps.validator, request.headers.authorization);
      const result = await handler(caller);
      await reply.code(200).send(result);
    } catch (error) {
      const { status, body } = mapError(error);
      await reply.code(status).send(body);
    }
  }

  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/v1/authorize', async (request, reply) => {
    const idempotencyKey = request.headers['idempotency-key'];
    if (typeof idempotencyKey !== 'string' || idempotencyKey.length === 0) {
      // Required, not optional: without it a retried request becomes a second
      // decision and a second destination action (AUT-02).
      await reply
        .code(400)
        .send({ code: 'INVALID_SCHEMA', message: 'Idempotency-Key is required' });
      return;
    }
    await withCaller(request, reply, (caller) =>
      inCallerScope(deps.pool, caller, (client) =>
        authorize(client, caller, request.body as AuthorizeBody, idempotencyKey),
      ),
    );
  });

  app.get('/v1/decisions/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    await withCaller(request, reply, (caller) =>
      inCallerScope(deps.pool, caller, async (client) => {
        const r = await client.query<Record<string, unknown>>(
          `SELECT d.id AS decision_id, d.effect, d.mode, d.reason_codes, d.obligations,
                  d.bundle_revision AS policy_bundle_revision, r.request_hash,
                  a.id AS approval_id, a.state AS approval_state, a.expires_at AS approval_expires_at,
                  g.id AS grant_id, g.state AS grant_state, g.expires_at AS grant_expires_at
           FROM decisions d
           JOIN authorization_requests r ON r.tenant_id = d.tenant_id AND r.id = d.request_id
           LEFT JOIN approval_requests a ON a.tenant_id = d.tenant_id AND a.decision_id = d.id
           LEFT JOIN execution_grants g ON g.tenant_id = d.tenant_id AND g.decision_id = d.id
           WHERE d.tenant_id = $1 AND d.id = $2`,
          [caller.tenantId, id],
        );
        const row = r.rows[0];
        if (!row) throw new AgentNotFoundError(id);
        // The original decision is immutable; current approval, grant and execution
        // state are reported separately (§9.2).
        const outcome = await currentOutcome(client, id);
        return { ...row, execution: outcome };
      }),
    );
  });

  app.post('/v1/grants/:id/consume', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      request_hash: string;
      execution_key: string;
      resource_version?: string | null;
    };
    await withCaller(request, reply, async (caller) => {
      if (caller.principalType !== 'gateway') {
        // §5.2: execution authority is consumed by the trusted gateway only. A direct
        // agent credential must never be able to.
        throw new AuthenticationError('CALLER_SCOPE_DENIED', 'only a gateway may consume a grant');
      }
      const receipt = await inCallerScope(deps.pool, caller, (client) =>
        consumeGrant(client, {
          grantId: id,
          gatewayPrincipalId: caller.principalId,
          gatewayAudience: caller.clientId,
          requestHash: body.request_hash,
          executionKey: body.execution_key,
          resourceVersion: body.resource_version ?? null,
        }),
      );
      return {
        receipt_id: receipt.receiptId,
        decision_id: receipt.decisionId,
        grant_id: receipt.grantId,
        execution_key: receipt.executionKey,
        state: 'consumed',
        consumed_at: receipt.consumedAt.toISOString(),
        recovered: !receipt.consumedNow,
      };
    });
  });

  app.post('/v1/decisions/:id/outcomes', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      receipt_id: string;
      report_id: string;
      state: 'started' | 'succeeded' | 'failed' | 'unknown';
      external_operation_id?: string;
      detail?: Record<string, unknown>;
      is_reconciliation?: boolean;
    };
    await withCaller(request, reply, (caller) =>
      inCallerScope(deps.pool, caller, (client) =>
        reportOutcome(client, {
          decisionId: id,
          receiptId: body.receipt_id,
          gatewayPrincipalId: caller.principalId,
          reportId: body.report_id,
          state: body.state,
          externalOperationId: body.external_operation_id ?? null,
          detail: body.detail ?? {},
          isReconciliation: body.is_reconciliation ?? false,
        }),
      ),
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
  const port = Number(process.env['DECISION_API_PORT'] ?? 53002);
  await app.listen({ port, host: '0.0.0.0' });
  process.stdout.write(`decision-api listening on ${port}\n`);
}

export { Pool };
