import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { TrustOsClient, type TrustOsError } from '@trustos/sdk-typescript';
import { OperationLedger } from './ledger.js';

/**
 * The reference enforcement gateway (architecture.md §2, §8.3).
 *
 * This is the customer-controlled trust boundary, and the only thing in the system
 * holding destination credentials. The agent has none, which is what makes the
 * control non-optional: there is no path to the CRM that skips this process.
 *
 * Sequence for a protected write:
 *   1 read current resource state from the destination (trusted context, with version)
 *   2 authorize with TrustOS
 *   3 if approval is required, stop -- the agent is told to wait, not to proceed
 *   4 record the execution intent in OUR ledger, before calling anything
 *   5 consume the grant, once
 *   6 call the destination with our credential, its idempotency key and If-Match
 *   7 report the outcome, including "unknown" when we genuinely do not know
 */

export interface GatewayOptions {
  readonly trustosUrl: string;
  readonly crmUrl: string;
  readonly ledgerPath: string;
  readonly tokenProvider: () => Promise<string>;
  readonly gatewayAudience: string;
}

export function buildGateway(options: GatewayOptions): FastifyInstance {
  const app = Fastify({ logger: false });
  const ledger = new OperationLedger(options.ledgerPath);
  const trustos = new TrustOsClient({
    baseUrl: options.trustosUrl,
    accessToken: options.tokenProvider,
  });

  app.get('/health', async () => ({
    status: 'ok',
    needs_reconciliation: ledger.needingReconciliation().length,
  }));

  /**
   * What the agent calls. Note what it CANNOT pass: its own identity (the gateway
   * attests that), the customer region (read from the destination), or any claim
   * about being allowed.
   */
  app.post('/agent/leads/:id/discount', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      agent_id: string;
      discount_basis_points: number;
      business_reason: string;
      simulate?: string;
    };

    // 1. Trusted context comes from the destination, not the agent (§5.3).
    const leadResponse = await fetch(`${options.crmUrl}/leads/${id}`);
    if (!leadResponse.ok) return reply.code(404).send({ error: 'lead_not_found' });
    const lead = (await leadResponse.json()) as { region: string; version: number };
    const observedAt = new Date().toISOString();

    const executionKey = `crm-discount-${id}-${randomUUID()}`;

    // 2. Authorize.
    let decision;
    try {
      decision = await trustos.authorize(
        {
          agent_id: body.agent_id,
          action: 'crm.discount.apply',
          resource: { type: 'crm.lead', id, version: String(lead.version) },
          parameters: { discount_basis_points: body.discount_basis_points },
          context: {
            customer_region: lead.region,
            business_reason: body.business_reason,
            observed_at: observedAt,
          },
          gateway_audience: options.gatewayAudience,
        },
        executionKey,
      );
    } catch (error) {
      const e = error as TrustOsError;
      // Fail closed. An authorization failure is never a reason to proceed.
      return reply.code(e.status || 503).send({ error: e.code, message: e.message });
    }

    if (decision.effect === 'deny') {
      return reply.code(403).send({
        error: 'denied',
        decision_id: decision.decision_id,
        reasons: decision.reason_codes,
      });
    }

    if (decision.effect === 'approval_required') {
      // 3. The agent is told to wait. It is NOT given a way to proceed.
      return reply.code(202).send({
        status: 'awaiting_approval',
        decision_id: decision.decision_id,
        approval: decision.approval,
        poll: `/agent/decisions/${decision.decision_id}`,
      });
    }

    return executeWithGrant(reply, decision.decision_id, decision.grant?.id, {
      requestHash: decision.request_hash,
      executionKey,
      leadId: id,
      version: lead.version,
      discountBasisPoints: body.discount_basis_points,
      simulate: body.simulate,
    });
  });

  /** Poll after an approval. Re-reads authoritative state; a webhook is only a hint. */
  app.get('/agent/decisions/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const decision = (await trustos.getDecision(id)) as unknown as Record<string, unknown>;
    const grantId = decision['grant_id'] as string | undefined;
    const grantState = decision['grant_state'] as string | undefined;

    if (!grantId || grantState !== 'issued') {
      return reply.send({ status: decision['approval_state'] ?? 'pending', decision_id: id });
    }

    const executionKey = `crm-discount-approved-${id}`;
    return executeWithGrant(reply, id, grantId, {
      requestHash: decision['request_hash'] as string,
      executionKey,
      leadId: decision['resource_id'] as string,
      version: Number(decision['resource_version'] ?? 0),
      discountBasisPoints: 0,
      fromApproval: true,
    });
  });

  async function executeWithGrant(
    reply: FastifyReply,
    decisionId: string,
    grantId: string | undefined,
    ctx: {
      requestHash: string;
      executionKey: string;
      leadId: string;
      version: number;
      discountBasisPoints: number;
      simulate?: string | undefined;
      fromApproval?: boolean;
    },
  ) {
    if (!grantId) {
      return reply.code(500).send({ error: 'allow_without_grant', decision_id: decisionId });
    }

    // 4. Record the intent BEFORE touching anything. A crash after this point is
    // recoverable; a crash without it is not.
    ledger.put({ executionKey: ctx.executionKey, state: 'prepared', decisionId, grantId });

    // 5. Consume, once.
    let receipt;
    try {
      receipt = await trustos.consumeGrant(grantId, {
        request_hash: ctx.requestHash,
        execution_key: ctx.executionKey,
        resource_version: String(ctx.version),
      });
    } catch (error) {
      const e = error as TrustOsError;
      ledger.put({ executionKey: ctx.executionKey, state: 'failed', decisionId, grantId });
      return reply.code(e.status || 409).send({ error: e.code, message: e.message });
    }

    ledger.put({
      executionKey: ctx.executionKey,
      state: 'executing',
      decisionId,
      grantId,
      receiptId: receipt.receipt_id,
    });

    // 6. Execute with OUR credential, the destination's idempotency key, and
    // If-Match so a changed record is refused rather than silently overwritten.
    try {
      const response = await fetch(`${options.crmUrl}/leads/${ctx.leadId}/discount`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'idempotency-key': ctx.executionKey,
          'if-match': String(ctx.version),
        },
        body: JSON.stringify({
          discount_basis_points: ctx.discountBasisPoints,
          simulate: ctx.simulate,
        }),
      });

      if (!response.ok) {
        // A 504 after the destination may have written is NOT a failure. Recording it
        // as one would license a retry that applies the discount twice.
        const state = response.status === 504 ? 'unknown' : 'failed';
        ledger.put({
          executionKey: ctx.executionKey,
          state,
          decisionId,
          grantId,
          receiptId: receipt.receipt_id,
        });
        await report(decisionId, receipt.receipt_id, ctx.executionKey, state);
        return reply.code(state === 'unknown' ? 202 : 502).send({
          status: state,
          decision_id: decisionId,
          reconciliation_required: state === 'unknown',
        });
      }

      const result = (await response.json()) as { operation_id: string; version: number };
      ledger.put({
        executionKey: ctx.executionKey,
        state: 'succeeded',
        decisionId,
        grantId,
        receiptId: receipt.receipt_id,
        externalOperationId: result.operation_id,
      });
      // Outside the destination try/catch below: by this point the destination has
      // CONFIRMED success and the ledger says so. A failure to report that is a
      // reporting problem to retry, not grounds to downgrade a known-good execution
      // to "unknown" -- which would invite a retry that discounts the lead twice.
      await report(
        decisionId,
        receipt.receipt_id,
        ctx.executionKey,
        'succeeded',
        result.operation_id,
      );

      return reply.send({
        status: 'succeeded',
        decision_id: decisionId,
        receipt_id: receipt.receipt_id,
        external_operation_id: result.operation_id,
        lead_version: result.version,
      });
    } catch (error) {
      ledger.put({
        executionKey: ctx.executionKey,
        state: 'unknown',
        decisionId,
        grantId,
        receiptId: receipt.receipt_id,
      });
      await report(decisionId, receipt.receipt_id, ctx.executionKey, 'unknown');
      return reply.code(202).send({
        status: 'unknown',
        decision_id: decisionId,
        reconciliation_required: true,
        detail: (error as Error).message,
      });
    }
  }

  /**
   * Reporting is best-effort by design. The ledger is already durable, so a failed
   * report leaves TrustOS showing a consumed grant with no outcome -- visibly
   * unknown, which is the honest state and exactly what AUT-04 asks for. Silently
   * swallowing it here would be wrong; so would rewriting what we know happened.
   */
  async function report(
    decisionId: string,
    receiptId: string,
    executionKey: string,
    state: 'succeeded' | 'failed' | 'unknown',
    externalOperationId?: string,
  ): Promise<void> {
    try {
      await trustos.reportOutcome(decisionId, {
        receipt_id: receiptId,
        report_id: `${executionKey}-1`,
        state,
        ...(externalOperationId === undefined
          ? {}
          : { external_operation_id: externalOperationId }),
      });
    } catch (error) {
      process.stderr.write(
        `outcome report failed for ${decisionId} (${state}); ledger holds the truth: ${(error as Error).message}\n`,
      );
    }
  }

  return app;
}
