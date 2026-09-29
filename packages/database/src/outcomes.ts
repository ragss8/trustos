import type { ScopedClient } from './tenant-transaction.js';
import { appendAuditEvent, publishOutboxEvent } from './audit.js';

/**
 * Execution outcome reporting (AUT-04, architecture.md §10.4).
 *
 * Append-only. Reports require an authorised consumed receipt, so nothing can claim
 * an outcome for an action that was never granted authority.
 *
 * "Unknown" is a first-class state, not a failure. A gateway that crashed after
 * calling the destination genuinely does not know, and recording that honestly is the
 * whole point: a missing outcome must stay visibly unknown rather than being counted
 * as success (prd.md §13).
 */

export type OutcomeState = 'started' | 'succeeded' | 'failed' | 'unknown';

export class OutcomeRefusedError extends Error {
  constructor(
    readonly code: 'RECEIPT_NOT_FOUND' | 'NOT_RECEIPT_OWNER' | 'CONTRADICTORY_TERMINAL',
    message: string,
  ) {
    super(message);
    this.name = 'OutcomeRefusedError';
  }
}

export interface ReportOutcomeInput {
  readonly decisionId: string;
  readonly receiptId: string;
  readonly gatewayPrincipalId: string;
  readonly reportId: string;
  readonly state: OutcomeState;
  readonly externalOperationId?: string | null;
  readonly detail?: Record<string, unknown>;
  /** Set when deliberately correcting an earlier terminal report (§10.4). */
  readonly isReconciliation?: boolean;
}

const TERMINAL: ReadonlySet<OutcomeState> = new Set(['succeeded', 'failed']);

export async function reportOutcome(
  client: ScopedClient,
  input: ReportOutcomeInput,
): Promise<{ outcomeId: string; duplicate: boolean }> {
  const { tenantId } = client.scope;

  const receipt = await client.query<{ gateway_id: string; environment_id: string }>(
    `SELECT cr.gateway_id, g.environment_id
     FROM consumption_receipts cr
     JOIN execution_grants g ON g.tenant_id = cr.tenant_id AND g.id = cr.grant_id
     WHERE cr.tenant_id = $1 AND cr.id = $2 AND g.decision_id = $3`,
    [tenantId, input.receiptId, input.decisionId],
  );
  const row = receipt.rows[0];
  if (!row)
    throw new OutcomeRefusedError('RECEIPT_NOT_FOUND', 'no consumed grant for this decision');
  if (row.gateway_id !== input.gatewayPrincipalId) {
    // Only the gateway that consumed the grant may say what happened.
    throw new OutcomeRefusedError('NOT_RECEIPT_OWNER', 'caller did not consume this grant');
  }

  // Arrival order is not truth (§10.4): a delayed 'started' after 'succeeded' is
  // ordinary. What is refused is a CONTRADICTORY terminal, unless explicitly
  // submitted as a reconciliation with a reason.
  if (TERMINAL.has(input.state) && input.isReconciliation !== true) {
    const existing = await client.query<{ state: OutcomeState }>(
      `SELECT state FROM execution_outcomes
       WHERE tenant_id = $1 AND decision_id = $2 AND state IN ('succeeded','failed')`,
      [tenantId, input.decisionId],
    );
    const conflicting = existing.rows.find((r) => r.state !== input.state);
    if (conflicting) {
      throw new OutcomeRefusedError(
        'CONTRADICTORY_TERMINAL',
        `already reported ${conflicting.state}; submit a reconciliation to correct it`,
      );
    }
  }

  try {
    const r = await client.query<{ id: string }>(
      `INSERT INTO execution_outcomes
         (tenant_id, environment_id, decision_id, receipt_id, report_id, state,
          external_operation_id, detail, is_reconciliation)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING id`,
      [
        tenantId,
        row.environment_id,
        input.decisionId,
        input.receiptId,
        input.reportId,
        input.state,
        input.externalOperationId ?? null,
        JSON.stringify(input.detail ?? {}),
        input.isReconciliation ?? false,
      ],
    );

    await appendAuditEvent(client, {
      environmentId: row.environment_id,
      actorType: 'gateway',
      actorId: input.gatewayPrincipalId,
      eventType: 'execution.outcome_reported',
      subjectType: 'decision',
      subjectId: input.decisionId,
      safePayload: {
        state: input.state,
        external_operation_id: input.externalOperationId ?? null,
      },
    });
    await publishOutboxEvent(client, row.environment_id, 'execution.outcome', {
      decision_id: input.decisionId,
      state: input.state,
    });

    return { outcomeId: r.rows[0]!.id, duplicate: false };
  } catch (error) {
    if ((error as { code?: string }).code === '23505') {
      // Same report id replayed. Idempotent by design: a retried report must not
      // append a second record.
      const existing = await client.query<{ id: string }>(
        `SELECT id FROM execution_outcomes
         WHERE tenant_id = $1 AND decision_id = $2 AND report_id = $3`,
        [tenantId, input.decisionId, input.reportId],
      );
      return { outcomeId: existing.rows[0]!.id, duplicate: true };
    }
    throw error;
  }
}

/** Current projection. Computed from the reports, never stored as a mutable field. */
export async function currentOutcome(
  client: ScopedClient,
  decisionId: string,
): Promise<{ state: OutcomeState | 'none'; externalOperationId: string | null }> {
  const r = await client.query<{ state: OutcomeState; external_operation_id: string | null }>(
    `SELECT state, external_operation_id FROM execution_outcomes
     WHERE tenant_id = $1 AND decision_id = $2
     ORDER BY is_reconciliation DESC, reported_at DESC
     LIMIT 1`,
    [client.scope.tenantId, decisionId],
  );
  const row = r.rows[0];
  return row
    ? { state: row.state, externalOperationId: row.external_operation_id }
    : { state: 'none', externalOperationId: null };
}
