import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * The gateway's own durable operation ledger (architecture.md §8.3).
 *
 * This belongs to the CUSTOMER's trust domain, not TrustOS, so it deliberately uses
 * its own storage rather than TrustOS's database.
 *
 * Why it exists at all: TrustOS receipts guarantee a grant is consumed once. They
 * cannot stop a gateway that crashes mid-execution from calling the destination a
 * second time on restart. Only a record written BEFORE the destination call can, and
 * that record has to be the gateway's own.
 *
 * States: prepared -> receipt_received -> executing -> succeeded | failed | unknown.
 * A crash in `executing` means the destination may or may not have applied the write,
 * so recovery must reconcile rather than retry.
 */

export type OperationState =
  'prepared' | 'receipt_received' | 'executing' | 'succeeded' | 'failed' | 'unknown';

export interface OperationRecord {
  executionKey: string;
  state: OperationState;
  decisionId?: string;
  grantId?: string;
  receiptId?: string;
  externalOperationId?: string;
  updatedAt: string;
}

export class OperationLedger {
  #records = new Map<string, OperationRecord>();

  constructor(private readonly path: string) {
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8')) as OperationRecord[];
      for (const r of raw) this.#records.set(r.executionKey, r);
    } catch {
      // No ledger yet. An empty one is correct for a first run.
    }
  }

  get(executionKey: string): OperationRecord | undefined {
    return this.#records.get(executionKey);
  }

  /** Written and flushed before the state it describes is acted on. */
  put(record: Omit<OperationRecord, 'updatedAt'>): OperationRecord {
    const full: OperationRecord = { ...record, updatedAt: new Date().toISOString() };
    this.#records.set(record.executionKey, full);
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify([...this.#records.values()], null, 2));
    return full;
  }

  /** Operations that need reconciliation before any further attempt. */
  needingReconciliation(): OperationRecord[] {
    return [...this.#records.values()].filter(
      (r) => r.state === 'executing' || r.state === 'unknown',
    );
  }
}
