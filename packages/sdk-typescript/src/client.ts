import type { ActionKey } from '@trustos/contracts';
import { errorFromResponse, TrustOsError } from './errors.js';

/**
 * TrustOS client.
 *
 * Two behaviours here are load-bearing rather than conveniences:
 *
 * 1. A retry reuses the ORIGINAL idempotency key. Generating a fresh one on retry is
 *    the single most damaging bug an SDK of this kind can have: the server correctly
 *    treats it as a new intent and issues a second decision, so one business action
 *    becomes two.
 *
 * 2. Only documented-retryable failures are retried (§9.5). A 409 or 410 is never
 *    retried, with any key.
 */

export type Effect = 'allow' | 'deny' | 'approval_required';

export interface AuthorizeRequest {
  readonly agent_id: string;
  readonly action: ActionKey;
  readonly resource: { readonly type: string; readonly id: string; readonly version?: string };
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly context: Readonly<Record<string, string | number | boolean>>;
  readonly business_deadline?: string;
  readonly gateway_audience: string;
}

export interface AuthorizeResponse {
  readonly decision_id: string;
  readonly effect: Effect;
  readonly mode: 'shadow' | 'enforced';
  readonly reason_codes: readonly string[];
  readonly policy_bundle_revision: number;
  readonly request_hash: string;
  readonly obligations: readonly string[];
  readonly approval: {
    readonly id: string;
    readonly state: string;
    readonly expires_at: string;
  } | null;
  /** null for deny, for approval_required before approval, and always in shadow mode. */
  readonly grant: { readonly id: string; readonly expires_at: string } | null;
}

export interface ConsumeResponse {
  readonly receipt_id: string;
  readonly decision_id: string;
  readonly grant_id: string;
  readonly execution_key: string;
  readonly state: 'consumed';
  readonly consumed_at: string;
}

export interface RetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
}

export interface ClientOptions {
  readonly baseUrl: string;
  readonly accessToken: string | (() => Promise<string>);
  readonly fetch?: typeof globalThis.fetch;
  readonly retry?: Partial<RetryPolicy>;
  /** Injected so tests need no real timers. */
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
}

const DEFAULT_RETRY: RetryPolicy = { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 2_000 };

export class TrustOsClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #retry: RetryPolicy;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #random: () => number;

  constructor(private readonly options: ClientOptions) {
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#retry = { ...DEFAULT_RETRY, ...options.retry };
    this.#sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.#random = options.random ?? Math.random;
  }

  async authorize(request: AuthorizeRequest, idempotencyKey: string): Promise<AuthorizeResponse> {
    return this.#send<AuthorizeResponse>('POST', '/v1/authorize', request, idempotencyKey);
  }

  async consumeGrant(
    grantId: string,
    body: { request_hash: string; execution_key: string; resource_version?: string },
  ): Promise<ConsumeResponse> {
    // The execution key IS the idempotency key here: the gateway's durable handle on
    // one execution intent, so a lost response recovers the same receipt (§8.3).
    return this.#send<ConsumeResponse>(
      'POST',
      `/v1/grants/${encodeURIComponent(grantId)}/consume`,
      body,
      body.execution_key,
    );
  }

  async reportOutcome(
    decisionId: string,
    body: {
      /** Proves the caller is the gateway that consumed the grant (AUT-04). */
      receipt_id: string;
      report_id: string;
      state: 'started' | 'succeeded' | 'failed' | 'unknown';
      external_operation_id?: string;
      is_reconciliation?: boolean;
    },
  ): Promise<void> {
    await this.#send(
      'POST',
      `/v1/decisions/${encodeURIComponent(decisionId)}/outcomes`,
      body,
      body.report_id,
    );
  }

  async getDecision(decisionId: string): Promise<AuthorizeResponse> {
    return this.#send<AuthorizeResponse>('GET', `/v1/decisions/${encodeURIComponent(decisionId)}`);
  }

  async #token(): Promise<string> {
    const t = this.options.accessToken;
    return typeof t === 'function' ? t() : t;
  }

  #backoff(attempt: number, retryAfterSeconds?: number): number {
    if (retryAfterSeconds !== undefined) return retryAfterSeconds * 1000;
    const exponential = Math.min(
      this.#retry.baseDelayMs * 2 ** (attempt - 1),
      this.#retry.maxDelayMs,
    );
    // Full jitter: synchronised clients must not retry in lockstep and re-create the
    // spike that rate-limited them.
    return Math.floor(exponential * this.#random());
  }

  async #send<T>(
    method: string,
    path: string,
    body?: unknown,
    idempotencyKey?: string,
  ): Promise<T> {
    let lastError: TrustOsError | undefined;

    for (let attempt = 1; attempt <= this.#retry.maxAttempts; attempt += 1) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${await this.#token()}`,
        accept: 'application/json',
      };
      if (body !== undefined) headers['content-type'] = 'application/json';
      // Same key on every attempt. Never regenerated.
      if (idempotencyKey !== undefined) headers['idempotency-key'] = idempotencyKey;

      let response: Response;
      try {
        // Built conditionally: exactOptionalPropertyTypes rejects an explicit
        // `body: undefined`, and a GET with a body key present is not the same
        // request as one without it.
        const init: RequestInit = { method, headers };
        if (body !== undefined) init.body = JSON.stringify(body);
        response = await this.#fetch(`${this.options.baseUrl}${path}`, init);
      } catch (cause) {
        // The request may or may not have reached the server, so this is retryable
        // with the same key, and unresolved outcomes need reconciliation.
        lastError = new TrustOsError('TRANSPORT_FAILURE', 0, (cause as Error).message);
        if (attempt === this.#retry.maxAttempts) throw lastError;
        await this.#sleep(this.#backoff(attempt));
        continue;
      }

      if (response.ok) return (await response.json()) as T;

      const retryAfter = response.headers.get('retry-after');
      const error = errorFromResponse(
        response.status,
        await response.json().catch(() => null),
        response.headers.get('x-request-id') ?? undefined,
        retryAfter === null ? undefined : Number(retryAfter),
      );

      if (!error.retryable || attempt === this.#retry.maxAttempts) throw error;
      lastError = error;
      await this.#sleep(this.#backoff(attempt, error.retryAfterSeconds));
    }

    throw lastError ?? new TrustOsError('UNKNOWN', 0, 'retries exhausted');
  }
}
