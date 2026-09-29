/**
 * Error taxonomy (architecture.md §9.5).
 *
 * The important property is not the names — it is which of these a client may retry.
 * Retrying the wrong one turns a single business intent into two destination actions.
 */

export type TrustOsErrorCode =
  | 'INVALID_SCHEMA'
  | 'CONTEXT_MISSING'
  | 'INVALID_CREDENTIAL'
  | 'CALLER_SCOPE_DENIED'
  | 'NOT_FOUND'
  | 'IDEMPOTENCY_CONFLICT'
  | 'STATE_CONFLICT'
  | 'GRANT_EXPIRED'
  | 'AUTHORITY_STALE'
  | 'GRANT_ALREADY_CONSUMED'
  | 'RATE_LIMITED'
  | 'AUTHORITY_UNAVAILABLE'
  | 'DURABLE_STORE_UNAVAILABLE'
  | 'TRANSPORT_FAILURE'
  | 'UNKNOWN';

export class TrustOsError extends Error {
  constructor(
    readonly code: TrustOsErrorCode,
    readonly status: number,
    message: string,
    readonly requestId?: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'TrustOsError';
  }

  /**
   * Only rate limiting and genuine unavailability are retryable, and only with the
   * SAME idempotency key.
   *
   * Everything else is deliberately excluded:
   *   409 IDEMPOTENCY_CONFLICT  the body changed; a retry cannot fix that, and a NEW
   *                             key would create a second decision for one intent
   *   410 GRANT_EXPIRED         authority is gone; reauthorize, do not retry
   *   403 CALLER_SCOPE_DENIED   scope will not change by asking again
   *   400/422                   the request is wrong
   */
  get retryable(): boolean {
    return (
      this.code === 'RATE_LIMITED' ||
      this.code === 'AUTHORITY_UNAVAILABLE' ||
      this.code === 'DURABLE_STORE_UNAVAILABLE' ||
      this.code === 'TRANSPORT_FAILURE'
    );
  }

  /**
   * True when the destination may or may not have acted. The caller must reconcile
   * by external operation id before requesting new authority (§10.4) — never simply
   * try again.
   */
  get requiresReconciliation(): boolean {
    return this.code === 'TRANSPORT_FAILURE' || this.code === 'GRANT_ALREADY_CONSUMED';
  }
}

const STATUS_DEFAULTS: Record<number, TrustOsErrorCode> = {
  400: 'INVALID_SCHEMA',
  401: 'INVALID_CREDENTIAL',
  403: 'CALLER_SCOPE_DENIED',
  404: 'NOT_FOUND',
  409: 'STATE_CONFLICT',
  410: 'GRANT_EXPIRED',
  422: 'INVALID_SCHEMA',
  429: 'RATE_LIMITED',
  503: 'AUTHORITY_UNAVAILABLE',
};

export function errorFromResponse(
  status: number,
  body: unknown,
  requestId?: string,
  retryAfterSeconds?: number,
): TrustOsError {
  const parsed = body as { code?: unknown; message?: unknown } | null;
  const code =
    typeof parsed?.code === 'string'
      ? (parsed.code as TrustOsErrorCode)
      : (STATUS_DEFAULTS[status] ?? 'UNKNOWN');
  const message =
    typeof parsed?.message === 'string' ? parsed.message : `request failed (${status})`;
  return new TrustOsError(code, status, message, requestId, retryAfterSeconds);
}
