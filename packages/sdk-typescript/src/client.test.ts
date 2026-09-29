import { describe, expect, it, vi } from 'vitest';
import { TrustOsClient, type AuthorizeRequest } from './client.js';
import { TrustOsError } from './errors.js';

/** Records every call so we can assert on headers, not just outcomes. */
function stubFetch(
  responses: { status: number; body?: unknown; headers?: Record<string, string> }[],
) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const next = responses.shift() ?? { status: 500, body: null };
    return new Response(next.body === undefined ? null : JSON.stringify(next.body), {
      status: next.status,
      headers: { 'content-type': 'application/json', ...(next.headers ?? {}) },
    });
  });
  return { fn: fn as unknown as typeof globalThis.fetch, calls };
}

const request: AuthorizeRequest = {
  agent_id: 'agent_1',
  action: 'crm.discount.apply',
  resource: { type: 'crm.lead', id: 'lead_1', version: '17' },
  parameters: { discount_basis_points: 1500 },
  context: { customer_region: 'KA' },
  gateway_audience: 'gateway_1',
};

const ok = {
  decision_id: 'd1',
  effect: 'approval_required',
  mode: 'enforced',
  reason_codes: ['discount_manager_approval'],
  policy_bundle_revision: 7,
  request_hash: 'sha256:abc',
  obligations: [],
  approval: { id: 'a1', state: 'pending', expires_at: '2026-09-29T08:10:00Z' },
  grant: null,
};

function client(fetchFn: typeof globalThis.fetch, retry = {}) {
  return new TrustOsClient({
    baseUrl: 'https://trustos.test',
    accessToken: 'token',
    fetch: fetchFn,
    sleep: async () => {}, // no real timers
    random: () => 1, // deterministic jitter
    retry,
  });
}

describe('idempotency key handling', () => {
  it('sends the key the caller supplied', async () => {
    const { fn, calls } = stubFetch([{ status: 200, body: ok }]);
    await client(fn).authorize(request, 'key-abc');
    expect((calls[0]!.init.headers as Record<string, string>)['idempotency-key']).toBe('key-abc');
  });

  it('reuses the SAME key across retries, never a fresh one', async () => {
    // Regenerating on retry is how one business intent becomes two decisions and two
    // destination actions. This is the single most important assertion in the SDK.
    const { fn, calls } = stubFetch([
      { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE' } },
      { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE' } },
      { status: 200, body: ok },
    ]);
    await client(fn).authorize(request, 'key-stable');
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect((call.init.headers as Record<string, string>)['idempotency-key']).toBe('key-stable');
    }
  });

  it('uses the execution key as the idempotency key when consuming a grant', async () => {
    // §8.3: same caller + same execution key recovers the original receipt after a
    // lost response, rather than consuming twice.
    const { fn, calls } = stubFetch([{ status: 200, body: { receipt_id: 'r1' } }]);
    await client(fn).consumeGrant('grant_1', {
      request_hash: 'sha256:abc',
      execution_key: 'crm-op-001',
    });
    expect((calls[0]!.init.headers as Record<string, string>)['idempotency-key']).toBe(
      'crm-op-001',
    );
  });
});

describe('retry classification (§9.5)', () => {
  it.each([
    [429, 'RATE_LIMITED'],
    [503, 'AUTHORITY_UNAVAILABLE'],
  ])('retries %i %s', async (status, code) => {
    const { fn, calls } = stubFetch([
      { status, body: { code } },
      { status: 200, body: ok },
    ]);
    await client(fn).authorize(request, 'k');
    expect(calls).toHaveLength(2);
  });

  it.each([
    [400, 'INVALID_SCHEMA'],
    [401, 'INVALID_CREDENTIAL'],
    [403, 'CALLER_SCOPE_DENIED'],
    [409, 'IDEMPOTENCY_CONFLICT'],
    [410, 'GRANT_EXPIRED'],
  ])('does NOT retry %i %s', async (status, code) => {
    const { fn, calls } = stubFetch([
      { status, body: { code } },
      { status: 200, body: ok },
    ]);
    await expect(client(fn).authorize(request, 'k')).rejects.toMatchObject({ code });
    // One attempt only. Retrying a 409 with a new key, or a 410 at all, is how an
    // expired or conflicting intent gets executed anyway.
    expect(calls).toHaveLength(1);
  });

  it('gives up after maxAttempts and surfaces the last error', async () => {
    const { fn, calls } = stubFetch([
      { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE' } },
      { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE' } },
    ]);
    await expect(client(fn, { maxAttempts: 2 }).authorize(request, 'k')).rejects.toMatchObject({
      code: 'AUTHORITY_UNAVAILABLE',
    });
    expect(calls).toHaveLength(2);
  });

  it('honours Retry-After over its own backoff', async () => {
    const slept: number[] = [];
    const { fn } = stubFetch([
      { status: 429, body: { code: 'RATE_LIMITED' }, headers: { 'retry-after': '7' } },
      { status: 200, body: ok },
    ]);
    const c = new TrustOsClient({
      baseUrl: 'https://trustos.test',
      accessToken: 't',
      fetch: fn,
      sleep: async (ms) => void slept.push(ms),
      random: () => 1,
    });
    await c.authorize(request, 'k');
    expect(slept).toEqual([7000]);
  });

  it('applies jitter so synchronised clients do not retry in lockstep', async () => {
    const slept: number[] = [];
    const { fn } = stubFetch([
      { status: 503, body: { code: 'AUTHORITY_UNAVAILABLE' } },
      { status: 200, body: ok },
    ]);
    const c = new TrustOsClient({
      baseUrl: 'https://trustos.test',
      accessToken: 't',
      fetch: fn,
      sleep: async (ms) => void slept.push(ms),
      random: () => 0.25,
      retry: { baseDelayMs: 100 },
    });
    await c.authorize(request, 'k');
    expect(slept).toEqual([25]); // 100 * 0.25, not a fixed 100
  });
});

describe('transport failure', () => {
  it('retries a network error with the same key and flags reconciliation', async () => {
    const fn = vi.fn(async () => {
      throw new Error('ECONNRESET');
    }) as unknown as typeof globalThis.fetch;
    const err = await client(fn, { maxAttempts: 2 })
      .authorize(request, 'k')
      .catch((e: unknown) => e as TrustOsError);
    expect(err).toBeInstanceOf(TrustOsError);
    expect((err as TrustOsError).code).toBe('TRANSPORT_FAILURE');
    // The request may or may not have reached the server, so "try again" is not safe
    // without first reconciling (§10.4).
    expect((err as TrustOsError).requiresReconciliation).toBe(true);
  });
});

describe('responses', () => {
  it('returns approval_required with no grant', async () => {
    const { fn } = stubFetch([{ status: 200, body: ok }]);
    const r = await client(fn).authorize(request, 'k');
    expect(r.effect).toBe('approval_required');
    // INVARIANT 3: no executable authority before approval.
    expect(r.grant).toBeNull();
  });

  it('treats deny as a successful call, not an error', async () => {
    // §9.1: valid effects all return 200. Throwing on deny would tempt callers to
    // retry it.
    const { fn } = stubFetch([{ status: 200, body: { ...ok, effect: 'deny', grant: null } }]);
    const r = await client(fn).authorize(request, 'k');
    expect(r.effect).toBe('deny');
  });

  it('sends no body or content-type on a GET', async () => {
    const { fn, calls } = stubFetch([{ status: 200, body: ok }]);
    await client(fn).getDecision('d1');
    expect(calls[0]!.init.body).toBeUndefined();
    expect((calls[0]!.init.headers as Record<string, string>)['content-type']).toBeUndefined();
  });

  it('resolves a token provider per attempt, so a refresh takes effect', async () => {
    let n = 0;
    const { fn, calls } = stubFetch([
      { status: 401, body: { code: 'INVALID_CREDENTIAL' } },
      { status: 200, body: ok },
    ]);
    const c = new TrustOsClient({
      baseUrl: 'https://trustos.test',
      accessToken: async () => `token-${(n += 1)}`,
      fetch: fn,
      sleep: async () => {},
    });
    await c.authorize(request, 'k').catch(() => {});
    expect((calls[0]!.init.headers as Record<string, string>)['authorization']).toBe(
      'Bearer token-1',
    );
  });
});
