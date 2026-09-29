import { describe, expect, it } from 'vitest';
import {
  computeIdempotencyKeyHash,
  computeRequestFingerprint,
  type FingerprintInput,
} from './request-fingerprint.js';

const base: FingerprintInput = {
  tenantId: 't1',
  environmentId: 'e1',
  agentId: 'agent_1',
  action: 'crm.discount.apply',
  resource: { type: 'crm.lead', id: 'lead_1', version: '17' },
  parameters: { discount_basis_points: 1500 },
  trustedContext: { customer_region: 'KA' },
  gatewayAudience: 'gateway_1',
  businessDeadline: '2026-09-29T08:10:00Z',
};

describe('stability', () => {
  it('is stable across repeated computation', () => {
    const first = computeRequestFingerprint(base);
    for (let i = 0; i < 20; i += 1) expect(computeRequestFingerprint(base)).toBe(first);
  });

  it('ignores key insertion order', () => {
    const reordered: FingerprintInput = {
      ...base,
      parameters: { discount_basis_points: 1500 },
      trustedContext: { customer_region: 'KA' },
    };
    expect(computeRequestFingerprint(reordered)).toBe(computeRequestFingerprint(base));
  });

  it('is unchanged by a multi-key reordering', () => {
    const a = { ...base, parameters: { a: 1, b: 2, c: 3 } };
    const b = { ...base, parameters: { c: 3, a: 1, b: 2 } };
    expect(computeRequestFingerprint(a)).toBe(computeRequestFingerprint(b));
  });

  it('treats 0 and -0 as the same amount', () => {
    const a = { ...base, parameters: { discount_basis_points: 0 } };
    const b = { ...base, parameters: { discount_basis_points: -0 } };
    expect(computeRequestFingerprint(a)).toBe(computeRequestFingerprint(b));
  });
});

describe('sensitivity', () => {
  it.each([
    ['parameters', { ...base, parameters: { discount_basis_points: 1501 } }],
    ['agent', { ...base, agentId: 'agent_2' }],
    ['action', { ...base, action: 'crm.lead.update' as const }],
    ['resource id', { ...base, resource: { ...base.resource, id: 'lead_2' } }],
    ['resource version', { ...base, resource: { ...base.resource, version: '18' } }],
    ['trusted context', { ...base, trustedContext: { customer_region: 'MH' } }],
    ['gateway audience', { ...base, gatewayAudience: 'gateway_2' }],
    ['deadline', { ...base, businessDeadline: '2026-09-29T09:00:00Z' }],
    ['tenant', { ...base, tenantId: 't2' }],
    ['environment', { ...base, environmentId: 'e2' }],
  ])('changes when %s changes', (_label, altered) => {
    expect(computeRequestFingerprint(altered)).not.toBe(computeRequestFingerprint(base));
  });

  it('distinguishes an absent field from an explicitly null one', () => {
    // {"version": null} and {} must not bind to the same grant.
    const absent = { ...base, resource: { type: 'crm.lead', id: 'lead_1' } };
    const explicitNull = { ...base, resource: { type: 'crm.lead', id: 'lead_1', version: null } };
    expect(computeRequestFingerprint(absent)).not.toBe(computeRequestFingerprint(explicitNull));
  });

  it('does not let a string collide with a number of the same text', () => {
    const asNumber = { ...base, parameters: { discount_basis_points: 1500 } };
    const asString = { ...base, parameters: { discount_basis_points: '1500' } };
    expect(computeRequestFingerprint(asNumber)).not.toBe(computeRequestFingerprint(asString));
  });

  it('does not let key/value boundaries be shifted into a collision', () => {
    // A naive concatenation fingerprint collides on these two.
    const a = { ...base, parameters: { ab: 'c' } };
    const b = { ...base, parameters: { a: 'bc' } };
    expect(computeRequestFingerprint(a)).not.toBe(computeRequestFingerprint(b));
  });
});

describe('idempotency key hashing', () => {
  it('is stable and distinguishes different keys', () => {
    expect(computeIdempotencyKeyHash('k1')).toBe(computeIdempotencyKeyHash('k1'));
    expect(computeIdempotencyKeyHash('k1')).not.toBe(computeIdempotencyKeyHash('k2'));
  });

  it('emits a prefixed sha256 digest', () => {
    expect(computeIdempotencyKeyHash('k1')).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
