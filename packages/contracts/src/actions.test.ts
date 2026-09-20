import { describe, expect, it } from 'vitest';
import { ACTION_CATALOG, ACTION_KEYS, getAction, isActionKey } from './actions.js';

describe('action catalog', () => {
  it('holds exactly the ten actions agreed for the first partner (prd.md §5.2)', () => {
    expect(ACTION_KEYS).toHaveLength(10);
  });

  it('keys its entries consistently, so lookup cannot return a mismatched definition', () => {
    for (const key of ACTION_KEYS) expect(ACTION_CATALOG[key].key).toBe(key);
  });

  it('uses the namespaced domain.resource.verb form required by POL-01', () => {
    for (const key of ACTION_KEYS) expect(key).toMatch(/^[a-z]+\.[a-z]+\.[a-z]+$/);
  });

  // A write that is not 'protected' needs no consumed grant, which removes the
  // enforcement point entirely. That must never happen by oversight.
  it('classifies every write action as protected', () => {
    const unprotected = ACTION_KEYS.filter(
      (k) =>
        ACTION_CATALOG[k].effectClass === 'write' && ACTION_CATALOG[k].riskClass !== 'protected',
    );
    expect(unprotected).toEqual([]);
  });

  it('requires a resource version for writes that mutate an existing record', () => {
    // architecture.md §8.3: conditional update stops an approved action landing on a
    // record that changed after the decision was made.
    for (const key of ['crm.lead.update', 'crm.lead.assign', 'support.ticket.update'] as const) {
      expect(ACTION_CATALOG[key].requiredTrustedContext).toContain('resource_version');
    }
  });

  it('requires a business reason for the discount path', () => {
    expect(ACTION_CATALOG['crm.discount.apply'].requiredTrustedContext).toContain(
      'business_reason',
    );
  });
});

describe('isActionKey', () => {
  it('accepts every catalog key', () => {
    for (const key of ACTION_KEYS) expect(isActionKey(key)).toBe(true);
  });

  // POL-01: an unknown action cannot authorize. These are the shapes an attacker or a
  // buggy agent actually sends.
  it.each([
    'crm.discount.apply ',
    'CRM.DISCOUNT.APPLY',
    'crm.discount.approve',
    '__proto__',
    'constructor',
    'toString',
    '',
    null,
    undefined,
    42,
    {},
    ['crm.lead.read'],
  ])('rejects %p', (v) => {
    expect(isActionKey(v)).toBe(false);
  });
});

describe('getAction', () => {
  it('returns the definition for a known key', () => {
    expect(getAction('crm.discount.apply').resourceType).toBe('crm.lead');
  });
});
