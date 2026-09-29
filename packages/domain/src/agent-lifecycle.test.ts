import { describe, expect, it } from 'vitest';
import {
  canTransition,
  confersAuthority,
  requiresSuspensionOnOwnerDeparture,
  type AgentState,
  type AgentStatus,
  type AgentTransition,
} from './agent-lifecycle.js';

const STATUSES: AgentStatus[] = ['draft', 'active', 'suspended', 'revoked'];
const TRANSITIONS: AgentTransition[] = ['activate', 'suspend', 'resume', 'revoke'];

const ready = (status: AgentStatus): AgentState => ({
  status,
  hasOwner: true,
  ownerAcknowledged: true,
  ownerActive: true,
});

describe('authority', () => {
  it.each(STATUSES)('only active confers authority (%s)', (s) => {
    expect(confersAuthority(s)).toBe(s === 'active');
  });
});

describe('revocation is terminal (IDN-01)', () => {
  it.each(TRANSITIONS)('refuses %s on a revoked agent', (t) => {
    const r = canTransition(ready('revoked'), t);
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('TERMINAL_STATE');
  });

  it('has no path back, so a mistaken revoke means registering a new agent', () => {
    // IDN-01 forbids ID reuse. An un-revoke would resurrect an identity that audit
    // evidence already describes as gone.
    expect(canTransition(ready('revoked'), 'activate').allowed).toBe(false);
    expect(canTransition(ready('revoked'), 'resume').allowed).toBe(false);
  });
});

describe('activation requires accountability (IDN-02)', () => {
  it('activates a draft agent with an acknowledged, active owner', () => {
    const r = canTransition(ready('draft'), 'activate');
    expect(r).toEqual({ allowed: true, nextStatus: 'active', bumpEpoch: false });
  });

  it.each([
    [{ hasOwner: false, ownerAcknowledged: false, ownerActive: false }, 'OWNER_REQUIRED'],
    [
      { hasOwner: true, ownerAcknowledged: false, ownerActive: true },
      'OWNER_ACKNOWLEDGEMENT_REQUIRED',
    ],
    [{ hasOwner: true, ownerAcknowledged: true, ownerActive: false }, 'OWNER_INACTIVE'],
  ])('refuses activation when %o', (owner, reason) => {
    const r = canTransition({ status: 'draft', ...owner }, 'activate');
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe(reason);
  });

  it('will not activate a suspended agent (that is a resume)', () => {
    // Kept distinct so resume always carries the epoch bump and activate never has to.
    const r = canTransition(ready('suspended'), 'activate');
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('INVALID_TRANSITION');
  });
});

describe('containment (OPS-01)', () => {
  it.each(['draft', 'active'] as const)('suspends from %s and bumps the epoch', (s) => {
    const r = canTransition(ready(s), 'suspend');
    expect(r).toEqual({ allowed: true, nextStatus: 'suspended', bumpEpoch: true });
  });

  it('suspends a draft agent without complaint', () => {
    // No authority to contain, but an operator under pressure should not have to
    // know that before acting.
    expect(canTransition(ready('draft'), 'suspend').allowed).toBe(true);
  });

  it('revokes from any non-terminal state with an epoch bump', () => {
    for (const s of ['draft', 'active', 'suspended'] as const) {
      expect(canTransition(ready(s), 'revoke')).toEqual({
        allowed: true,
        nextStatus: 'revoked',
        bumpEpoch: true,
      });
    }
  });
});

describe('resume does not restore prior authority', () => {
  it('bumps the epoch, invalidating grants issued before suspension', () => {
    // prd.md §6.2: "Resuming a suspended agent ... does not revive old grants."
    const r = canTransition(ready('suspended'), 'resume');
    expect(r).toEqual({ allowed: true, nextStatus: 'active', bumpEpoch: true });
  });

  it('refuses to resume when the owner left during suspension', () => {
    const r = canTransition({ ...ready('suspended'), ownerActive: false }, 'resume');
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('OWNER_INACTIVE');
  });

  it('refuses resume from any state but suspended', () => {
    for (const s of ['draft', 'active'] as const) {
      expect(canTransition(ready(s), 'resume').allowed).toBe(false);
    }
  });
});

describe('owner departure (prd.md §6.2)', () => {
  it('requires suspension of an active agent whose owner left', () => {
    expect(requiresSuspensionOnOwnerDeparture({ ...ready('active'), ownerActive: false })).toBe(
      true,
    );
  });

  it('leaves already-inactive agents alone', () => {
    for (const s of ['draft', 'suspended', 'revoked'] as const) {
      expect(requiresSuspensionOnOwnerDeparture({ ...ready(s), ownerActive: false })).toBe(false);
    }
  });
});

describe('the full transition matrix is total', () => {
  it('returns a decision for every state and transition, never undefined', () => {
    // A missing case here would surface as `undefined.allowed` at runtime, on the
    // containment path, which is the worst possible place to find it.
    for (const status of STATUSES) {
      for (const transition of TRANSITIONS) {
        const r = canTransition(ready(status), transition);
        expect(typeof r.allowed).toBe('boolean');
      }
    }
  });
});
