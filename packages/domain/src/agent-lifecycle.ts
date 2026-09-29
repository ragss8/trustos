/**
 * Agent lifecycle (prd.md IDN-01..IDN-03, §6.2; architecture.md §4).
 *
 * Pure transition rules, kept separate from the database so they can be reasoned
 * about and tested exhaustively. The repository enforces the same rules again under a
 * row lock — this is the readable statement of them, not the only guard.
 *
 * The rules that carry weight:
 *
 *   - Only `active` confers authority. Draft and suspended agents get decisions
 *     refused; revoked ones are gone for good.
 *   - `revoked` is TERMINAL. IDN-01 forbids ID reuse, so there is no path back. An
 *     operator who revokes by mistake registers a new agent; they do not un-revoke.
 *   - Activation requires an acknowledged owner (IDN-02). Accountability is a
 *     precondition for authority, not a field someone fills in later.
 *   - Resuming does not restore prior authority. It bumps the epoch, which
 *     invalidates every grant issued before the suspension (§6.2).
 */

export type AgentStatus = 'draft' | 'active' | 'suspended' | 'revoked';

export type AgentTransition = 'activate' | 'suspend' | 'resume' | 'revoke';

export interface AgentState {
  readonly status: AgentStatus;
  readonly hasOwner: boolean;
  readonly ownerAcknowledged: boolean;
  readonly ownerActive: boolean;
}

export type TransitionRefusal =
  | 'ALREADY_IN_STATE'
  | 'TERMINAL_STATE'
  | 'INVALID_TRANSITION'
  | 'OWNER_REQUIRED'
  | 'OWNER_ACKNOWLEDGEMENT_REQUIRED'
  | 'OWNER_INACTIVE';

export interface TransitionAllowed {
  readonly allowed: true;
  readonly nextStatus: AgentStatus;
  /** Bumping invalidates credentials and unconsumed grants issued before it. */
  readonly bumpEpoch: boolean;
}

export interface TransitionRefused {
  readonly allowed: false;
  readonly reason: TransitionRefusal;
}

export type TransitionResult = TransitionAllowed | TransitionRefused;

function refuse(reason: TransitionRefusal): TransitionRefused {
  return { allowed: false, reason };
}

export function canTransition(state: AgentState, transition: AgentTransition): TransitionResult {
  // Terminal beats everything, including an attempt to revoke again.
  if (state.status === 'revoked') return refuse('TERMINAL_STATE');

  switch (transition) {
    case 'activate': {
      if (state.status === 'active') return refuse('ALREADY_IN_STATE');
      // Suspended agents resume; they do not re-activate. Keeping these distinct
      // means "resume" always carries the epoch bump and "activate" never has to.
      if (state.status !== 'draft') return refuse('INVALID_TRANSITION');
      if (!state.hasOwner) return refuse('OWNER_REQUIRED');
      if (!state.ownerAcknowledged) return refuse('OWNER_ACKNOWLEDGEMENT_REQUIRED');
      if (!state.ownerActive) return refuse('OWNER_INACTIVE');
      return { allowed: true, nextStatus: 'active', bumpEpoch: false };
    }

    case 'suspend': {
      if (state.status === 'suspended') return refuse('ALREADY_IN_STATE');
      // A draft agent has no authority to contain, but suspending one is harmless and
      // an operator under pressure should not have to know the difference.
      // OPS-01: the epoch bump is what stops new decisions and grant consumption.
      return { allowed: true, nextStatus: 'suspended', bumpEpoch: true };
    }

    case 'resume': {
      if (state.status !== 'suspended') return refuse('INVALID_TRANSITION');
      if (!state.hasOwner) return refuse('OWNER_REQUIRED');
      if (!state.ownerAcknowledged) return refuse('OWNER_ACKNOWLEDGEMENT_REQUIRED');
      // An owner who left during the suspension cannot be accountable for what
      // happens next. Transfer ownership first.
      if (!state.ownerActive) return refuse('OWNER_INACTIVE');
      // Bump again on the way back: prd.md §6.2, "resuming does not revive old grants".
      return { allowed: true, nextStatus: 'active', bumpEpoch: true };
    }

    case 'revoke': {
      return { allowed: true, nextStatus: 'revoked', bumpEpoch: true };
    }
  }
}

/** Only an active agent may receive a decision (IDN-03). */
export function confersAuthority(status: AgentStatus): boolean {
  return status === 'active';
}

/**
 * Owner departure (prd.md §6.2): "Owner departure suspends owned agents unless
 * ownership is transferred first." An active agent whose owner is gone has no
 * accountable human, so it loses authority until someone takes it on.
 */
export function requiresSuspensionOnOwnerDeparture(state: AgentState): boolean {
  return state.status === 'active' && !state.ownerActive;
}
