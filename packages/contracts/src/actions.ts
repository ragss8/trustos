/**
 * Canonical action vocabulary (prd.md §20).
 *
 * These keys are the shared language between policy, capability grants, decisions and
 * audit. Adapters map a destination's native operation names onto these keys; the
 * destination's own vocabulary never leaks into policy.
 *
 * Adding a key here is a contract change. An action absent from this catalog cannot be
 * authorized (POL-01): unknown actions fail validation rather than falling through to a
 * default.
 */

/** Whether the action changes state at the destination. */
export type ActionEffectClass = 'read' | 'write';

/**
 * Whether the action is eligible for the approval workflow at all.
 *
 * `protected` actions are the ones that require a consumed execution grant before the
 * gateway may call the destination. Marking an action `routine` is a statement that no
 * policy will ever route it to a human, so a mistake here silently removes a control.
 */
export type ActionRiskClass = 'routine' | 'protected';

export interface ActionDefinition {
  readonly key: ActionKey;
  readonly resourceType: ResourceType;
  readonly effectClass: ActionEffectClass;
  readonly riskClass: ActionRiskClass;
  readonly summary: string;
  /**
   * Context attributes that must be present and trusted before this action can be
   * evaluated. Attributes sourced from the agent itself can never satisfy these
   * (architecture.md §5.3); the gateway supplies them with provenance and observed_at.
   */
  readonly requiredTrustedContext: readonly TrustedContextKey[];
}

export type ResourceType =
  | 'crm.lead'
  | 'crm.note'
  | 'communication.thread'
  | 'calendar.calendar'
  | 'calendar.meeting'
  | 'support.ticket';

export type TrustedContextKey =
  'customer_region' | 'resource_version' | 'business_reason' | 'assigned_owner';

export const ACTION_KEYS = [
  'crm.lead.read',
  'crm.lead.update',
  'crm.lead.assign',
  'crm.note.create',
  'crm.discount.apply',
  'communication.email.send',
  'calendar.availability.read',
  'calendar.meeting.create',
  'support.ticket.read',
  'support.ticket.update',
] as const;

export type ActionKey = (typeof ACTION_KEYS)[number];

export const ACTION_CATALOG: Readonly<Record<ActionKey, ActionDefinition>> = {
  'crm.lead.read': {
    key: 'crm.lead.read',
    resourceType: 'crm.lead',
    effectClass: 'read',
    riskClass: 'routine',
    summary: 'Read a single lead record.',
    requiredTrustedContext: ['customer_region'],
  },
  'crm.lead.update': {
    key: 'crm.lead.update',
    resourceType: 'crm.lead',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Update mutable fields on a lead.',
    requiredTrustedContext: ['customer_region', 'resource_version'],
  },
  'crm.lead.assign': {
    key: 'crm.lead.assign',
    resourceType: 'crm.lead',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Reassign lead ownership to another representative.',
    requiredTrustedContext: ['customer_region', 'resource_version', 'assigned_owner'],
  },
  'crm.note.create': {
    key: 'crm.note.create',
    resourceType: 'crm.note',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Append a note to a customer record.',
    requiredTrustedContext: ['customer_region'],
  },
  'crm.discount.apply': {
    key: 'crm.discount.apply',
    resourceType: 'crm.lead',
    effectClass: 'write',
    riskClass: 'protected',
    summary:
      'Apply a commercial discount. The worked example throughout prd.md §8.1: allow to ' +
      '1000 bps, manager approval to 2000 bps, deny above.',
    requiredTrustedContext: ['customer_region', 'resource_version', 'business_reason'],
  },
  'communication.email.send': {
    key: 'communication.email.send',
    resourceType: 'communication.thread',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Send an email to a customer contact.',
    requiredTrustedContext: ['customer_region', 'business_reason'],
  },
  'calendar.availability.read': {
    key: 'calendar.availability.read',
    resourceType: 'calendar.calendar',
    effectClass: 'read',
    riskClass: 'routine',
    summary: 'Read free/busy availability.',
    requiredTrustedContext: [],
  },
  'calendar.meeting.create': {
    key: 'calendar.meeting.create',
    resourceType: 'calendar.meeting',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Create a meeting and invite a customer contact.',
    requiredTrustedContext: ['customer_region'],
  },
  'support.ticket.read': {
    key: 'support.ticket.read',
    resourceType: 'support.ticket',
    effectClass: 'read',
    riskClass: 'routine',
    summary: 'Read a support ticket and its history.',
    requiredTrustedContext: [],
  },
  'support.ticket.update': {
    key: 'support.ticket.update',
    resourceType: 'support.ticket',
    effectClass: 'write',
    riskClass: 'protected',
    summary: 'Update ticket status, priority or assignment.',
    requiredTrustedContext: ['resource_version'],
  },
} as const;

/** Narrow an untrusted string from the wire. Never cast; unknown keys must not authorize. */
export function isActionKey(value: unknown): value is ActionKey {
  return typeof value === 'string' && (ACTION_KEYS as readonly string[]).includes(value);
}

export function getAction(key: ActionKey): ActionDefinition {
  return ACTION_CATALOG[key];
}
