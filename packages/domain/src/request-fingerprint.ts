import { createHash } from 'node:crypto';
import type { ActionKey } from '@trustos/contracts';
import type { JsonValue } from './strict-json.js';

/**
 * The canonical request fingerprint (architecture.md §8.1 step 2).
 *
 * This digest is what a grant is bound to. If it is not stable, a gateway can consume
 * a grant for a request other than the one that was authorized; if it covers too
 * much, an irrelevant retry detail invalidates a legitimate retry.
 *
 * Included: agent, action, resource identity and version, parameters, business
 * deadline, trusted context with its provenance, and gateway audience.
 *
 * Excluded on purpose: transport trace ids (X-Request-ID), timestamps of the call
 * itself, and anything else that legitimately differs between a request and its
 * identical retry. Including them would break idempotent retry (AUT-02).
 */

export interface FingerprintInput {
  readonly agentId: string;
  readonly action: ActionKey;
  readonly resource: {
    readonly type: string;
    readonly id: string;
    /** Absent and null mean different things and must hash differently. */
    readonly version?: string | null;
  };
  readonly parameters: Readonly<Record<string, JsonValue>>;
  readonly trustedContext: Readonly<Record<string, JsonValue>>;
  readonly gatewayAudience: string;
  readonly businessDeadline?: string | null;
  readonly environmentId: string;
  readonly tenantId: string;
}

const ABSENT = '\u0000absent';
const NULL = '\u0000null';

/**
 * Canonical form. Sorted keys, and absent distinguished from null by distinct
 * sentinels rather than both collapsing to "missing" — otherwise
 * {"version": null} and {} would produce the same grant binding.
 */
function canonical(value: JsonValue | undefined): unknown {
  if (value === undefined) return ABSENT;
  if (value === null) return NULL;
  if (Array.isArray(value)) return ['a', value.map((v) => canonical(v))];
  if (typeof value === 'object') {
    return [
      'o',
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k])]),
    ];
  }
  // Every scalar carries its type tag. Without one, the number 1500 and the string
  // "1500" serialize identically, and a string parameter fingerprints the same as
  // the numeric threshold it was never allowed to satisfy.
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite number in fingerprint input');
    // -0 and 0 are the same amount and must not differ.
    return ['n', Object.is(value, -0) ? '0' : String(value)];
  }
  if (typeof value === 'boolean') return ['b', value];
  return ['s', value];
}

/** `null ?? undefined` is `undefined`, which would collapse an explicit null into
 *  "absent". They must hash differently, so the check is explicit. */
function optional(value: JsonValue | undefined): unknown {
  return value === undefined ? ABSENT : canonical(value);
}

/** Tagged so a string "1" and a number 1 cannot collide, and so the field order is
 *  fixed by this function rather than by the caller's object literal. */
export function computeRequestFingerprint(input: FingerprintInput): string {
  const shape: unknown[] = [
    ['v', 1],
    ['tenant', input.tenantId],
    ['environment', input.environmentId],
    ['agent', input.agentId],
    ['action', input.action],
    ['resource.type', input.resource.type],
    ['resource.id', input.resource.id],
    ['resource.version', optional(input.resource.version)],
    ['parameters', canonical(input.parameters)],
    ['context', canonical(input.trustedContext)],
    ['gateway', input.gatewayAudience],
    ['deadline', optional(input.businessDeadline)],
  ];
  const digest = createHash('sha256').update(JSON.stringify(shape), 'utf8').digest('hex');
  return `sha256:${digest}`;
}

/**
 * Idempotency key digest. Scoped per caller and route by the database unique
 * constraint, so the raw key never needs storing and two tenants cannot collide.
 */
export function computeIdempotencyKeyHash(key: string): string {
  return `sha256:${createHash('sha256').update(key, 'utf8').digest('hex')}`;
}
