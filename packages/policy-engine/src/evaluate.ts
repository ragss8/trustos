import type {
  ApprovalRoute,
  Condition,
  EvaluationInput,
  EvaluationResult,
  Literal,
  MatchedRule,
  Rule,
} from './types.js';
import type { CompiledBundle } from './compile.js';

/**
 * The evaluator (architecture.md §7.2).
 *
 * A pure function of (compiled bundle, normalized input). No clock, no randomness, no
 * IO — enforced by lint and dependency rules, not convention — so replaying an old
 * decision against its recorded bundle reproduces the original effect exactly.
 */

export class PolicyEvaluationError extends Error {
  constructor(
    readonly code: 'TYPE_MISMATCH' | 'UNRESOLVABLE_FIELD',
    message: string,
  ) {
    super(message);
    this.name = 'PolicyEvaluationError';
  }
}

/** Blocked at every path segment: these reach the prototype chain, not own data. */
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

const MISSING = Symbol('missing');
type Resolved = Literal | typeof MISSING;

/**
 * Own-property lookup only. `parameters.__proto__.polluted` must resolve to missing,
 * not to something inherited, and a compiled policy must never be able to read the
 * prototype chain.
 */
export function resolveField(input: EvaluationInput, path: string): Resolved {
  const segments = path.split('.');
  let current: unknown = input;

  for (const segment of segments) {
    if (FORBIDDEN_SEGMENTS.has(segment)) {
      throw new PolicyEvaluationError('UNRESOLVABLE_FIELD', `forbidden path segment: ${segment}`);
    }
    if (typeof current !== 'object' || current === null) return MISSING;
    if (!Object.hasOwn(current, segment)) return MISSING;
    current = (current as Record<string, unknown>)[segment];
  }

  if (current === undefined || current === null) return MISSING;
  const t = typeof current;
  if (t !== 'string' && t !== 'number' && t !== 'boolean') return MISSING;
  return current as Literal;
}

function compareOrdered(left: Literal, right: Literal, path: string): number {
  // Ordered comparison across types has no defined meaning. Returning "no match" would
  // let a malformed value slip past a deny rule, so this fails closed instead: the
  // caller turns it into an error response, never an allow.
  if (typeof left !== typeof right) {
    throw new PolicyEvaluationError(
      'TYPE_MISMATCH',
      `cannot order-compare ${typeof left} with ${typeof right} at ${path}`,
    );
  }
  if (typeof left === 'boolean') {
    throw new PolicyEvaluationError('TYPE_MISMATCH', `booleans are not ordered at ${path}`);
  }
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function evaluateCondition(condition: Condition, input: EvaluationInput): boolean {
  if ('all' in condition) return condition.all.every((c) => evaluateCondition(c, input));
  if ('any' in condition) return condition.any.some((c) => evaluateCondition(c, input));
  if ('not' in condition) return !evaluateCondition(condition.not, input);

  const value = resolveField(input, condition.field);

  // One switch so the compiler narrows the union exhaustively. The earlier
  // if-chain type-checked only by accident and would have silently stopped
  // narrowing if another operator were added.
  switch (condition.op) {
    case 'exists':
      return value !== MISSING;
    case 'not_exists':
      return value === MISSING;

    case 'in':
    case 'not_in': {
      // A missing field matches nothing. Presence of REQUIRED fields is enforced
      // before evaluation via CompiledBundle.requiredFields, so this is not how a
      // required attribute goes unchecked.
      if (value === MISSING) return false;
      const present = condition.value.some((v) => v === value);
      return condition.op === 'in' ? present : !present;
    }

    // Strict: no coercion. 15 and "15" are different values, and treating them as
    // equal is how a string parameter satisfies a numeric threshold.
    case 'eq':
      return value !== MISSING && value === condition.value;
    case 'ne':
      // A missing field is not "not equal to 5"; it is unknown. Returning true here
      // would let an absent attribute satisfy a negative condition.
      return value !== MISSING && value !== condition.value;

    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      if (value === MISSING) return false;
      const order = compareOrdered(value, condition.value, condition.field);
      if (condition.op === 'gt') return order > 0;
      if (condition.op === 'gte') return order >= 0;
      if (condition.op === 'lt') return order < 0;
      return order <= 0;
    }
  }
}

function matches(rule: Rule, input: EvaluationInput): boolean {
  if (rule.action !== input.action) return false;
  return rule.when === undefined || evaluateCondition(rule.when, input);
}

/** Union, deduplicated, sorted. Sorted because the result is hashed into evidence:
 *  two identical decisions must not differ by obligation ordering. */
function mergeObligations(rules: readonly Rule[]): string[] {
  return [...new Set(rules.flatMap((r) => r.obligations ?? []))].sort();
}

export function evaluate(bundle: CompiledBundle, input: EvaluationInput): EvaluationResult {
  const applicable = bundle.rulesByAction.get(input.action) ?? [];

  // Precedence is fixed (§7.2): explicit deny, then approval_required, then allow,
  // then default deny. Evaluated in that order so a later allow can never override an
  // earlier deny (POL-05).
  const denied = applicable.filter((r) => r.effect === 'deny' && matches(r, input));
  if (denied.length > 0) {
    return {
      effect: 'deny',
      reasonCodes: denied.map((r) => r.rule_id).sort(),
      matchedRules: denied.map(toMatched),
      obligations: [],
      approval: undefined,
    };
  }

  const escalated = applicable.filter((r) => r.effect === 'approval_required' && matches(r, input));
  if (escalated.length > 0) {
    // POL-07: conflicting approval routes are rejected at PUBLICATION. Reaching two
    // distinct routes at runtime means the compiler let something through, so fail
    // closed rather than silently picking one.
    const routes = new Map<string, ApprovalRoute>();
    for (const r of escalated) if (r.approval) routes.set(r.approval.group_key, r.approval);
    if (routes.size > 1) {
      return {
        effect: 'deny',
        reasonCodes: ['CONFLICTING_APPROVAL_ROUTES'],
        matchedRules: escalated.map(toMatched),
        obligations: [],
        approval: undefined,
      };
    }
    // Most restrictive timeout wins when several rules route to the same group.
    const [route] = [...routes.values()];
    const timeout = Math.min(...escalated.map((r) => r.approval?.timeout_seconds ?? Infinity));
    return {
      effect: 'approval_required',
      reasonCodes: escalated.map((r) => r.rule_id).sort(),
      matchedRules: escalated.map(toMatched),
      obligations: mergeObligations(escalated),
      approval: route ? { group_key: route.group_key, timeout_seconds: timeout } : undefined,
    };
  }

  const allowed = applicable.filter((r) => r.effect === 'allow' && matches(r, input));
  if (allowed.length > 0) {
    return {
      effect: 'allow',
      reasonCodes: allowed.map((r) => r.rule_id).sort(),
      matchedRules: allowed.map(toMatched),
      obligations: mergeObligations(allowed),
      approval: undefined,
    };
  }

  // Nothing permitted it. INVARIANT 1 and prd.md §3.3: deny by default.
  return {
    effect: 'deny',
    reasonCodes: ['NO_MATCHING_RULE'],
    matchedRules: [],
    obligations: [],
    approval: undefined,
  };
}

function toMatched(rule: Rule): MatchedRule {
  return { ruleId: rule.rule_id, effect: rule.effect };
}
