import { createHash } from 'node:crypto';
import { isActionKey, type ActionKey } from '@trustos/contracts';
import {
  FIELD_NAMESPACES,
  LIMITS,
  type Condition,
  type Literal,
  type PolicyBundleSource,
  type Rule,
} from './types.js';

/**
 * The compiler (architecture.md §7.1, §7.3).
 *
 * Everything checkable is checked HERE, at publication, not on the decision path. A
 * policy that would behave surprisingly at runtime should instead fail to publish,
 * where a human is present to read the error. POL-04 and POL-07.
 *
 * Hashing is deterministic over canonical JSON: the same source always yields the same
 * digest, which is what a reviewer signs off on (SEC-01) and what binds a decision to
 * the exact rules that produced it.
 */

export class PolicyCompilationError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly ruleId?: string,
  ) {
    super(ruleId ? `${message} (rule ${ruleId})` : message);
    this.name = 'PolicyCompilationError';
  }
}

export interface CompiledBundle {
  readonly rules: readonly Rule[];
  readonly rulesByAction: ReadonlyMap<ActionKey, readonly Rule[]>;
  /**
   * Every field any rule reads. The decision path asserts the REQUIRED ones are
   * present before evaluating, so a missing attribute cannot quietly stop a
   * restrictive rule from matching (POL-05).
   */
  readonly requiredFields: readonly string[];
  readonly hash: string;
  readonly evaluatorVersion: string;
}

/** Bump when evaluation semantics change. Recorded with every decision so a replay
 *  can tell "the rules changed" from "the evaluator changed". */
export const EVALUATOR_VERSION = '1.0.0';

const RULE_ID = /^[a-z][a-z0-9_]{1,62}$/;
const GROUP_KEY = /^[a-z][a-z0-9_]{1,62}$/;
const FIELD_SEGMENT = /^[a-z][a-z0-9_]{0,62}$/;

function fail(code: string, message: string, ruleId?: string): never {
  throw new PolicyCompilationError(code, message, ruleId);
}

/** Stable key ordering, so two structurally identical bundles hash identically. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((k) => [k, canonicalize((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

function validateFieldPath(path: string, ruleId: string): void {
  const segments = path.split('.');
  if (segments.length < 2) {
    fail('INVALID_FIELD', `field "${path}" must be namespaced, e.g. parameters.amount`, ruleId);
  }
  if (segments.length > LIMITS.maxFieldPathSegments) {
    fail(
      'FIELD_TOO_DEEP',
      `field "${path}" exceeds ${LIMITS.maxFieldPathSegments} segments`,
      ruleId,
    );
  }
  const [namespace, ...rest] = segments;
  if (!(FIELD_NAMESPACES as readonly string[]).includes(namespace!)) {
    // An unlisted namespace would let a policy read something whose provenance was
    // never classified (§5.3).
    fail(
      'UNKNOWN_NAMESPACE',
      `field "${path}" uses unknown namespace "${namespace}"; allowed: ${FIELD_NAMESPACES.join(', ')}`,
      ruleId,
    );
  }
  for (const segment of rest) {
    if (!FIELD_SEGMENT.test(segment)) {
      fail('INVALID_FIELD', `field "${path}" has invalid segment "${segment}"`, ruleId);
    }
  }
}

function validateLiteral(value: unknown, ruleId: string, path: string): asserts value is Literal {
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value as number)) {
      fail('INVALID_LITERAL', `non-finite number at ${path}`, ruleId);
    }
    // INVARIANT 10: thresholds are integers (basis points, minor units). A float
    // threshold invites the comparison bugs the branded types exist to prevent.
    if (!Number.isInteger(value as number)) {
      fail(
        'NON_INTEGER_LITERAL',
        `threshold at ${path} must be an integer, got ${String(value)}`,
        ruleId,
      );
    }
    return;
  }
  if (t === 'string') {
    if ((value as string).length > LIMITS.maxStringLiteralLength) {
      fail(
        'LITERAL_TOO_LONG',
        `string literal at ${path} exceeds ${LIMITS.maxStringLiteralLength}`,
        ruleId,
      );
    }
    return;
  }
  if (t === 'boolean') return;
  fail('INVALID_LITERAL', `literal at ${path} must be string, integer or boolean`, ruleId);
}

interface WalkState {
  conditions: number;
  fields: Set<string>;
}

function walkCondition(
  condition: Condition,
  ruleId: string,
  depth: number,
  state: WalkState,
): void {
  if (depth > LIMITS.maxConditionDepth) {
    fail(
      'CONDITION_TOO_DEEP',
      `condition nesting exceeds depth ${LIMITS.maxConditionDepth}`,
      ruleId,
    );
  }
  if (condition === null || typeof condition !== 'object') {
    fail('INVALID_CONDITION', 'condition must be an object', ruleId);
  }

  if ('all' in condition || 'any' in condition) {
    const branch = 'all' in condition ? condition.all : condition.any;
    if (!Array.isArray(branch) || branch.length === 0) {
      // An empty all[] is vacuously true and an empty any[] vacuously false. Both are
      // almost certainly a mistake, and both are dangerous in a permission document.
      fail(
        'EMPTY_BRANCH',
        `"${'all' in condition ? 'all' : 'any'}" must be a non-empty array`,
        ruleId,
      );
    }
    for (const c of branch) walkCondition(c, ruleId, depth + 1, state);
    return;
  }
  if ('not' in condition) {
    walkCondition(condition.not, ruleId, depth + 1, state);
    return;
  }

  state.conditions += 1;
  if (!('field' in condition) || typeof condition.field !== 'string') {
    fail('INVALID_CONDITION', 'leaf condition needs a string "field"', ruleId);
  }
  validateFieldPath(condition.field, ruleId);
  state.fields.add(condition.field);

  const op = (condition as { op?: unknown }).op;
  if (op === 'exists' || op === 'not_exists') return;

  if (op === 'in' || op === 'not_in') {
    const set = (condition as { value?: unknown }).value;
    if (!Array.isArray(set) || set.length === 0) {
      fail('INVALID_SET', `"${op}" needs a non-empty array`, ruleId);
    }
    if (set.length > LIMITS.maxSetSize) {
      fail('SET_TOO_LARGE', `set exceeds ${LIMITS.maxSetSize} members`, ruleId);
    }
    for (const v of set) validateLiteral(v, ruleId, condition.field);
    return;
  }

  if (!['eq', 'ne', 'gt', 'gte', 'lt', 'lte'].includes(op as string)) {
    fail('UNKNOWN_OPERATOR', `unknown operator "${String(op)}"`, ruleId);
  }
  validateLiteral((condition as { value?: unknown }).value, ruleId, condition.field);
}

function validateRule(rule: Rule, state: WalkState): void {
  if (rule.schema_version !== '1') {
    fail('UNSUPPORTED_SCHEMA', `unsupported schema_version ${String(rule.schema_version)}`);
  }
  if (typeof rule.rule_id !== 'string' || !RULE_ID.test(rule.rule_id)) {
    fail('INVALID_RULE_ID', `invalid rule_id ${JSON.stringify(rule.rule_id)}`);
  }
  // POL-01: an action outside the catalog cannot authorize, so it cannot be written
  // about either. Catches typos such as crm.discount.approve at publication.
  if (!isActionKey(rule.action)) {
    fail('UNKNOWN_ACTION', `action "${String(rule.action)}" is not in the catalog`, rule.rule_id);
  }
  if (!['allow', 'deny', 'approval_required'].includes(rule.effect)) {
    fail('INVALID_EFFECT', `invalid effect "${String(rule.effect)}"`, rule.rule_id);
  }

  // POL-06.
  if (rule.effect === 'approval_required') {
    if (!rule.approval)
      fail('MISSING_APPROVAL_ROUTE', 'approval_required needs an approval route', rule.rule_id);
    if (!GROUP_KEY.test(rule.approval.group_key)) {
      fail('INVALID_GROUP_KEY', `invalid group_key "${rule.approval.group_key}"`, rule.rule_id);
    }
    const t = rule.approval.timeout_seconds;
    if (!Number.isInteger(t) || t <= 0 || t > 86_400) {
      fail(
        'INVALID_TIMEOUT',
        `timeout_seconds must be an integer in 1..86400, got ${String(t)}`,
        rule.rule_id,
      );
    }
  } else if (rule.approval) {
    // An approval route on an allow rule reads as if approval were required. It is not.
    fail(
      'UNEXPECTED_APPROVAL_ROUTE',
      `effect "${rule.effect}" must not carry an approval route`,
      rule.rule_id,
    );
  }

  if (rule.obligations) {
    for (const o of rule.obligations) {
      if (typeof o !== 'string' || o.length === 0 || o.length > 64) {
        fail('INVALID_OBLIGATION', `invalid obligation ${JSON.stringify(o)}`, rule.rule_id);
      }
    }
  }

  if (rule.when !== undefined) walkCondition(rule.when, rule.rule_id, 1, state);
}

export function compile(source: PolicyBundleSource): CompiledBundle {
  if (source === null || typeof source !== 'object')
    fail('INVALID_BUNDLE', 'bundle must be an object');
  if (source.schema_version !== '1') {
    fail(
      'UNSUPPORTED_SCHEMA',
      `unsupported bundle schema_version ${String(source.schema_version)}`,
    );
  }
  if (!Array.isArray(source.rules)) fail('INVALID_BUNDLE', 'bundle needs a rules array');
  if (source.rules.length > LIMITS.maxRulesPerBundle) {
    fail('TOO_MANY_RULES', `bundle exceeds ${LIMITS.maxRulesPerBundle} rules`);
  }

  const state: WalkState = { conditions: 0, fields: new Set() };
  const seen = new Set<string>();

  for (const rule of source.rules) {
    if (seen.has(rule.rule_id)) {
      // Duplicate ids make reason codes ambiguous and a reviewer's job impossible.
      fail('DUPLICATE_RULE_ID', `duplicate rule_id "${rule.rule_id}"`);
    }
    seen.add(rule.rule_id);
    validateRule(rule, state);
  }

  if (state.conditions > LIMITS.conditionsPerBundle) {
    fail(
      'TOO_MANY_CONDITIONS',
      `bundle has ${state.conditions} conditions, limit ${LIMITS.conditionsPerBundle}`,
    );
  }

  const rulesByAction = new Map<ActionKey, Rule[]>();
  for (const rule of source.rules) {
    const list = rulesByAction.get(rule.action) ?? [];
    list.push(rule);
    rulesByAction.set(rule.action, list);
  }
  for (const [action, rules] of rulesByAction) {
    if (rules.length > LIMITS.rulesPerAction) {
      fail(
        'TOO_MANY_RULES_FOR_ACTION',
        `action "${action}" has ${rules.length} rules, limit ${LIMITS.rulesPerAction}`,
      );
    }
    // POL-07: two approval routes for one action can both match, and picking one at
    // runtime would be arbitrary. Reject the publication instead.
    const groups = new Set(
      rules
        .filter((r) => r.effect === 'approval_required' && r.approval)
        .map((r) => r.approval!.group_key),
    );
    if (groups.size > 1) {
      fail(
        'CONFLICTING_APPROVAL_ROUTES',
        `action "${action}" routes approvals to multiple groups: ${[...groups].sort().join(', ')}`,
      );
    }
  }

  const hash = createHash('sha256')
    .update(JSON.stringify(canonicalize(source)))
    .digest('hex');

  return {
    rules: source.rules,
    rulesByAction,
    requiredFields: [...state.fields].sort(),
    hash: `sha256:${hash}`,
    evaluatorVersion: EVALUATOR_VERSION,
  };
}
