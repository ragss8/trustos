import type { ActionKey } from '@trustos/contracts';

/**
 * The restricted policy DSL (architecture.md §7.1).
 *
 * What it deliberately cannot express, and why:
 *
 *   no arbitrary regex   ReDoS on the decision path (§7.1)
 *   no JS evaluation     arbitrary code in a document an admin can publish
 *   no network or IO     determinism: replay must reproduce the original decision
 *   no clock access      server time is normalized INTO the input by the caller
 *   no arithmetic        a policy that computes cannot be reasoned about by a reviewer
 *
 * This is a small language on purpose. Everything it can say, a reviewer can check
 * against the exact hash they signed off on (SEC-01).
 */

export type Effect = 'allow' | 'deny' | 'approval_required';

/** Literals are scalars only. No objects, no arrays-of-arrays, no nesting. */
export type Literal = string | number | boolean;

export type ComparisonOp = 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte';
export type MembershipOp = 'in' | 'not_in';
export type ExistenceOp = 'exists' | 'not_exists';

export interface ComparisonCondition {
  readonly field: string;
  readonly op: ComparisonOp;
  readonly value: Literal;
}

export interface MembershipCondition {
  readonly field: string;
  readonly op: MembershipOp;
  readonly value: readonly Literal[];
}

/**
 * Explicit, because "missing" and "false" are different and conflating them is how a
 * restrictive rule gets skipped (POL-05).
 */
export interface ExistenceCondition {
  readonly field: string;
  readonly op: ExistenceOp;
}

export interface AllCondition {
  readonly all: readonly Condition[];
}
export interface AnyCondition {
  readonly any: readonly Condition[];
}
export interface NotCondition {
  readonly not: Condition;
}

export type Condition =
  | ComparisonCondition
  | MembershipCondition
  | ExistenceCondition
  | AllCondition
  | AnyCondition
  | NotCondition;

export interface ApprovalRoute {
  readonly group_key: string;
  readonly timeout_seconds: number;
}

export interface Rule {
  readonly schema_version: '1';
  readonly rule_id: string;
  readonly action: ActionKey;
  readonly effect: Effect;
  /** Absent means the rule matches any request for its action. */
  readonly when?: Condition;
  /** Required for approval_required, forbidden otherwise (POL-06). */
  readonly approval?: ApprovalRoute;
  readonly obligations?: readonly string[];
}

export interface PolicyBundleSource {
  readonly schema_version: '1';
  readonly rules: readonly Rule[];
}

/**
 * Field namespaces a rule may read. An unlisted prefix fails compilation, so a policy
 * cannot reach into the raw request or into anything the agent controls but has not
 * been classified (architecture.md §5.3).
 */
export const FIELD_NAMESPACES = ['parameters', 'resource', 'context', 'principal', 'time'] as const;
export type FieldNamespace = (typeof FIELD_NAMESPACES)[number];

/**
 * Limits from architecture.md §7.1. Exceeding one rejects the DRAFT, so an oversized
 * policy is a publication-time error rather than a latency surprise on the decision path.
 */
export const LIMITS = {
  rulesPerAction: 10,
  conditionsPerBundle: 100,
  maxConditionDepth: 8,
  maxSetSize: 64,
  maxRulesPerBundle: 200,
  maxFieldPathSegments: 4,
  maxStringLiteralLength: 256,
} as const;

/** The normalized evaluation input (§7.2). Everything non-deterministic is resolved
 *  by the CALLER and passed in here, which is what makes replay reproducible. */
export interface EvaluationInput {
  readonly action: ActionKey;
  readonly parameters: Readonly<Record<string, Literal>>;
  readonly resource: Readonly<Record<string, Literal>>;
  /** Trusted attributes only. Agent free-text never reaches the evaluator as context. */
  readonly context: Readonly<Record<string, Literal>>;
  readonly principal: Readonly<Record<string, Literal>>;
  /** Normalized server time, derived outside the evaluator. */
  readonly time: Readonly<Record<string, Literal>>;
}

export interface MatchedRule {
  readonly ruleId: string;
  readonly effect: Effect;
}

export interface EvaluationResult {
  readonly effect: Effect;
  readonly reasonCodes: readonly string[];
  readonly matchedRules: readonly MatchedRule[];
  readonly obligations: readonly string[];
  readonly approval: ApprovalRoute | undefined;
}
