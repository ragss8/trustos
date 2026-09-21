import { describe, expect, it } from 'vitest';
import { compile, PolicyCompilationError } from './compile.js';
import { evaluate, PolicyEvaluationError, resolveField } from './evaluate.js';
import type { EvaluationInput, PolicyBundleSource, Rule } from './types.js';

/** The worked example from prd.md §8.1, as a real bundle. */
const DISCOUNT_BUNDLE: PolicyBundleSource = {
  schema_version: '1',
  rules: [
    {
      schema_version: '1',
      rule_id: 'region_must_be_assigned',
      action: 'crm.discount.apply',
      effect: 'deny',
      when: { not: { field: 'context.customer_region', op: 'in', value: ['KA', 'MH', 'TN'] } },
    },
    {
      schema_version: '1',
      rule_id: 'discount_above_ceiling',
      action: 'crm.discount.apply',
      effect: 'deny',
      when: { field: 'parameters.discount_basis_points', op: 'gt', value: 2000 },
    },
    {
      schema_version: '1',
      rule_id: 'discount_manager_approval',
      action: 'crm.discount.apply',
      effect: 'approval_required',
      when: {
        all: [
          { field: 'parameters.discount_basis_points', op: 'gt', value: 1000 },
          { field: 'parameters.discount_basis_points', op: 'lte', value: 2000 },
        ],
      },
      approval: { group_key: 'regional_sales_manager', timeout_seconds: 600 },
      obligations: ['business_reason_required', 'execution_report_required'],
    },
    {
      schema_version: '1',
      rule_id: 'discount_within_authority',
      action: 'crm.discount.apply',
      effect: 'allow',
      when: { field: 'parameters.discount_basis_points', op: 'lte', value: 1000 },
      obligations: ['execution_report_required'],
    },
  ],
};

const compiled = compile(DISCOUNT_BUNDLE);

function request(bps: number, region = 'KA'): EvaluationInput {
  return {
    action: 'crm.discount.apply',
    parameters: { discount_basis_points: bps },
    resource: { type: 'crm.lead', id: 'lead_1', version: '17' },
    context: { customer_region: region, business_reason: 'campaign exception' },
    principal: { id: 'agent_1' },
    time: { now: '2026-09-21T08:00:00Z' },
  };
}

describe('the discount example (prd.md §8.1)', () => {
  it.each([
    [0, 'allow'],
    [500, 'allow'],
    [1000, 'allow'],
    [1001, 'approval_required'],
    [1500, 'approval_required'],
    [2000, 'approval_required'],
    [2001, 'deny'],
    [2500, 'deny'],
    [10000, 'deny'],
  ])('%i basis points -> %s', (bps, effect) => {
    expect(evaluate(compiled, request(bps)).effect).toBe(effect);
  });

  it('denies an unassigned region regardless of how small the discount is', () => {
    // prd.md §18: "deny even if an approver is available".
    const r = evaluate(compiled, request(100, 'ZZ'));
    expect(r.effect).toBe('deny');
    expect(r.reasonCodes).toContain('region_must_be_assigned');
  });

  it('denies an unassigned region even in the approval band', () => {
    const r = evaluate(compiled, request(1500, 'ZZ'));
    expect(r.effect).toBe('deny');
    expect(r.approval).toBeUndefined();
  });

  it('routes an approval with its group and timeout', () => {
    const r = evaluate(compiled, request(1500));
    expect(r.approval).toEqual({ group_key: 'regional_sales_manager', timeout_seconds: 600 });
    expect(r.obligations).toEqual(['business_reason_required', 'execution_report_required']);
  });

  it('denies an action the bundle says nothing about', () => {
    const r = evaluate(compiled, { ...request(100), action: 'crm.lead.update' });
    expect(r.effect).toBe('deny');
    expect(r.reasonCodes).toEqual(['NO_MATCHING_RULE']);
  });
});

describe('precedence (§7.2, POL-05)', () => {
  const conflicting = compile({
    schema_version: '1',
    rules: [
      { schema_version: '1', rule_id: 'always_allow', action: 'crm.note.create', effect: 'allow' },
      { schema_version: '1', rule_id: 'always_deny', action: 'crm.note.create', effect: 'deny' },
      {
        schema_version: '1',
        rule_id: 'always_escalate',
        action: 'crm.note.create',
        effect: 'approval_required',
        approval: { group_key: 'managers', timeout_seconds: 300 },
      },
    ],
  });

  const input: EvaluationInput = {
    action: 'crm.note.create',
    parameters: {},
    resource: {},
    context: {},
    principal: {},
    time: {},
  };

  it('lets an explicit deny beat both allow and approval_required', () => {
    const r = evaluate(conflicting, input);
    expect(r.effect).toBe('deny');
    // An allow rule matched too. It must not appear as justification.
    expect(r.reasonCodes).toEqual(['always_deny']);
  });

  it('lets approval_required beat allow when no deny matches', () => {
    const noDeny = compile({
      schema_version: '1',
      rules: conflicting.rules.filter((r) => r.effect !== 'deny') as Rule[],
    });
    expect(evaluate(noDeny, input).effect).toBe('approval_required');
  });

  it('denies by default when the bundle is empty', () => {
    const empty = compile({ schema_version: '1', rules: [] });
    expect(evaluate(empty, input).effect).toBe('deny');
  });
});

describe('type strictness', () => {
  it('does not let a numeric string satisfy a numeric threshold', () => {
    // The request schema should have rejected this upstream. If it ever does not,
    // the evaluator must fail closed rather than coerce.
    expect(() =>
      evaluate(compiled, {
        ...request(0),
        parameters: { discount_basis_points: '1500' },
      }),
    ).toThrow(PolicyEvaluationError);
  });

  it('refuses to order-compare a boolean', () => {
    expect(() =>
      evaluate(compiled, { ...request(0), parameters: { discount_basis_points: true } }),
    ).toThrow(PolicyEvaluationError);
  });

  it('treats a missing parameter as no-match, not as zero', () => {
    // Falls through every rule to the default deny. It must not land in 'allow' by
    // being treated as 0 <= 1000.
    const r = evaluate(compiled, { ...request(0), parameters: {} });
    expect(r.effect).toBe('deny');
  });

  it('does not let a missing field satisfy a "ne" condition', () => {
    const b = compile({
      schema_version: '1',
      rules: [
        {
          schema_version: '1',
          rule_id: 'allow_when_not_blocked',
          action: 'crm.note.create',
          effect: 'allow',
          when: { field: 'context.status', op: 'ne', value: 'blocked' },
        },
      ],
    });
    const r = evaluate(b, {
      action: 'crm.note.create',
      parameters: {},
      resource: {},
      context: {},
      principal: {},
      time: {},
    });
    expect(r.effect).toBe('deny');
  });
});

describe('field resolution safety', () => {
  const input = request(500);

  it.each(['parameters.__proto__', 'parameters.constructor', 'resource.prototype'])(
    'refuses to resolve %s',
    (path) => {
      expect(() => resolveField(input, path)).toThrow(PolicyEvaluationError);
    },
  );

  it('rejects such a path at compile time too', () => {
    expect(() =>
      compile({
        schema_version: '1',
        rules: [
          {
            schema_version: '1',
            rule_id: 'sneaky',
            action: 'crm.note.create',
            effect: 'allow',
            when: { field: 'parameters.__proto__', op: 'exists' },
          },
        ],
      }),
    ).toThrow(PolicyCompilationError);
  });

  it('does not read inherited properties', () => {
    const polluted = Object.create({ inherited: 'from prototype' }) as Record<string, string>;
    polluted['own'] = 'value';
    const r = resolveField({ ...input, context: polluted }, 'context.inherited');
    expect(r).not.toBe('from prototype');
  });

  it('returns missing for an unreachable nested path', () => {
    expect(resolveField(input, 'parameters.nope.deeper')).not.toBe('value');
  });
});

describe('determinism (§7.2)', () => {
  it('produces identical results across repeated evaluation', () => {
    const first = evaluate(compiled, request(1500));
    for (let i = 0; i < 50; i += 1) {
      expect(evaluate(compiled, request(1500))).toEqual(first);
    }
  });

  it('is unaffected by key insertion order in the input', () => {
    const a: EvaluationInput = {
      action: 'crm.discount.apply',
      parameters: { discount_basis_points: 1500 },
      resource: {},
      context: { customer_region: 'KA', business_reason: 'x' },
      principal: {},
      time: {},
    };
    const b: EvaluationInput = {
      time: {},
      principal: {},
      context: { business_reason: 'x', customer_region: 'KA' },
      resource: {},
      parameters: { discount_basis_points: 1500 },
      action: 'crm.discount.apply',
    };
    expect(evaluate(compiled, a)).toEqual(evaluate(compiled, b));
  });

  it('hashes the same source identically regardless of key order', () => {
    const reordered: PolicyBundleSource = {
      rules: DISCOUNT_BUNDLE.rules,
      schema_version: '1',
    };
    expect(compile(reordered).hash).toBe(compiled.hash);
  });

  it('changes the hash when any rule changes', () => {
    // Raising the ceiling from 2000 to 3000 is exactly the kind of edit a reviewer
    // signed off against a hash (SEC-01). It must not hash the same.
    const altered: PolicyBundleSource = {
      schema_version: '1',
      rules: DISCOUNT_BUNDLE.rules.map((r) =>
        r.rule_id === 'discount_above_ceiling'
          ? { ...r, when: { field: 'parameters.discount_basis_points', op: 'gt', value: 3000 } }
          : r,
      ),
    };
    expect(compile(altered).hash).not.toBe(compiled.hash);
  });

  it('reports the evaluator version, so a replay can tell rules from semantics', () => {
    expect(compiled.evaluatorVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('compiler rejections', () => {
  const rule = (over: Partial<Rule>): PolicyBundleSource => ({
    schema_version: '1',
    rules: [
      {
        schema_version: '1',
        rule_id: 'r1',
        action: 'crm.note.create',
        effect: 'allow',
        ...over,
      } as Rule,
    ],
  });

  it('rejects an action outside the catalog', () => {
    // POL-01. Catches a plausible typo such as crm.discount.approve.
    expect(() => compile(rule({ action: 'crm.discount.approve' as never }))).toThrow(
      /not in the catalog/,
    );
  });

  it('rejects an unknown field namespace', () => {
    expect(() => compile(rule({ when: { field: 'secrets.api_key', op: 'exists' } }))).toThrow(
      /unknown namespace/,
    );
  });

  it('rejects a non-integer threshold', () => {
    // INVARIANT 10: a float threshold reintroduces the comparison bugs branded
    // integer types exist to prevent.
    expect(() =>
      compile(rule({ when: { field: 'parameters.amount', op: 'gt', value: 10.5 } })),
    ).toThrow(/must be an integer/);
  });

  it('rejects approval_required with no route (POL-06)', () => {
    expect(() => compile(rule({ effect: 'approval_required' }))).toThrow(/needs an approval route/);
  });

  it('rejects an approval route on an allow rule', () => {
    expect(() =>
      compile(rule({ effect: 'allow', approval: { group_key: 'g', timeout_seconds: 60 } })),
    ).toThrow(/must not carry an approval route/);
  });

  it('rejects conflicting approval routes for one action (POL-07)', () => {
    expect(() =>
      compile({
        schema_version: '1',
        rules: [
          {
            schema_version: '1',
            rule_id: 'route_a',
            action: 'crm.note.create',
            effect: 'approval_required',
            approval: { group_key: 'managers', timeout_seconds: 300 },
          },
          {
            schema_version: '1',
            rule_id: 'route_b',
            action: 'crm.note.create',
            effect: 'approval_required',
            approval: { group_key: 'directors', timeout_seconds: 300 },
          },
        ],
      }),
    ).toThrow(/multiple groups/);
  });

  it('rejects duplicate rule ids', () => {
    expect(() =>
      compile({ schema_version: '1', rules: [rule({}).rules[0]!, rule({}).rules[0]!] }),
    ).toThrow(/duplicate rule_id/);
  });

  it('rejects an empty all[] branch', () => {
    // Vacuously true, and in a permission document that is dangerous.
    expect(() => compile(rule({ when: { all: [] } }))).toThrow(/non-empty/);
  });

  it('rejects nesting beyond the depth limit', () => {
    let nested: unknown = { field: 'parameters.a', op: 'exists' };
    for (let i = 0; i < 12; i += 1) nested = { not: nested };
    expect(() => compile(rule({ when: nested as never }))).toThrow(/depth/);
  });

  it('rejects an oversized membership set', () => {
    const big = Array.from({ length: 100 }, (_, i) => `v${i}`);
    expect(() =>
      compile(rule({ when: { field: 'context.region', op: 'in', value: big } })),
    ).toThrow(/exceeds/);
  });

  it('rejects more rules for one action than the limit allows', () => {
    const many = Array.from({ length: 11 }, (_, i) => ({
      schema_version: '1' as const,
      rule_id: `r${i}`,
      action: 'crm.note.create' as const,
      effect: 'allow' as const,
    }));
    expect(() => compile({ schema_version: '1', rules: many })).toThrow(/limit 10/);
  });

  it('collects the fields a bundle reads, for pre-evaluation presence checks', () => {
    expect(compiled.requiredFields).toEqual([
      'context.customer_region',
      'parameters.discount_basis_points',
    ]);
  });
});
