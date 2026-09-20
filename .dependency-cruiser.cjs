/**
 * Architectural boundaries for TrustOS.
 *
 * These rules encode invariants from CLAUDE.md and architecture.md §4. They are not
 * style preferences: each one, if violated, breaks a stated correctness or security
 * property. Run in CI before typecheck.
 */
module.exports = {
  forbidden: [
    {
      name: 'policy-engine-is-pure',
      comment:
        'INVARIANT 7. The evaluator must be deterministic: same bundle + same evaluator ' +
        'version + same normalized snapshot produces identical output. Any IO, clock or ' +
        'randomness destroys that. Identity and server time are derived OUTSIDE the ' +
        'evaluator and passed in (architecture.md §7.2).',
      severity: 'error',
      from: { path: '^packages/policy-engine' },
      to: {
        path: ['^packages/(database|auth|observability)', '^apps/', '^integrations/'],
      },
    },
    {
      name: 'policy-engine-no-io',
      comment: 'INVARIANT 7. No network, filesystem or subprocess access on the policy path.',
      severity: 'error',
      from: { path: '^packages/policy-engine' },
      to: {
        dependencyTypes: ['core'],
        path: '^(fs|fs/promises|net|http|https|dns|dgram|child_process|worker_threads|cluster|tls|http2|inspector|perf_hooks)$',
      },
    },
    {
      name: 'sdk-stays-public',
      comment:
        'The published SDK must not drag server internals into a customer build. It may ' +
        'depend on contracts and nothing else internal.',
      severity: 'error',
      from: { path: '^packages/sdk-typescript' },
      to: { path: '^(packages/(?!contracts|sdk-typescript)|apps/|integrations/)' },
    },
    {
      name: 'apps-do-not-couple',
      comment:
        'Control API, decision API and worker are separate entry points from shared ' +
        'packages (architecture.md §3). They must not call into each other directly, or ' +
        'independent deployment and rolling upgrade break.',
      severity: 'error',
      from: { path: '^apps/([^/]+)/' },
      to: { path: '^apps/([^/]+)/', pathNot: '^apps/$1/' },
    },
    {
      name: 'no-cross-package-internals',
      comment:
        'Import a package by its name, never by reaching into its src/ or dist/. One ' +
        'module owns writes to each table; that ownership is meaningless if callers can ' +
        'bypass the public interface (architecture.md §3.1).',
      severity: 'error',
      from: { pathNot: '^(packages|apps|integrations)/([^/]+)/' },
      to: { path: '^(packages|apps|integrations)/([^/]+)/(src|dist)/.+' },
    },
    {
      name: 'gateway-is-a-consumer',
      comment:
        'The reference gateway models a CUSTOMER trust domain (architecture.md §2). If it ' +
        'can import server internals it is no longer testing the real trust boundary.',
      severity: 'error',
      from: { path: '^integrations/reference-crm' },
      to: { path: '^(packages/(database|auth|domain|policy-engine)|apps/)' },
    },
    { name: 'no-circular', severity: 'error', from: {}, to: { circular: true } },
    {
      name: 'no-orphans',
      severity: 'warn',
      from: { orphan: true, pathNot: '\\.d\\.ts$|(^|/)index\\.ts$' },
      to: {},
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    // NOTE: 'dist' must NOT be excluded here. Workspace imports resolve to
    // packages/<name>/dist/index.js, so excluding dist silently drops every
    // cross-package edge and every boundary rule below passes vacuously.
    // Entry points are the src globs in the `boundaries` script; includeOnly keeps
    // the report to first-party code.
    exclude: { path: '(^|/)(coverage|node_modules)(/|$)' },
    includeOnly: { path: '^(apps|packages|integrations)/' },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.base.json' },
    enhancedResolveOptions: {
      exportsFields: ['exports'],
      conditionNames: ['import', 'require', 'node', 'default'],
    },
    reporterOptions: { text: { highlightFocused: true } },
  },
};
