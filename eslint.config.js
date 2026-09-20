// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/coverage/**', '**/node_modules/**', '**/generated/**', '**/*.cjs'],
  },

  eslint.configs.recommended,
  ...tseslint.configs.recommended,

  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-console': 'error', // INVARIANT 13: log through @trustos/observability, which redacts.
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
  },

  // INVARIANT 7 and architecture.md §7.2. The evaluator is a pure function of its
  // inputs. Time, randomness and identity are resolved by the caller and passed in as
  // part of the normalized snapshot, so replaying an old decision reproduces it exactly.
  {
    files: ['packages/policy-engine/**/*.ts'],
    ignores: ['packages/policy-engine/**/*.test.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        {
          name: 'Date',
          message:
            'Non-deterministic. Server time is normalized into the evaluation input by the caller.',
        },
        { name: 'fetch', message: 'No network on the policy path.' },
        { name: 'process', message: 'No ambient environment in the evaluator.' },
      ],
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message: 'Non-deterministic. The evaluator must replay identically.',
        },
        {
          object: 'Date',
          property: 'now',
          message: 'Non-deterministic. Pass normalized server time in the snapshot.',
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "NewExpression[callee.name='RegExp']",
          message: 'architecture.md §7.1 forbids arbitrary regex in the DSL (ReDoS surface).',
        },
        {
          selector: "NewExpression[callee.name='Date']",
          message: 'Non-deterministic. Pass normalized server time in the snapshot.',
        },
      ],
    },
  },

  // Tests need the freedom the production rules remove.
  {
    files: ['**/*.test.ts', '**/*.spec.ts', 'tests/**/*.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      'no-restricted-globals': 'off',
    },
  },
);
