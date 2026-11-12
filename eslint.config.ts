import { qualityConfig } from './dist/src/eslint.js';

// Migration debt: the strict-type-checked profile flags ~130 existing sites for
// these rules. They are switched off for this repository only (consumers of
// `qualityConfig` get them on) until the cleanup slice in
// docs/language-profiles.md lands. Remove entries as each rule is cleaned up.
const migrationDebt = {
  '@typescript-eslint/no-unnecessary-condition': 'off',
  '@typescript-eslint/restrict-template-expressions': 'off',
  '@typescript-eslint/no-non-null-assertion': 'off',
  '@typescript-eslint/no-confusing-void-expression': 'off',
  '@typescript-eslint/no-dynamic-delete': 'off',
} as const;

export default [
  ...qualityConfig(import.meta.dirname),
  { files: ['**/*.ts'], rules: migrationDebt },
];
