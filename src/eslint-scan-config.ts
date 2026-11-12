import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import {
  releaseready,
  unresolvedModuleRules,
} from './eslint-unresolved-module.js';

/**
 * Approved bundled configuration for hosted scans. It is data only: no customer
 * config, plugin or type information is loaded, so it needs no TypeScript
 * project. Inline `eslint-*` comments cannot change or hide rules.
 *
 * Limitation: hosted scans run ESLint `recommended` plus the syntax-only
 * typescript-eslint `strict` and `stylistic` sets. The type-aware
 * `strict-type-checked` / `stylistic-type-checked` rules need the caller's
 * tsconfig and run in the caller's own lint through `qualityConfig`
 * (`@releaseready/code-quality/eslint`), which reads tsconfig without
 * executing project code. See docs/language-profiles.md.
 */
export const scanFiles = [
  '**/*.js',
  '**/*.mjs',
  '**/*.cjs',
  '**/*.jsx',
  '**/*.ts',
  '**/*.mts',
  '**/*.cts',
  '**/*.tsx',
];
export const scanIgnores = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/vendor/**',
  '**/*.min.js',
];

/**
 * The scan configuration. `typed` is the explicit opt-in (workflow input
 * `eslint-tsconfig`): it swaps the syntax-only `strict`/`stylistic` sets for
 * `strict-type-checked`/`stylistic-type-checked`. The reviewed tsconfig is not
 * named here; the adapter passes it as `--parser-options project:<path>`.
 * Everything else is identical, so the default export (typed = false) is the
 * same configuration as before the opt-in existed.
 */
export function scanConfig(typed: boolean) {
  return defineConfig(
    { ignores: scanIgnores },
    {
      files: scanFiles,
      extends: [js.configs.recommended],
      linterOptions: {
        noInlineConfig: true,
        reportUnusedDisableDirectives: 'off',
      },
      // JSX is parsed in every JavaScript-family file: React projects commonly
      // keep JSX in `.js`. TypeScript files infer JSX from the `.tsx` extension.
      languageOptions: {
        ecmaVersion: 'latest',
        parserOptions: { ecmaFeatures: { jsx: true } },
      },
      // No browser/Node globals are configured, so undefined-name checks would
      // only produce noise; they are off rather than guessed.
      rules: { 'no-undef': 'off' },
    },
    {
      files: ['**/*.ts', '**/*.mts', '**/*.cts', '**/*.tsx'],
      extends: typed
        ? [
            tseslint.configs.strictTypeChecked,
            tseslint.configs.stylisticTypeChecked,
            { plugins: { releaseready }, rules: unresolvedModuleRules },
          ]
        : [tseslint.configs.strict, tseslint.configs.stylistic],
    },
    {
      files: [
        '**/*.js',
        '**/*.mjs',
        '**/*.jsx',
        '**/*.ts',
        '**/*.mts',
        '**/*.tsx',
      ],
      languageOptions: { sourceType: 'module' },
    },
    {
      files: ['**/*.cjs', '**/*.cts'],
      languageOptions: { sourceType: 'commonjs' },
    },
  );
}

export default scanConfig(false);
