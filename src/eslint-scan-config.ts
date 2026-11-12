import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

/**
 * Approved bundled configuration for hosted scans. It is data only: no customer
 * config, plugin or type information is loaded, so it needs no TypeScript
 * project. Inline `eslint-*` comments cannot change or hide rules.
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

export default defineConfig(
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
    extends: [tseslint.configs.recommended],
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
