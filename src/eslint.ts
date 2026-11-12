import js from '@eslint/js';
import { defineConfig, includeIgnoreFile } from 'eslint/config';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier/flat';
import { join } from 'node:path';

/**
 * Industry-standard TS/JS profile: ESLint `recommended`, typescript-eslint
 * `strict-type-checked` and `stylistic-type-checked`, Prettier compatibility.
 * Type-aware rules read the caller's tsconfig through typescript-estree's
 * project service. That parses tsconfig JSON (including `extends`) and never
 * executes project code, but the files in `typedFiles` must be covered by a
 * real TypeScript project or ESLint reports a parsing error for them.
 */
export function qualityConfig(
  root: string,
  typedFiles = ['src/**/*.ts', 'src/**/*.tsx', 'tests/**/*.ts'],
) {
  return defineConfig(
    includeIgnoreFile(join(root, 'quality.ignore')),
    js.configs.recommended,
    tseslint.configs.strict,
    tseslint.configs.stylistic,
    {
      files: typedFiles,
      extends: [
        tseslint.configs.strictTypeChecked,
        tseslint.configs.stylisticTypeChecked,
      ],
      languageOptions: {
        parserOptions: { projectService: true, tsconfigRootDir: root },
      },
    },
    // Files outside `typedFiles` keep the syntax-only strict and stylistic rules.
    prettier,
  );
}
