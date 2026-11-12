/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves the bundled ESLint configs enable the strict and stylistic typescript-eslint sets (type-aware only in qualityConfig, syntax-only in the hosted scan config) by resolving rule levels and linting inline text; does not lint a real consumer project or run the workflow.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ESLint, type Linter } from 'eslint';
import scanConfig from '../src/eslint-scan-config.js';
import { qualityConfig } from '../src/eslint.js';

const root = new URL('../../', import.meta.url).pathname;
const level = (config: Linter.Config | undefined, rule: string): unknown =>
  Array.isArray(config?.rules?.[rule])
    ? config.rules[rule][0]
    : config?.rules?.[rule];

await test('qualityConfig turns on strict and stylistic type-checked rules for typed files', async () => {
  const eslint = new ESLint({
    cwd: root,
    overrideConfigFile: true,
    overrideConfig: qualityConfig(root),
  });
  const config = (await eslint.calculateConfigForFile('src/eslint.ts')) as
    Linter.Config | undefined;
  for (const rule of [
    '@typescript-eslint/no-unnecessary-condition', // strict-type-checked
    '@typescript-eslint/no-floating-promises', // recommended-type-checked, kept
    '@typescript-eslint/prefer-nullish-coalescing', // stylistic-type-checked
    '@typescript-eslint/no-extraneous-class', // strict
  ])
    assert.ok([2, 'error'].includes(level(config, rule) as never), rule);
});

await test('the hosted scan config adds strict and stylistic rules but no type-aware ones', async () => {
  const eslint = new ESLint({
    cwd: root,
    overrideConfigFile: true,
    overrideConfig: scanConfig,
  });
  const [result] = await eslint.lintText(
    'export class OnlyStatic { static x = 1; }\nexport const a: Array<string> = [];\n',
    { filePath: 'probe.ts' },
  );
  const ids = result?.messages.map((m) => m.ruleId) ?? [];
  assert.ok(ids.includes('@typescript-eslint/no-extraneous-class'), 'strict');
  assert.ok(ids.includes('@typescript-eslint/array-type'), 'stylistic');
  const config = (await eslint.calculateConfigForFile('probe.ts')) as
    Linter.Config | undefined;
  assert.ok(
    [0, 'off', undefined].includes(
      level(config, '@typescript-eslint/no-unnecessary-condition') as never,
    ),
    'type-aware rules stay off without a tsconfig',
  );
});
