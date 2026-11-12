/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves language detection and the "skipped: no engine yet" labelling on synthetic path lists; runs no engine and reads no repository.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detectLanguages, renderLanguages } from '../src/language-detection.js';
import { renderSummary } from '../src/quality-scan.js';
import { decideWithGate, loadGate } from '../src/quality-gate.js';

const paths = [
  'src/a.ts',
  'src/b.tsx',
  'web/c.mjs',
  'tools/x.py',
  'app/Main.kt',
  'ios/App.swift',
  'build.gradle.kts',
  'scripts/run.sh',
  'Dockerfile',
  'svc/Dockerfile.prod',
  'Dockerfile.dockerignore',
  'infra/main.tf',
  '.github/workflows/ci.yml',
  'config/app.yaml',
  'README.md',
  'logo.png',
];

await test('every language present is listed with its file count', () => {
  const byName = new Map(detectLanguages(paths).map((l) => [l.language, l]));
  assert.equal(byName.get('TypeScript')?.files, 2);
  assert.equal(byName.get('JavaScript')?.files, 1);
  assert.equal(byName.get('Kotlin')?.files, 2);
  assert.equal(byName.get('Dockerfile')?.files, 2);
  assert.equal(byName.get('YAML')?.files, 2);
  assert.equal(byName.get('GitHub Actions')?.files, 1);
  assert.equal(byName.has('Java'), false);
  assert.equal(byName.has('PNG'), false);
});

await test('Python is covered by Ruff, not skipped', () => {
  const python = detectLanguages(paths).find((l) => l.language === 'Python');
  assert.equal(python?.status, 'covered');
  assert.deepEqual(python.engines, ['ruff']);
});

await test('Kotlin is covered by detekt and ktlint, not skipped', () => {
  const kotlin = detectLanguages(paths).find((l) => l.language === 'Kotlin');
  assert.equal(kotlin?.status, 'covered');
  assert.deepEqual(kotlin.engines, ['detekt', 'ktlint']);
});

await test('languages without an engine are skipped, never clean', () => {
  const byName = new Map(detectLanguages(paths).map((l) => [l.language, l]));
  for (const name of ['Swift']) {
    assert.equal(byName.get(name)?.status, 'skipped: no engine yet', name);
    assert.deepEqual(byName.get(name)?.engines, []);
  }
  assert.equal(byName.get('TypeScript')?.status, 'covered');
  assert.deepEqual(byName.get('TypeScript')?.engines, ['eslint', 'semgrep']);
  for (const name of ['Terraform', 'Dockerfile', 'YAML', 'Markdown'])
    assert.equal(byName.get(name)?.status, 'covered', name);
});

await test('Shell and GitHub Actions workflows count as covered', () => {
  const byName = new Map(detectLanguages(paths).map((l) => [l.language, l]));
  assert.equal(byName.get('Shell')?.status, 'covered');
  assert.deepEqual(byName.get('Shell')?.engines, ['shellcheck', 'shfmt']);
  assert.equal(byName.get('GitHub Actions')?.status, 'covered');
  assert.deepEqual(byName.get('GitHub Actions')?.engines, [
    'actionlint',
    'zizmor',
  ]);
  assert.equal(
    detectLanguages(['ci.yml']).some((l) => l.language === 'GitHub Actions'),
    false,
  );
});

await test('the summary shows unsupported languages explicitly', async () => {
  const languages = detectLanguages(['a.py', 'b.ts']);
  const summary = renderSummary({
    commitSha: 'a'.repeat(40),
    results: [],
    decision: decideWithGate([], { enforce: false, gate: await loadGate() }),
    baseline: null,
    languages,
  });
  assert.match(summary, /\| Python \| 1 \| analysed by ruff \|/);
  assert.match(summary, /\| TypeScript \| 1 \| analysed by eslint, semgrep \|/);
  assert.match(summary, /not a clean result/);
  assert.deepEqual(renderLanguages([]), []);
});
