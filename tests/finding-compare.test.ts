// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: Pure compareFindings and fingerprint helpers on synthetic envelopes; no engine is run.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type {
  AdapterEnvelope,
  AdapterFinding,
} from '../src/adapter-envelope.js';
import {
  compareFindings,
  normalisedSnippet,
  stableFingerprint,
} from '../src/finding-compare.js';
import { scope } from './eslint-fixtures.js';

const finding = (n: number): AdapterFinding => ({
  ruleId: 'no-var',
  nativeSeverity: 'error',
  path: 'a.ts',
  range: { startLine: n, startColumn: 1, endLine: n, endColumn: 4 },
  fingerprint: stableFingerprint('eslint', 'no-var', 'a.ts', `var x${n}`),
  message: 'm',
});
const env = (
  status: AdapterEnvelope['status'],
  findings: AdapterFinding[],
  extra: Partial<AdapterEnvelope> = {},
): AdapterEnvelope => ({
  schemaVersion: 1,
  provenance: 'adapter-executed',
  ...scope,
  engine: { id: 'eslint', version: '10.13.0' },
  rulesetVersion: 'r1',
  configVersion: 'c1',
  status,
  ...(status === 'completed' ? {} : { reason: 'timeout' as const }),
  findings: status === 'failed' || status === 'skipped' ? [] : findings,
  ...extra,
});
const [f1, f2, f3] = [finding(1), finding(2), finding(3)];

await test('classifies new, existing and resolved', () => {
  const r = compareFindings(
    env('completed', [f1, f2]),
    env('completed', [f2, f3]),
  );
  assert.ok(r.status === 'compared');
  assert.deepEqual(r.new, [f3]);
  assert.deepEqual(r.existing, [f2]);
  assert.deepEqual(r.resolved, [f1]);
});

await test('incomplete, failed or skipped current runs never resolve', () => {
  for (const s of ['incomplete', 'failed', 'skipped'] as const) {
    const r = compareFindings(env('completed', [f1, f2]), env(s, []));
    assert.ok(r.status === 'compared');
    assert.deepEqual(r.resolved, [], s);
    assert.equal(r.currentComplete, false);
  }
});

await test('an incomplete baseline never makes findings new', () => {
  const r = compareFindings(
    env('incomplete', [f1]),
    env('completed', [f1, f2]),
  );
  assert.ok(r.status === 'compared');
  assert.deepEqual(r.new, []);
  assert.deepEqual(r.unclassified, [f2]);
  assert.deepEqual(r.existing, [f1]);
});

await test('refuses cross-version, cross-scope, imported and invalid input', () => {
  const base = env('completed', [f1]);
  const reason = (c: unknown) =>
    (compareFindings(base, c as AdapterEnvelope) as { reason?: string }).reason;
  assert.equal(
    reason(env('completed', [], { rulesetVersion: 'r2' })),
    'version-mismatch',
  );
  assert.equal(
    reason(env('completed', [], { projectId: 'other' })),
    'scope-mismatch',
  );
  assert.equal(
    reason(env('completed', [], { provenance: 'imported-unverified' })),
    'provenance',
  );
  assert.equal(reason({ bad: true }), 'invalid-envelope');
});

await test('snippet normalisation ignores whitespace and keeps rule/path identity', () => {
  const r = { startLine: 2, startColumn: 3, endLine: 2, endColumn: 15 };
  assert.equal(normalisedSnippet('a\n  var   x = 1;', r), 'var x = 1;');
  assert.notEqual(
    stableFingerprint('eslint', 'a', 'p', 's'),
    stableFingerprint('eslint', 'b', 'p', 's'),
  );
  assert.notEqual(
    stableFingerprint('eslint', 'a', 'p', 's', 0),
    stableFingerprint('eslint', 'a', 'p', 's', 1),
  );
});
