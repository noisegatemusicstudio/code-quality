/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves engine selection, applicability detection, severity normalisation, the advisory/enforce decision, baseline comparison and Markdown summary rendering on synthetic engine results; runs no engine and reads no repository.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AdapterFinding } from '../src/adapter-envelope.js';
import {
  buildReport,
  decide,
  detectApplicability,
  engineIds,
  newFindings,
  normaliseSeverity,
  parseBaseline,
  parseScanners,
  renderSummary,
  type EngineId,
  type EngineResult,
} from '../src/quality-scan.js';

const finding = (
  ruleId: string,
  nativeSeverity: string,
  n = 1,
): AdapterFinding => ({
  ruleId,
  nativeSeverity,
  path: 'a.ts',
  range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
  fingerprint: `sha256:${String(n).padStart(64, '0')}`,
  message: 'm',
});
const result = (
  engine: EngineId,
  status: EngineResult['status'],
  findings: AdapterFinding[] = [],
  reason?: string,
): EngineResult => ({ engine, status, findings, reason });

await test('scanner list: all by default, subsets honoured, unknown names reported', () => {
  assert.deepEqual(parseScanners('').selected, [...engineIds]);
  assert.deepEqual(parseScanners('all').selected, [...engineIds]);
  assert.deepEqual(parseScanners(' Semgrep, gitleaks ').selected, [
    'gitleaks',
    'semgrep',
  ]);
  assert.deepEqual(parseScanners('gitleaks,sonar').unknown, ['sonar']);
});

await test('applicability: engines only apply when their inputs exist', () => {
  const none = detectApplicability(['README.md', 'docs/a.md']);
  assert.equal(none.eslint.applicable, false);
  assert.equal(none.semgrep.applicable, false);
  assert.equal(none.osv.applicable, false);
  assert.equal(none.trivy.applicable, false);
  assert.equal(none.gitleaks.applicable, true);
  assert.equal(none.jscpd.applicable, true);
  const some = detectApplicability([
    'src/a.ts',
    'web/package-lock.json',
    'infra/main.tf',
  ]);
  assert.equal(some.eslint.applicable, true);
  assert.equal(some.semgrep.applicable, true);
  assert.equal(some.osv.applicable, true);
  assert.equal(some.trivy.applicable, true);
  // A lockfile name must match exactly, not as a suffix.
  assert.equal(
    detectApplicability(['x/not-package-lock.json']).osv.applicable,
    false,
  );
  // tsx is Semgrep territory but not an ESLint adapter extension.
  const tsx = detectApplicability(['ui/App.tsx']);
  assert.equal(tsx.semgrep.applicable, true);
  assert.equal(tsx.eslint.applicable, false);
});

await test('severity: native labels map, unknown labels fail closed to high', () => {
  assert.equal(normaliseSeverity('gitleaks', 'secret'), 'critical');
  assert.equal(normaliseSeverity('jscpd', 'info'), 'info');
  assert.equal(normaliseSeverity('semgrep', 'ERROR'), 'high');
  assert.equal(normaliseSeverity('semgrep', 'WARNING'), 'medium');
  assert.equal(normaliseSeverity('eslint', 'error'), 'medium');
  assert.equal(normaliseSeverity('trivy', 'CRITICAL'), 'critical');
  assert.equal(normaliseSeverity('trivy', 'MODERATE'), 'medium');
  assert.equal(normaliseSeverity('trivy', 'weird'), 'high');
});

await test('advisory mode exits 0 even with findings and broken engines, but still reports the verdict', () => {
  const results = [
    result('gitleaks', 'completed', [finding('secret', 'secret')]),
    result('semgrep', 'failed', [], 'engine-error'),
  ];
  const d = decide(results, { enforce: false, failOnSeverity: 'high' });
  assert.equal(d.exitCode, 0);
  assert.equal(d.wouldFail, true);
  assert.equal(d.mode, 'advisory');
});

await test('enforce mode fails on failed or incomplete engines', () => {
  for (const status of ['failed', 'incomplete'] as const) {
    const d = decide([result('trivy', status, [], 'x')], {
      enforce: true,
      failOnSeverity: 'high',
    });
    assert.equal(d.exitCode, 1, status);
    assert.deepEqual(d.broken, ['trivy']);
  }
});

await test('enforce mode: findings at or above the threshold fail, below it pass', () => {
  const high = [result('semgrep', 'completed', [finding('r', 'ERROR')])];
  assert.equal(
    decide(high, { enforce: true, failOnSeverity: 'high' }).exitCode,
    1,
  );
  assert.equal(
    decide(high, { enforce: true, failOnSeverity: 'critical' }).exitCode,
    0,
  );
  const low = [result('semgrep', 'completed', [finding('r', 'INFO')])];
  assert.equal(
    decide(low, { enforce: true, failOnSeverity: 'high' }).exitCode,
    0,
  );
  assert.equal(
    decide(low, { enforce: true, failOnSeverity: 'low' }).exitCode,
    1,
  );
  // Findings from an incomplete engine still count towards the threshold.
  const part = [
    result('gitleaks', 'incomplete', [finding('s', 'secret')], 'x'),
  ];
  assert.equal(
    decide(part, { enforce: true, failOnSeverity: 'critical' }).blocking,
    1,
  );
});

await test('enforce mode passes when every applicable engine completed clean; skipped engines do not fail it', () => {
  const clean: EngineResult[] = [
    result('gitleaks', 'completed'),
    { ...result('osv', 'skipped', [], 'no db'), skipKind: 'unavailable' },
    { ...result('eslint', 'skipped', [], 'n/a'), skipKind: 'not-applicable' },
  ];
  const d = decide(clean, { enforce: true, failOnSeverity: 'high' });
  assert.equal(d.exitCode, 0);
  assert.equal(d.wouldFail, false);
});

await test('baseline: only completed baseline engines compare, and only unseen fingerprints are new', () => {
  const base = parseBaseline(
    JSON.stringify({
      engines: [
        {
          engine: 'semgrep',
          status: 'completed',
          findings: [finding('r', 'ERROR', 1)],
        },
        { engine: 'trivy', status: 'failed', findings: [] },
      ],
    }),
  );
  assert.ok(base);
  const now = result('semgrep', 'completed', [
    finding('r', 'ERROR', 1),
    finding('r', 'ERROR', 2),
  ]);
  assert.equal(newFindings(now, base)?.length, 1);
  // A failed baseline engine is not a baseline: nothing is called new.
  assert.equal(
    newFindings(result('trivy', 'completed', [finding('t', 'HIGH', 9)]), base),
    null,
  );
  // A non-completed current run cannot be compared either.
  assert.equal(
    newFindings(result('semgrep', 'incomplete', [], 'x'), base),
    null,
  );
  assert.equal(parseBaseline('not json'), null);
  assert.equal(parseBaseline('{"engines":3}'), null);
});

await test('summary: counts per engine; skipped, failed and incomplete are never shown as clean', () => {
  const results: EngineResult[] = [
    result('gitleaks', 'completed'),
    result('semgrep', 'completed', [
      finding('releaseready.js.no-eval', 'ERROR'),
      finding('releaseready.js.no-eval', 'ERROR', 2),
    ]),
    result('trivy', 'failed', [], 'engine-error'),
    result('jscpd', 'incomplete', [], 'limited'),
    { ...result('osv', 'skipped', [], 'no database'), skipKind: 'unavailable' },
  ];
  const decision = decide(results, { enforce: false, failOnSeverity: 'high' });
  const md = renderSummary({
    commitSha: 'a'.repeat(40),
    results,
    decision,
    baseline: null,
  });
  assert.match(md, /\| gitleaks \| completed \| 0 \|/);
  assert.match(md, /\| semgrep \| completed \| 2 \|/);
  assert.match(md, /\| trivy \| failed \| – \|/);
  assert.match(md, /\| jscpd \| incomplete \| 0\+ \|/);
  assert.match(md, /\| osv \| skipped \| – \|.*skipped \(unavailable\)/);
  assert.match(md, /Not a clean result/);
  for (const engine of ['trivy', 'jscpd', 'osv'])
    assert.match(md, new RegExp(`\\*\\*${engine}\\*\\*`));
  assert.ok(md.includes('releaseready.js.no-eval (2)'));
  assert.match(md, /Advisory mode/);
  assert.match(md, /no new-vs-baseline split/);
});

await test('summary: engine-supplied text cannot inject Markdown or HTML', () => {
  const results = [
    result('trivy', 'failed', [], '<img src=x onerror=1>|`x`\n# h'),
  ];
  const md = renderSummary({
    commitSha: 'b'.repeat(40),
    results,
    decision: decide(results, { enforce: true, failOnSeverity: 'high' }),
    baseline: null,
  });
  assert.equal(/(?<!\\)</.test(md), false);
  assert.match(md, /Enforce mode: this job fails/);
});

await test('report artefact carries fingerprints so it can serve as a later baseline', () => {
  const results = [result('semgrep', 'completed', [finding('r', 'ERROR', 3)])];
  const report = buildReport({
    commitSha: 'c'.repeat(40),
    repository: 'o/r',
    results,
    decision: decide(results, { enforce: false, failOnSeverity: 'high' }),
  });
  const base = parseBaseline(JSON.stringify(report));
  assert.equal(newFindings(results[0], base)?.length, 0);
});
