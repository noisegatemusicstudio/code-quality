/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves gate file parsing and the new-code gate decision on synthetic engine results; runs no engine, reads no repository and does not exercise the CLI or workflow.
*/
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import type { AdapterFinding } from '../src/adapter-envelope.js';
import {
  decideWithGate,
  defaultGatePath,
  loadGate,
  parseGate,
  type QualityGate,
} from '../src/quality-gate.js';
import type { EngineResult } from '../src/quality-scan.js';
import { parseBaseline } from '../src/quality-scan.js';

const finding = (n: number, nativeSeverity: string): AdapterFinding => ({
  ruleId: 'r',
  nativeSeverity,
  path: 'a.ts',
  range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
  fingerprint: `sha256:${String(n).padStart(64, '0')}`,
  message: 'm',
});
const done = (
  engine: EngineResult['engine'],
  findings: AdapterFinding[] = [],
): EngineResult => ({ engine, status: 'completed', findings });

await test('the shipped default gate is the Sonar-way new-code gate', async () => {
  const gate = await loadGate();
  assert.equal(gate.newIssues.failOnSeverity, 'high');
  assert.equal(gate.secrets.maxFindings, 0);
  assert.equal(gate.newCodeCoverage.minPercent, 80);
  assert.equal(gate.newCodeDuplication.maxPercent, 3);
  assert.equal(gate.requiredEnginesMustComplete, true);
});

const base = async (): Promise<Record<string, unknown>> =>
  JSON.parse(await readFile(defaultGatePath, 'utf8')) as Record<
    string,
    unknown
  >;

await test('parseGate rejects unknown keys, missing keys and bad values', async () => {
  const good = await base();
  assert.doesNotThrow(() => parseGate(JSON.stringify(good)));
  assert.throws(() => parseGate('not json'), /not valid JSON/);
  assert.throws(
    () => parseGate(JSON.stringify({ ...good, extra: 1 })),
    /unknown key gate.extra/,
  );
  const rest = { ...good };
  delete rest.secrets;
  assert.throws(
    () => parseGate(JSON.stringify(rest)),
    /missing key gate.secrets/,
  );
  assert.throws(
    () =>
      parseGate(
        JSON.stringify({ ...good, newIssues: { failOnSeverity: 'severe' } }),
      ),
    /failOnSeverity/,
  );
  assert.throws(
    () =>
      parseGate(
        JSON.stringify({
          ...good,
          newCodeCoverage: { minPercent: 120, onUnknown: 'fail' },
        }),
      ),
    /0 to 100/,
  );
  assert.throws(
    () => parseGate(JSON.stringify({ ...good, schemaVersion: 2 })),
    /schemaVersion/,
  );
});

const gate = async (): Promise<QualityGate> => loadGate();

await test('high findings fail in enforce mode and only report in advisory mode', async () => {
  const results = [done('semgrep', [finding(1, 'ERROR')])];
  const enforce = decideWithGate(results, {
    enforce: true,
    gate: await gate(),
  });
  assert.equal(enforce.exitCode, 1);
  assert.match(enforce.reasons.join(), /new finding\(s\) at or above high/);
  assert.equal(enforce.gate.name, 'releaseready-default');
  const advisory = decideWithGate(results, {
    enforce: false,
    gate: await gate(),
  });
  assert.equal(advisory.exitCode, 0);
  assert.equal(advisory.wouldFail, true);
});

await test('findings present in the baseline are not new', async () => {
  const old = finding(1, 'ERROR');
  const baseline = parseBaseline(
    JSON.stringify({
      engines: [{ engine: 'semgrep', status: 'completed', findings: [old] }],
    }),
  );
  const results = [done('semgrep', [old, finding(2, 'WARNING')])];
  const d = decideWithGate(results, {
    enforce: true,
    gate: await gate(),
    baseline,
  });
  assert.equal(d.blocking, 0);
  assert.equal(d.exitCode, 0);
});

await test('any secret fails even below the severity threshold', async () => {
  const g = await gate();
  const lenient: QualityGate = {
    ...g,
    newIssues: { failOnSeverity: 'critical' },
  };
  const d = decideWithGate([done('gitleaks', [finding(1, 'x')])], {
    enforce: true,
    gate: { ...lenient, secrets: { maxFindings: 0 } },
  });
  assert.match(d.reasons.join(), /secret finding/);
  const allowed = decideWithGate([done('gitleaks')], {
    enforce: true,
    gate: lenient,
  });
  assert.equal(allowed.exitCode, 0);
});

await test('failed or incomplete required engines block, skipped ones do not', async () => {
  const g = await gate();
  const failed: EngineResult = {
    engine: 'osv',
    status: 'failed',
    reason: 'x',
    findings: [],
  };
  const skipped: EngineResult = {
    engine: 'trivy',
    status: 'skipped',
    skipKind: 'not-applicable',
    reason: 'x',
    findings: [],
  };
  assert.equal(
    decideWithGate([failed], { enforce: true, gate: g }).exitCode,
    1,
  );
  assert.equal(
    decideWithGate([skipped], { enforce: true, gate: g }).exitCode,
    0,
  );
  assert.equal(
    decideWithGate([failed], {
      enforce: true,
      gate: { ...g, requiredEnginesMustComplete: false },
    }).exitCode,
    0,
  );
});

await test('coverage and duplication thresholds, and unknown measures', async () => {
  const g = await gate();
  const measured = (c: number | null, d: number | null, gg = g) =>
    decideWithGate([done('eslint')], {
      enforce: true,
      gate: gg,
      measures: {
        newCodeCoveragePercent: c,
        newCodeDuplicationPercent: d,
      },
    });
  assert.equal(measured(80, 3).exitCode, 0);
  assert.match(measured(79.9, 3).reasons.join(), /new-code coverage 79.9%/);
  assert.match(measured(80, 3.1).reasons.join(), /new-code duplication 3.1%/);
  // Default gate reports unmeasured values without blocking ...
  assert.equal(measured(null, null).exitCode, 0);
  // ... and a gate that says `fail` blocks on them.
  const strict: QualityGate = {
    ...g,
    newCodeCoverage: { minPercent: 80, onUnknown: 'fail' },
    newCodeDuplication: { maxPercent: 3, onUnknown: 'fail' },
  };
  const blocked = measured(null, null, strict);
  assert.equal(blocked.exitCode, 1);
  assert.match(blocked.reasons.join(), /coverage not measured/);
  assert.match(blocked.reasons.join(), /duplication not measured/);
});

await test('new-code measures decide the gate: below 80% coverage and above 3% duplication fail', async () => {
  const gate = await loadGate();
  const measures = (coverage: number | null, duplication: number | null) => ({
    newCodeCoveragePercent: coverage,
    newCodeDuplicationPercent: duplication,
  });
  const pass = decideWithGate([], {
    enforce: true,
    gate,
    measures: measures(80, 3),
  });
  assert.equal(pass.wouldFail, false);
  const low = decideWithGate([], {
    enforce: true,
    gate,
    measures: measures(79.9, 3),
  });
  assert.equal(low.exitCode, 1);
  assert.match(
    low.reasons.join(';'),
    /new-code coverage 79.9%, required >= 80%/,
  );
  const dup = decideWithGate([], {
    enforce: true,
    gate,
    measures: measures(90, 3.1),
  });
  assert.match(
    dup.reasons.join(';'),
    /new-code duplication 3.1%, required <= 3%/,
  );
});

await test('unknown new-code measures are reported by default and block only when onUnknown is fail', async () => {
  const gate = await loadGate();
  const unknown = {
    newCodeCoveragePercent: null,
    newCodeDuplicationPercent: null,
    newCodeCoverageUnknown: 'no coverage report supplied',
  };
  assert.equal(
    decideWithGate([], { enforce: true, gate, measures: unknown }).wouldFail,
    false,
  );
  const strict: QualityGate = {
    ...gate,
    newCodeCoverage: { ...gate.newCodeCoverage, onUnknown: 'fail' },
  };
  const blocked = decideWithGate([], {
    enforce: true,
    gate: strict,
    measures: unknown,
  });
  assert.equal(blocked.exitCode, 1);
  assert.match(
    blocked.reasons.join(';'),
    /coverage not measured \(no coverage report supplied\)/,
  );
});
