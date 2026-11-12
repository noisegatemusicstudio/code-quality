/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Checks coverage, jscpd duplication and new-code measure calculations against fixed synthetic reports with known totals; does not run jscpd or customer tests.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type CoverageContext,
  type CoverageFormat,
  parseCoverageDetail,
} from '../src/coverage-detail.js';
import { jscpdAdapter, parseJscpdReport } from '../src/duplication.js';
import { allowedArguments } from '../src/scanner-adapter.js';
import {
  type ChangedLinesDiff,
  buildQualityMeasures,
  evaluateThreshold,
  newCodeMeasures,
  overallMeasures,
} from '../src/quality-measures.js';

const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const root = '/repo';
const ctx = (over: Partial<CoverageContext> = {}): CoverageContext => ({
  commitSha: B,
  reportCommitSha: B,
  pathRoot: root,
  files: ['src/a.ts', 'src/b.ts'],
  ...over,
});
const loc = (line: number) => ({ start: { line, column: 0 } });
// src/a.ts: lines 1,2,3,4 hit 1,1,0,2 (3/4); branch at line 2 hits 1,0 (1/2).
// src/b.ts: lines 1,2 hit 0,0 (0/2); no branches.
const finalReport = JSON.stringify({
  '/repo/src/a.ts': {
    statementMap: { 0: loc(1), 1: loc(2), 2: loc(3), 3: loc(4) },
    s: { 0: 1, 1: 1, 2: 0, 3: 2 },
    branchMap: { 0: { type: 'if', locations: [loc(2), loc(2)] } },
    b: { 0: [1, 0] },
  },
  '/repo/src/b.ts': {
    statementMap: { 0: loc(1), 1: loc(2) },
    s: { 0: 0, 1: 0 },
    branchMap: {},
    b: {},
  },
});
const counts = (covered: number, total: number) => ({
  total,
  covered,
  skipped: 0,
  pct: 0,
});
const summaryReport = JSON.stringify({
  total: { lines: counts(3, 6), branches: counts(1, 2) },
  '/repo/src/a.ts': { lines: counts(3, 4), branches: counts(1, 2) },
  '/repo/src/b.ts': { lines: counts(0, 2), branches: counts(0, 0) },
});

await test('coverage keeps exact line and branch numerators and denominators', () => {
  for (const [raw, format] of [
    [summaryReport, 'json-summary'],
    [finalReport, 'coverage-final'],
  ] as const) {
    const d = parseCoverageDetail(raw, format, ctx());
    assert.equal(d.state, 'complete');
    assert.deepEqual(d.lines, { covered: 3, total: 6 });
    assert.deepEqual(d.branches, { covered: 1, total: 2 });
    assert.deepEqual(
      d.files.map((f) => [f.path, f.lines, f.branches]),
      [
        ['src/a.ts', { covered: 3, total: 4 }, { covered: 1, total: 2 }],
        ['src/b.ts', { covered: 0, total: 2 }, { covered: 0, total: 0 }],
      ],
    );
  }
});

await test('missing, unsupported, invalid and stale reports are not zero coverage', () => {
  const state = (
    raw: unknown,
    format: CoverageFormat = 'json-summary',
    c = ctx(),
  ) => parseCoverageDetail(raw, format, c);
  for (const raw of [undefined, null, '']) {
    const d = state(raw);
    assert.equal(d.state, 'missing');
    assert.equal(d.lines, null);
  }
  assert.equal(state('TN:\nSF:/repo/src/a.ts\n').state, 'unsupported');
  assert.equal(state('{"hello":1}').state, 'unsupported');
  assert.equal(state(summaryReport, 'coverage-final').state, 'unsupported');
  assert.equal(state('{oops').state, 'invalid');
  const bad = JSON.stringify({
    total: {},
    '/repo/src/a.ts': { lines: counts(5, 4), branches: counts(0, 0) },
  });
  assert.equal(state(bad).state, 'invalid');
  assert.equal(
    state(summaryReport, 'json-summary', ctx({ reportCommitSha: A })).state,
    'stale',
  );
  assert.equal(
    state(summaryReport, 'json-summary', ctx({ reportCommitSha: undefined }))
      .state,
    'stale',
  );
  const zero = JSON.stringify({
    total: {},
    '/repo/src/a.ts': { lines: counts(0, 4), branches: counts(0, 2) },
    '/repo/src/b.ts': { lines: counts(0, 2), branches: counts(0, 0) },
  });
  const z = state(zero);
  assert.equal(z.state, 'complete');
  assert.deepEqual(z.lines, { covered: 0, total: 6 });
  const m = overallMeasures(z);
  assert.equal(m[0]?.state === 'known' && m[0].percent, 0);
});

await test('partial reports, exclusions and renamed files', () => {
  const partial = parseCoverageDetail(
    summaryReport,
    'json-summary',
    ctx({ files: ['src/a.ts', 'src/b.ts', 'src/c.ts'] }),
  );
  assert.equal(partial.state, 'partial');
  assert.deepEqual(partial.missing, ['src/c.ts']);
  assert.equal(overallMeasures(partial)[0]?.state, 'unknown');

  const excluded = parseCoverageDetail(
    summaryReport,
    'json-summary',
    ctx({ exclusions: ['src/b.ts'], files: ['src/a.ts', 'src/b.ts'] }),
  );
  assert.equal(excluded.state, 'complete');
  assert.deepEqual(excluded.excluded, ['src/b.ts']);
  assert.deepEqual(excluded.lines, { covered: 3, total: 4 });

  const old = summaryReport.replace('/repo/src/b.ts', '/repo/src/old.ts');
  const unmatched = parseCoverageDetail(old, 'json-summary', ctx());
  assert.equal(unmatched.state, 'unmatched');
  assert.deepEqual(unmatched.unmatched, ['src/old.ts']);
  assert.equal(unmatched.lines, null);
  const renamed = parseCoverageDetail(
    old,
    'json-summary',
    ctx({ renames: { 'src/old.ts': 'src/b.ts' } }),
  );
  assert.equal(renamed.state, 'complete');
  const outside = summaryReport.replace('/repo/src/b.ts', '/other/src/b.ts');
  assert.equal(
    parseCoverageDetail(outside, 'json-summary', ctx()).state,
    'unmatched',
  );
});

const diff = (over: Partial<ChangedLinesDiff> = {}): ChangedLinesDiff => ({
  baseCommitSha: A,
  headCommitSha: B,
  files: [
    { path: 'src/a.ts', status: 'modified', lines: [2, 3, 5] },
    { path: 'src/b.ts', status: 'added', lines: [1] },
    { path: 'src/gone.ts', status: 'deleted', lines: [] },
  ],
  ...over,
});
const id = (ms: ReturnType<typeof newCodeMeasures>, key: string) =>
  ms.find((m) => m.id === key);

await test('new-code coverage counts only executable changed lines', () => {
  const coverage = parseCoverageDetail(finalReport, 'coverage-final', ctx());
  const ms = newCodeMeasures({
    referenceCommitSha: A,
    headCommitSha: B,
    diff: diff(),
    coverage,
  });
  // a.ts line 2 hit, line 3 not hit, line 5 not executable; b.ts line 1 not hit.
  assert.deepEqual(id(ms, 'coverage.lines'), {
    id: 'coverage.lines',
    scope: 'new-code',
    state: 'known',
    numerator: 1,
    denominator: 3,
    percent: (1 / 3) * 100,
  });
  const branches = id(ms, 'coverage.branches');
  assert.ok(branches?.state === 'known');
  assert.equal(branches.numerator, 1);
  assert.equal(branches.denominator, 2);
  assert.equal(id(ms, 'duplication.lines')?.state, 'unknown');
});

await test('new-code measures reject stale, unmatched or unrelated inputs', () => {
  const base = { referenceCommitSha: A, headCommitSha: B };
  const reason = (input: Parameters<typeof newCodeMeasures>[0]) => {
    const m = id(newCodeMeasures(input), 'coverage.lines');
    return m?.state === 'unknown' ? m.reason : 'known';
  };
  const cov = parseCoverageDetail(finalReport, 'coverage-final', ctx());
  assert.equal(reason({ ...base, diff: diff(), coverage: cov }), 'known');
  assert.equal(reason({ ...base, diff: diff() }), 'no-report');
  const sum = parseCoverageDetail(summaryReport, 'json-summary', ctx());
  assert.equal(
    reason({ ...base, diff: diff(), coverage: sum }),
    'no-line-data',
  );
  const stale = parseCoverageDetail(
    finalReport,
    'coverage-final',
    ctx({ reportCommitSha: A }),
  );
  assert.equal(
    reason({ ...base, diff: diff(), coverage: stale }),
    'stale-report',
  );
  const other = { ...cov, commitSha: A };
  assert.equal(
    reason({ ...base, diff: diff(), coverage: other }),
    'stale-report',
  );
  assert.equal(
    reason({ ...base, diff: diff({ baseCommitSha: B }), coverage: cov }),
    'diff-mismatch',
  );
  assert.equal(
    reason({
      referenceCommitSha: B,
      headCommitSha: B,
      diff: diff(),
      coverage: cov,
    }),
    'invalid-reference',
  );
  assert.equal(
    reason({
      referenceCommitSha: 'main',
      headCommitSha: B,
      diff: diff(),
      coverage: cov,
    }),
    'invalid-reference',
  );
  const extra = diff({
    files: [{ path: 'src/new.ts', status: 'added', lines: [1] }],
  });
  assert.equal(
    reason({ ...base, diff: extra, coverage: cov }),
    'changed-file-not-in-report',
  );
  const excluded = newCodeMeasures({
    ...base,
    diff: extra,
    coverage: cov,
    exclusions: ['src/new.ts'],
  });
  assert.equal(id(excluded, 'coverage.lines')?.state, 'unknown');
  assert.equal(
    (id(excluded, 'coverage.lines') as { reason: string }).reason,
    'zero-denominator',
  );
});

// Recorded jscpd-shaped report: x 100 lines, y 50, z 10. Clone 1: x 10-19 with
// y 1-10; clone 2: x 15-24 with y 30-39. Distinct duplicated lines: x 10-24
// (15) + y 1-10 and 30-39 (20) = 35 of 160 = 21.875%.
const side = (name: string, start: number, end: number) => ({
  name: `/repo/${name}`,
  start,
  end,
  startLoc: { line: start, column: 1, position: 0 },
  endLoc: { line: end, column: 1, position: 0 },
});
const jscpdReport = (over: { y?: boolean } = {}) =>
  JSON.stringify({
    statistics: {
      formats: {
        typescript: {
          sources: {
            '/repo/src/x.ts': { lines: 100 },
            '/repo/src/y.ts': { lines: 50 },
            '/repo/src/z.ts': { lines: 10 },
          },
        },
      },
      total: { lines: 160, clones: 2 },
    },
    duplicates: [
      {
        format: 'typescript',
        lines: 10,
        tokens: 60,
        firstFile: side('src/x.ts', 10, 19),
        secondFile: side('src/y.ts', 1, 10),
        fragment: 'SECRET',
      },
      {
        format: 'typescript',
        lines: 10,
        tokens: 60,
        firstFile: side('src/x.ts', 15, 24),
        secondFile: side(over.y ? 'src/q.ts' : 'src/y.ts', 30, 39),
      },
    ],
  });
const files = ['src/x.ts', 'src/y.ts', 'src/z.ts', 'src/w.py'];
const dctx = { pathRoot: root, files, commitSha: B, reportCommitSha: B };

await test('jscpd report: locations on both sides, totals, thresholds', () => {
  const d = parseJscpdReport(jscpdReport(), dctx);
  assert.equal(d.state, 'complete');
  assert.equal(d.cloneCount, 2);
  assert.deepEqual(d.clones[0]?.second, {
    path: 'src/y.ts',
    startLine: 1,
    endLine: 10,
  });
  assert.deepEqual(d.totals, { covered: 35, total: 160 });
  assert.deepEqual(d.notAnalyzed, ['src/w.py']);
  assert.equal(JSON.stringify(d).includes('SECRET'), false);
  assert.deepEqual(
    [d.tool.version, d.config.minLines, d.config.minTokens],
    ['5.4.3', 5, 50],
  );
  const m = overallMeasures(undefined, d)[2];
  assert.ok(m?.state === 'known');
  assert.equal(m.percent, 21.875);
  assert.equal(evaluateThreshold(m, { max: 20 }), 'fail');
  assert.equal(evaluateThreshold(m, { max: 21.875 }), 'pass');
  assert.equal(evaluateThreshold(m, { max: 25 }), 'pass');
  assert.equal(evaluateThreshold(m, { min: 30 }), 'fail');
  const none = overallMeasures(undefined, undefined)[2];
  assert.ok(none);
  assert.equal(evaluateThreshold(none, { max: 100 }), 'unknown');
});

await test('jscpd report: missing, stale, unmatched and excluded', () => {
  assert.equal(parseJscpdReport(undefined, dctx).state, 'missing');
  assert.equal(parseJscpdReport('{', dctx).state, 'invalid');
  assert.equal(parseJscpdReport('{"a":1}', dctx).state, 'unsupported');
  assert.equal(
    parseJscpdReport(jscpdReport(), { ...dctx, reportCommitSha: A }).state,
    'stale',
  );
  const unmatched = parseJscpdReport(jscpdReport({ y: true }), dctx);
  assert.equal(unmatched.state, 'unmatched');
  assert.deepEqual(unmatched.unmatched, ['src/q.ts']);
  const notInSet = parseJscpdReport(jscpdReport(), {
    ...dctx,
    files: ['src/x.ts'],
  });
  assert.equal(notInSet.state, 'unmatched');
  const ex = parseJscpdReport(jscpdReport(), {
    ...dctx,
    exclusions: ['src/y.ts'],
  });
  assert.equal(ex.state, 'complete');
  assert.deepEqual(ex.excluded, ['src/y.ts']);
  assert.deepEqual(ex.totals, { covered: 0, total: 110 });
  const tampered = jscpdReport().replace('"lines":160', '"lines":161');
  assert.equal(parseJscpdReport(tampered, dctx).state, 'invalid');
  const beyond = jscpdReport().replace('"lines":50', '"lines":5');
  assert.equal(parseJscpdReport(beyond, dctx).state, 'invalid');
});

await test('new-code duplication uses changed lines inside analyzed files', () => {
  const d = parseJscpdReport(jscpdReport(), dctx);
  const input = {
    referenceCommitSha: A,
    headCommitSha: B,
    duplication: d,
    diff: diff({
      files: [
        { path: 'src/x.ts', status: 'modified', lines: [12, 16, 30] },
        { path: 'src/w.py', status: 'added', lines: [1, 2] },
      ],
    }),
  };
  const m = id(newCodeMeasures(input), 'duplication.lines');
  assert.ok(m?.state === 'known');
  assert.deepEqual([m.numerator, m.denominator, m.unanalyzedLines], [2, 3, 2]);
  const beyond = {
    ...input,
    diff: diff({
      files: [{ path: 'src/x.ts', status: 'modified', lines: [101] }],
    }),
  };
  const r = id(newCodeMeasures(beyond), 'duplication.lines');
  assert.ok(r?.state === 'unknown' && r.reason === 'diff-mismatch');
  const stale = parseJscpdReport(jscpdReport(), {
    ...dctx,
    commitSha: undefined,
    reportCommitSha: undefined,
  });
  const s = id(
    newCodeMeasures({ ...input, duplication: stale }),
    'duplication.lines',
  );
  assert.ok(s?.state === 'unknown' && s.reason === 'stale-report');
});

await test('jscpd adapter pins the version, allowlists args and emits both sides', () => {
  const adapter = jscpdAdapter('/opt/jscpd');
  assert.deepEqual(adapter.engine, { id: 'jscpd', version: '5.4.3' });
  assert.equal(adapter.versionOutput, '5.4.3');
  assert.equal(allowedArguments(adapter, []), true);
  assert.equal(allowedArguments(adapter, ['--install']), false);
  const parsed = adapter.parse(jscpdReport(), { sourceRoot: '/ws' });
  assert.equal(parsed?.findings.length, 4);
  assert.equal(new Set(parsed?.findings.map((f) => f.fingerprint)).size, 4);
  assert.equal(parsed?.findings[0]?.message, 'Duplicate of repo/src/y.ts:1-10');
  assert.equal(adapter.parse('nonsense', { sourceRoot: '/ws' }), undefined);
});

await test('assembled output is versioned, has provenance and no ratings', () => {
  const scope = {
    tenantId: 't',
    projectId: 'p',
    repository: 'o/r',
    commitSha: B,
    sourceId: 's',
    jobId: 'j',
    attemptId: 'a',
  };
  const empty = buildQualityMeasures({ scope });
  assert.equal(empty.schemaVersion, 1);
  assert.equal(empty.provenance.coverage, null);
  assert.deepEqual(
    empty.measures.map((m) => m.state),
    ['unknown', 'unknown', 'unknown'],
  );
  const cov = parseCoverageDetail(
    finalReport,
    'coverage-final',
    ctx({ exclusions: ['src/b.ts'] }),
  );
  const out = buildQualityMeasures({
    scope,
    coverage: cov,
    duplication: parseJscpdReport(jscpdReport(), dctx),
    newCode: {
      referenceCommitSha: A,
      headCommitSha: B,
      diff: diff({
        files: [{ path: 'src/a.ts', status: 'modified', lines: [2, 3] }],
      }),
    },
  });
  assert.equal(out.measures.length, 6);
  assert.equal(out.provenance.coverage?.source, 'imported-unverified');
  assert.deepEqual(out.provenance.coverage?.exclusionPatterns, ['src/b.ts']);
  assert.equal(out.provenance.newCode?.referenceCommitSha, A);
  const text = JSON.stringify(out.measures);
  assert.equal(/rating|debt|score/i.test(text), false);
  assert.ok(out.notProvided.includes('technical-debt-estimate'));
});
