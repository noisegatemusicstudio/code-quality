/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Builds a real throwaway git repository with fixed base and head commits and proves the changed-lines diff totals, the new-code coverage and duplication pass/fail/unknown cases, the pull-request versus push base selection, and the CLI's report.json, summary.md and manifest output; runs no scanner other than the bundled ESLint engine, no project tests and no network.
*/
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { jscpdFindings } from '../src/duplication.js';
import {
  changedLinesDiff,
  computeNewCode,
  parseChangedLines,
} from '../src/new-code.js';
import { buildManifest } from '../src/quality-manifest.js';
import type { EngineResult } from '../src/quality-scan.js';
import { systemGit } from '../src/system-git.js';

// Plain diff/show/rev-parse need no snapshot-capable Git, so any system Git works.
const git = systemGit(
  process.platform,
  process.env.CODE_QUALITY_GIT_EXECUTABLE,
);
const repo = mkdtempSync(join(tmpdir(), 'new-code-'));
process.on('exit', () => rmSync(repo, { recursive: true, force: true }));
const run = (...args: string[]): string =>
  execFileSync(git, ['-C', repo, ...args], { encoding: 'utf8' }).trim();
const put = (name: string, lines: string[]): void => {
  mkdirSyncFor(name);
  writeFileSync(join(repo, name), lines.join('\n') + '\n');
};
const mkdirSyncFor = (name: string): void => {
  execFileSync('mkdir', ['-p', join(repo, name, '..')]);
};
const numbered = (n: number, tag = 'a'): string[] =>
  Array.from(
    { length: n },
    (_, i) => `export const ${tag}${i + 1} = ${i + 1};`,
  );

run('init', '-q', '-b', 'main');
run('config', 'user.email', 'fixture@example.invalid');
run('config', 'user.name', 'Fixture');
run('config', 'commit.gpgsign', 'false');
put('src/a.ts', numbered(10));
put('src/old.ts', numbered(2, 'o'));
put('src/r.ts', numbered(6, 'r'));
run('add', '-A');
run('commit', '-q', '-m', 'base');
const base = run('rev-parse', 'HEAD');
// Head: a.ts line 3 changed and 4 lines appended (3,11,12,13,14); new.ts is
// 5 added lines; old.ts deleted; r.ts renamed to r2.ts with line 2 changed.
const a = numbered(10);
a[2] = 'export const changed = 3;';
put('src/a.ts', [...a, ...numbered(4, 'n')]);
put('src/new.ts', numbered(5, 'w'));
run('rm', '-q', 'src/old.ts');
run('mv', 'src/r.ts', 'src/r2.ts');
const r = numbered(6, 'r');
r[1] = 'export const renamed = 2;';
put('src/r2.ts', r);
run('add', '-A');
run('commit', '-q', '-m', 'head');
const head = run('rev-parse', 'HEAD');
const tracked = run('ls-files').split('\n');

const loc = (line: number) => ({ start: { line, column: 0 } });
const entry = (hits: Record<number, number>) => {
  const lines = Object.keys(hits).map(Number);
  return {
    statementMap: Object.fromEntries(lines.map((l, i) => [i, loc(l)])),
    s: Object.fromEntries(lines.map((l, i) => [i, hits[l]])),
    branchMap: {},
    b: {},
  };
};
// Changed executable lines: a.ts 3,11,12,13,14 (4 of 5 hit), new.ts 1-5
// (all hit), r2.ts 2 (hit) -> 10/11 = 90.9%.
const coverageFinal = (r2Hit = 1, newHit = 1): string =>
  JSON.stringify({
    [join(repo, 'src/a.ts')]: entry({ 3: 1, 11: 1, 12: 0, 13: 1, 14: 1 }),
    [join(repo, 'src/new.ts')]: entry({
      1: newHit,
      2: newHit,
      3: newHit,
      4: newHit,
      5: newHit,
    }),
    [join(repo, 'src/r2.ts')]: entry({ 2: r2Hit }),
  });
const side = (path: string, startLine: number, endLine: number) => ({
  path,
  startLine,
  endLine,
});
const jscpd = (clones: ReturnType<typeof side>[][]): EngineResult => ({
  engine: 'jscpd',
  status: 'completed',
  findings: jscpdFindings(
    clones.map(([first, second]) => ({
      format: 'typescript',
      lines: 4,
      tokens: 60,
      first: first,
      second: second,
    })),
  ),
});
const base0 = {
  git,
  repo,
  headSha: head,
  env: {},
  readEvent: () => Promise.reject(new Error('no event')),
  baseRef: base,
  tracked,
};
const measure = (m: Awaited<ReturnType<typeof computeNewCode>>, id: string) =>
  m.measures.find((x) => x.id === id)!;

await test('diff: changed lines per file match the fixture exactly', async () => {
  const diff = await changedLinesDiff(git, repo, base, head);
  assert.ok(diff);
  const byPath = Object.fromEntries(diff.files.map((f) => [f.path, f]));
  assert.deepEqual(byPath['src/a.ts']?.lines, [3, 11, 12, 13, 14]);
  assert.deepEqual(byPath['src/new.ts']?.lines, [1, 2, 3, 4, 5]);
  assert.equal(byPath['src/new.ts']?.status, 'added');
  assert.equal(byPath['src/old.ts']?.status, 'deleted');
  assert.deepEqual(byPath['src/old.ts']?.lines, []);
  assert.equal(byPath['src/r2.ts']?.status, 'renamed');
  assert.equal(byPath['src/r2.ts']?.oldPath, 'src/r.ts');
  assert.deepEqual(byPath['src/r2.ts']?.lines, [2]);
});

await test('diff parser refuses quoted paths instead of guessing', () => {
  assert.throws(() =>
    parseChangedLines('diff --git "a/x" "b/x"\n+++ "b/x\\n"\n@@ -0,0 +1 @@\n'),
  );
});

await test('coverage: a known percentage passes and a low one fails the 80% threshold', async () => {
  const pass = await computeNewCode({
    ...base0,
    coverageReport: coverageFinal(),
    jscpd: jscpd([]),
  });
  const lines = measure(pass, 'coverage.lines');
  assert.equal(lines.state, 'known');
  assert.ok(lines.state === 'known');
  assert.equal(lines.numerator, 10);
  assert.equal(lines.denominator, 11);
  const fail = await computeNewCode({
    ...base0,
    coverageReport: coverageFinal(0, 0),
    jscpd: jscpd([]),
  });
  const low = measure(fail, 'coverage.lines');
  assert.ok(low.state === 'known');
  assert.equal(low.numerator, 4);
  assert.equal(low.denominator, 11);
  assert.ok(low.percent < 80);
});

await test('coverage: no report, a json-summary report and an unreadable one are unknown', async () => {
  const none = await computeNewCode({ ...base0, jscpd: jscpd([]) });
  assert.deepEqual(measure(none, 'coverage.lines'), {
    id: 'coverage.lines',
    scope: 'new-code',
    state: 'unknown',
    reason: 'no-report',
  });
  const summary = await computeNewCode({
    ...base0,
    jscpd: jscpd([]),
    coverageReport: JSON.stringify({
      total: {
        lines: { total: 1, covered: 1, skipped: 0, pct: 100 },
        statements: { total: 1, covered: 1, skipped: 0, pct: 100 },
        functions: { total: 0, covered: 0, skipped: 0, pct: 100 },
        branches: { total: 0, covered: 0, skipped: 0, pct: 100 },
      },
      [join(repo, 'src/a.ts')]: {
        lines: { total: 1, covered: 1 },
        branches: { total: 0, covered: 0 },
      },
    }),
  });
  assert.equal(measure(summary, 'coverage.lines').state, 'unknown');
  const junk = await computeNewCode({
    ...base0,
    jscpd: jscpd([]),
    coverageReport: 'not json',
  });
  assert.equal(measure(junk, 'coverage.lines').state, 'unknown');
  // A report that omits a changed file never yields a percentage.
  const missing = await computeNewCode({
    ...base0,
    jscpd: jscpd([]),
    coverageReport: JSON.stringify({
      [join(repo, 'src/a.ts')]: entry({ 3: 1 }),
    }),
  });
  assert.deepEqual(
    [
      measure(missing, 'coverage.lines').state,
      (measure(missing, 'coverage.lines') as { reason?: string }).reason,
    ],
    ['unknown', 'changed-file-not-in-report'],
  );
});

await test('duplication: no clones is 0% over the changed source lines; clones raise it above the 3% limit', async () => {
  const clean = measure(
    await computeNewCode({ ...base0, jscpd: jscpd([]) }),
    'duplication.lines',
  );
  assert.ok(clean.state === 'known');
  assert.equal(clean.percent, 0);
  assert.equal(clean.denominator, 11);
  const dup = measure(
    await computeNewCode({
      ...base0,
      jscpd: jscpd([[side('src/a.ts', 11, 14), side('src/new.ts', 1, 4)]]),
    }),
    'duplication.lines',
  );
  assert.ok(dup.state === 'known');
  assert.equal(dup.numerator, 8);
  assert.equal(dup.denominator, 11);
  assert.ok(dup.percent > 3);
});

await test('duplication: a skipped or failed jscpd is unknown, never 0%', async () => {
  for (const jscpdResult of [
    undefined,
    {
      engine: 'jscpd',
      status: 'failed',
      reason: 'x',
      findings: [],
    } as EngineResult,
  ]) {
    const m = measure(
      await computeNewCode({
        ...base0,
        ...(jscpdResult ? { jscpd: jscpdResult } : {}),
      }),
      'duplication.lines',
    );
    assert.equal(m.state, 'unknown');
  }
});

await test('base selection: pushes need a base ref; pull requests use their event base and ignore it', async () => {
  const noBase = await computeNewCode({
    ...base0,
    baseRef: undefined,
    jscpd: jscpd([]),
  });
  assert.equal(noBase.baseSource, 'none');
  assert.equal(noBase.baseSha, null);
  assert.deepEqual(
    noBase.measures.map((m) => (m.state === 'unknown' ? m.reason : 'known')),
    ['no-report', 'no-report', 'no-base-ref'],
  );
  const badRef = await computeNewCode({
    ...base0,
    baseRef: 'does-not-exist',
    jscpd: jscpd([]),
  });
  assert.equal(measure(badRef, 'duplication.lines').state, 'unknown');
  const option = await computeNewCode({
    ...base0,
    baseRef: '--output=x',
    jscpd: jscpd([]),
  });
  assert.equal(option.baseSha, null);
  const sameCommit = await computeNewCode({
    ...base0,
    baseRef: head,
    jscpd: jscpd([]),
  });
  assert.equal(measure(sameCommit, 'duplication.lines').state, 'unknown');

  const pr = await computeNewCode({
    ...base0,
    baseRef: head, // would be unknown if used; the PR base wins
    env: { GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: 'event.json' },
    readEvent: () =>
      Promise.resolve(
        JSON.stringify({ pull_request: { base: { sha: base } } }),
      ),
    jscpd: jscpd([]),
  });
  assert.equal(pr.baseSource, 'pull-request-base');
  assert.equal(pr.baseSha, base);
  assert.equal(measure(pr, 'duplication.lines').state, 'known');
  const noEventBase = await computeNewCode({
    ...base0,
    env: { GITHUB_EVENT_NAME: 'pull_request' },
    readEvent: () => Promise.resolve('{}'),
    jscpd: jscpd([]),
  });
  assert.equal(noEventBase.baseSha, null);
  assert.equal(measure(noEventBase, 'duplication.lines').state, 'unknown');
});

await test('CLI: --base-ref and --coverage reach report.json, summary.md and the manifest', () => {
  const out = join(repo, '..', `new-code-out-${process.pid}`);
  process.on('exit', () => rmSync(out, { recursive: true, force: true }));
  const coverage = join(out, '..', `cov-${process.pid}.json`);
  process.on('exit', () => rmSync(coverage, { force: true }));
  writeFileSync(coverage, coverageFinal());
  const env = {
    PATH: process.env.PATH ?? '',
    CODE_QUALITY_GIT_EXECUTABLE: git,
  };
  const cli = join(import.meta.dirname, '..', 'src', 'quality-scan-cli.js');
  const result = spawnSync(
    process.execPath,
    [
      cli,
      'run',
      '--repo',
      repo,
      '--out',
      out,
      '--scanners',
      'eslint',
      '--base-ref',
      base,
      '--coverage',
      coverage,
    ],
    { encoding: 'utf8', env },
  );
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')) as {
    newCode: {
      baseSha: string;
      measures: { id: string; state: string; denominator?: number }[];
    };
  };
  assert.equal(report.newCode.baseSha, base);
  const lines = report.newCode.measures.find((m) => m.id === 'coverage.lines');
  assert.equal(lines?.state, 'known');
  assert.equal(lines?.denominator, 11);
  const summary = readFileSync(join(out, 'summary.md'), 'utf8');
  assert.match(summary, /### New-code measures/);
  assert.match(summary, /coverage\.lines \| 90\.91% \| 10\/11/);
  assert.match(summary, /duplication\.lines \| unknown/);
  const bad = spawnSync(
    process.execPath,
    [
      cli,
      'run',
      '--repo',
      repo,
      '--out',
      out,
      '--scanners',
      'eslint',
      '--coverage',
      join(out, 'missing.json'),
    ],
    { encoding: 'utf8', env },
  );
  assert.equal(bad.status, 2);
});

await test('manifest carries the new-code measures, and null when none were computed', () => {
  const environment = {
    GITHUB_REPOSITORY: 'acme/widgets',
    GITHUB_SHA: head,
    GITHUB_REF: 'refs/heads/main',
    GITHUB_EVENT_NAME: 'push',
    GITHUB_RUN_ID: '1',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_WORKFLOW_REF: 'acme/widgets/.github/workflows/q.yml@refs/heads/main',
  };
  const input = {
    commitSha: head,
    codeQualityRef: base,
    results: [],
    envelopeFiles: new Map<string, string>(),
  };
  assert.equal(buildManifest(environment, input).measures, null);
  const m = buildManifest(environment, {
    ...input,
    measures: [
      {
        id: 'coverage.lines',
        state: 'known',
        percent: 90,
        numerator: 9,
        denominator: 10,
      },
      { id: 'duplication.lines', state: 'unknown', reason: 'no-report' },
    ],
  }).measures;
  assert.deepEqual(m?.[0], {
    id: 'coverage.lines',
    state: 'known',
    percent: 90,
    numerator: 9,
    denominator: 10,
    reason: null,
  });
  assert.equal(m?.[1]?.reason, 'no-report');
});
