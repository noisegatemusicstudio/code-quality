/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves the ShellCheck, shfmt, actionlint and zizmor parsers, argument contracts, exit-code handling, sha256 refusal, severity mapping, batching and pins by running fake executables through runAdapter on synthetic bad and clean scripts and workflows; does not run, download or install any real engine.
*/
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { EnvelopeScope } from '../src/adapter-envelope.js';
import {
  type LintEngineId,
  lintAdapter,
  lintBatchSize,
  lintEngines,
  parseActionlintReport,
  parseShellcheckReport,
  parseShfmtDiff,
  parseZizmorReport,
  pinnedVersionOutput,
  planBatches,
} from '../src/lint-engines.js';
import { detectApplicability, normaliseSeverity } from '../src/quality-scan.js';
import { runAdapter } from '../src/scanner-adapter.js';
import { lintPins, releaseAssets } from '../src/scanner-pins.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'c'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const linux = { skip: process.platform !== 'linux' };
const dir = await mkdtemp(join(tmpdir(), 'lint-engines-test-'));
const sha = (text: string) => createHash('sha256').update(text).digest('hex');

// Synthetic fixtures: a bad and a clean script, a bad and a clean workflow.
const badScript = 'for f in $(ls); do echo $f; done\n';
const cleanScript = '#!/bin/sh\nset -eu\nprintf "%s\\n" "ok"\n';
const badWorkflow =
  'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n';
const cleanWorkflow =
  'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n';

const shellcheckBad = JSON.stringify({
  comments: [
    {
      file: 'bad.sh',
      line: 1,
      endLine: 1,
      column: 10,
      endColumn: 15,
      level: 'error',
      code: 2045,
      message: 'Iterating over ls output is fragile.',
    },
    {
      file: 'bad.sh',
      line: 1,
      endLine: 1,
      column: 31,
      endColumn: 33,
      level: 'style',
      code: 2086,
      message: 'Double quote to prevent globbing.',
    },
  ],
});
const shfmtBad = [
  'diff -u bad.sh.orig bad.sh',
  '--- bad.sh.orig',
  '+++ bad.sh',
  '@@ -1,2 +1,3 @@',
  '-for f in $(ls); do echo $f; done',
  '+for f in $(ls); do',
  '+  echo $f',
  '+done',
  '',
].join('\n');
const actionlintBad = JSON.stringify([
  {
    message: 'property "x" is not defined in object type {}',
    filepath: '.github/workflows/bad.yml',
    line: 6,
    column: 19,
    kind: 'expression',
    snippet: '',
    end_column: 30,
  },
]);
const zizmorBad = JSON.stringify([
  {
    ident: 'template-injection',
    desc: 'code injection via template expansion',
    determinations: { confidence: 'High', severity: 'High' },
    locations: [
      {
        symbolic: {
          key: {
            Local: { verbatim_path: './.github/workflows/bad.yml' },
          },
          kind: 'Primary',
        },
        concrete: {
          location: {
            start_point: { row: 5, column: 14 },
            end_point: { row: 5, column: 45 },
          },
        },
      },
    ],
    ignored: false,
  },
  {
    ident: 'excessive-permissions',
    desc: 'ignored one',
    determinations: { confidence: 'High', severity: 'Medium' },
    locations: [],
    ignored: true,
  },
]);

/** A fake engine: prints its version, or the canned report, and records how it was called. */
async function fake(
  name: string,
  options: {
    version: string;
    stdout: string;
    exit: number;
    record?: string;
  },
) {
  const path = join(dir, name);
  const source = `#!${process.execPath}
const a = process.argv.slice(2);
if (a.length === 1 && (a[0] === '--version' || a[0] === '-version')) { process.stdout.write(${JSON.stringify(options.version)}); process.exit(0); }
${options.record ? `require('node:fs').writeFileSync(${JSON.stringify(options.record)}, JSON.stringify({ args: a, token: process.env.GITHUB_TOKEN ?? null, gh: process.env.GH_TOKEN ?? null }));` : ''}
process.stdout.write(${JSON.stringify(options.stdout)});
process.exit(${String(options.exit)});
`;
  await writeFile(path, source);
  await chmod(path, 0o755);
  return { path, sha256: sha(source) };
}
async function runFake(
  id: LintEngineId,
  options: Parameters<typeof fake>[1],
  files: Record<string, string>,
) {
  const engine = await fake(`${id}-${String(Math.random())}`, options);
  const spec = lintEngines[id];
  const batch = Object.keys(files);
  return runAdapter(
    lintAdapter(
      spec,
      engine.path,
      options.version.trim(),
      batch,
      engine.sha256,
    ),
    { scope, files, args: batch },
  );
}

await test(
  'shellcheck: findings keep native levels and codes; clean input is clean',
  linux,
  async () => {
    const bad = await runFake(
      'shellcheck',
      {
        version: 'ShellCheck\nversion: 0.11.0',
        stdout: shellcheckBad,
        exit: 1,
      },
      { 'bad.sh': badScript },
    );
    assert.equal(bad.status, 'completed');
    assert.deepEqual(
      bad.findings.map((f) => [
        f.ruleId,
        f.nativeSeverity,
        f.path,
        f.range.startLine,
      ]),
      [
        ['SC2045', 'error', 'bad.sh', 1],
        ['SC2086', 'style', 'bad.sh', 1],
      ],
    );
    const clean = await runFake(
      'shellcheck',
      {
        version: 'ShellCheck\nversion: 0.11.0',
        stdout: '{"comments":[]}',
        exit: 0,
      },
      { 'clean.sh': cleanScript },
    );
    assert.equal(clean.status, 'completed');
    assert.equal(clean.findings.length, 0);
  },
);

await test(
  'shfmt: diff hunks become findings and the engine is only ever called in diff mode',
  linux,
  async () => {
    const record = join(dir, 'shfmt-args.json');
    const bad = await runFake(
      'shfmt',
      { version: 'v3.14.1', stdout: shfmtBad, exit: 1, record },
      { 'bad.sh': badScript },
    );
    assert.equal(bad.status, 'completed');
    assert.equal(bad.findings.length, 1);
    assert.equal(bad.findings[0]?.ruleId, 'shfmt/format');
    assert.equal(bad.findings[0]?.range.startLine, 1);
    assert.equal(bad.findings[0]?.range.endLine, 2);
    const { readFile } = await import('node:fs/promises');
    const args = (
      JSON.parse(await readFile(record, 'utf8')) as { args: string[] }
    ).args;
    assert.deepEqual(args, ['-d', '-i', '2', '-ci', '--', 'bad.sh']);
    for (const writing of ['-w', '-l', '-s', '--write'])
      assert.ok(!args.includes(writing), writing);
    const clean = await runFake(
      'shfmt',
      { version: 'v3.14.1', stdout: '', exit: 0 },
      { 'clean.sh': cleanScript },
    );
    assert.equal(clean.status, 'completed');
    assert.equal(clean.findings.length, 0);
  },
);

await test(
  'actionlint: reports kind as rule; empty and null output are clean',
  linux,
  async () => {
    const bad = await runFake(
      'actionlint',
      { version: '1.7.12\nbuilt with go', stdout: actionlintBad, exit: 1 },
      { '.github/workflows/bad.yml': badWorkflow },
    );
    assert.equal(bad.status, 'completed');
    assert.equal(bad.findings[0]?.ruleId, 'actionlint/expression');
    assert.equal(bad.findings[0]?.range.startLine, 6);
    for (const stdout of ['', 'null']) {
      const clean = await runFake(
        'actionlint',
        { version: '1.7.12\nbuilt with go', stdout, exit: 0 },
        { '.github/workflows/ok.yml': cleanWorkflow },
      );
      assert.equal(clean.status, 'completed', stdout);
      assert.equal(clean.findings.length, 0, stdout);
    }
  },
);

await test(
  'zizmor: native severity kept, ignored findings dropped, offline and tokenless',
  linux,
  async () => {
    const record = join(dir, 'zizmor-call.json');
    process.env.GITHUB_TOKEN = 'ghp_should_not_reach_engine';
    process.env.GH_TOKEN = 'ghp_should_not_reach_engine';
    try {
      const bad = await runFake(
        'zizmor',
        { version: 'zizmor 1.32.0', stdout: zizmorBad, exit: 14, record },
        { '.github/workflows/bad.yml': badWorkflow },
      );
      assert.equal(bad.status, 'completed');
      assert.equal(bad.findings.length, 1);
      assert.equal(bad.findings[0]?.ruleId, 'zizmor/template-injection');
      assert.equal(bad.findings[0]?.nativeSeverity, 'High');
      assert.equal(bad.findings[0]?.range.startLine, 6);
      const { readFile } = await import('node:fs/promises');
      const call = JSON.parse(await readFile(record, 'utf8')) as {
        args: string[];
        token: string | null;
        gh: string | null;
      };
      assert.ok(call.args.includes('--offline'));
      assert.equal(call.token, null);
      assert.equal(call.gh, null);
    } finally {
      delete process.env.GITHUB_TOKEN;
      delete process.env.GH_TOKEN;
    }
    const clean = await runFake(
      'zizmor',
      { version: 'zizmor 1.32.0', stdout: '[]', exit: 0 },
      { '.github/workflows/ok.yml': cleanWorkflow },
    );
    assert.equal(clean.status, 'completed');
    assert.equal(clean.findings.length, 0);
  },
);

await test(
  'unexpected exit codes and unusable output fail instead of reading as clean',
  linux,
  async () => {
    // zizmor exit 1 is an engine error, not "findings".
    const crashed = await runFake(
      'zizmor',
      { version: 'zizmor 1.32.0', stdout: '[]', exit: 1 },
      { '.github/workflows/ok.yml': cleanWorkflow },
    );
    assert.equal(crashed.status, 'failed');
    assert.equal(crashed.reason, 'engine-error');
    const shfmtCrash = await runFake(
      'shfmt',
      { version: 'v3.14.1', stdout: '', exit: 2 },
      { 'a.sh': cleanScript },
    );
    assert.equal(shfmtCrash.status, 'failed');
    const garbage = await runFake(
      'shellcheck',
      { version: 'ShellCheck\nversion: 0.11.0', stdout: 'not json', exit: 1 },
      { 'a.sh': badScript },
    );
    assert.equal(garbage.status, 'failed');
    assert.equal(garbage.reason, 'invalid-output');
  },
);

await test(
  'an executable that does not match the sha256 is refused before running',
  linux,
  async () => {
    const engine = await fake('wrong-sha', {
      version: 'v3.14.1',
      stdout: '',
      exit: 0,
    });
    const envelope = await runAdapter(
      lintAdapter(
        lintEngines.shfmt,
        engine.path,
        'v3.14.1',
        ['a.sh'],
        lintPins.shfmt.sha256,
      ),
      { scope, files: { 'a.sh': cleanScript }, args: ['a.sh'] },
    );
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
  },
);

await test('arguments outside the batch are rejected', linux, async () => {
  const engine = await fake('args', {
    version: 'v3.14.1',
    stdout: '',
    exit: 0,
  });
  const envelope = await runAdapter(
    lintAdapter(
      lintEngines.shfmt,
      engine.path,
      'v3.14.1',
      ['a.sh'],
      engine.sha256,
    ),
    { scope, files: { 'a.sh': cleanScript }, args: ['-w', 'a.sh'] },
  );
  assert.equal(envelope.status, 'skipped');
  assert.equal(envelope.reason, 'invalid-request');
});

await test('pinnedVersionOutput requires the pinned version as a whole token', async () => {
  const ok = await fake('ver-ok', {
    version: 'ShellCheck\nversion: 0.11.0\n',
    stdout: '',
    exit: 0,
  });
  assert.equal(
    await pinnedVersionOutput(ok.path, ['--version'], '0.11.0'),
    'ShellCheck\nversion: 0.11.0',
  );
  const other = await fake('ver-bad', {
    version: 'version: 0.11.01',
    stdout: '',
    exit: 0,
  });
  await assert.rejects(
    pinnedVersionOutput(other.path, ['--version'], '0.11.0'),
  );
  const newer = await fake('ver-newer', {
    version: 'v10.11.0',
    stdout: '',
    exit: 0,
  });
  await assert.rejects(
    pinnedVersionOutput(newer.path, ['--version'], '0.11.0'),
  );
});

await test('parsers reject malformed entries rather than guessing', () => {
  assert.equal(parseShellcheckReport('{"comments":"x"}'), undefined);
  const partial = parseShellcheckReport(
    JSON.stringify({
      comments: [{ file: '../etc/passwd', line: 1, level: 'error', code: 1 }],
    }),
  );
  assert.equal(partial?.partial, 'invalid-output');
  assert.equal(partial?.findings.length, 0);
  assert.equal(parseActionlintReport('{}'), undefined);
  assert.equal(parseZizmorReport('{}'), undefined);
  assert.equal(parseShfmtDiff('').findings.length, 0);
  assert.equal(parseShfmtDiff('@@ -1 +1 @@\n').partial, 'invalid-output');
});

await test('severity: ShellCheck levels map through the gate table; zizmor stays native', () => {
  const map = (
    engine: Parameters<typeof normaliseSeverity>[0],
    label: string,
  ) => normaliseSeverity(engine, label);
  assert.equal(map('shellcheck', 'error'), 'high');
  assert.equal(map('shellcheck', 'warning'), 'medium');
  assert.equal(map('shellcheck', 'info'), 'low');
  assert.equal(map('shellcheck', 'style'), 'info');
  assert.equal(map('shellcheck', 'mystery'), 'high');
  assert.equal(map('shfmt', 'format'), 'info');
  assert.equal(map('actionlint', 'error'), 'medium');
  assert.equal(map('zizmor', 'High'), 'high');
  assert.equal(map('zizmor', 'Medium'), 'medium');
  assert.equal(map('zizmor', 'Low'), 'low');
  assert.equal(map('zizmor', 'Informational'), 'info');
  assert.equal(map('zizmor', 'Unknown'), 'high');
});

await test('applicability: engines run only when their files are tracked', () => {
  const none = detectApplicability(['src/a.ts']);
  for (const id of ['shellcheck', 'shfmt', 'actionlint', 'zizmor'] as const)
    assert.equal(none[id].applicable, false, id);
  const some = detectApplicability([
    'bin/run.sh',
    '.github/workflows/ci.yml',
    'docs/workflows/not-a-workflow.yml',
  ]);
  for (const id of ['shellcheck', 'shfmt', 'actionlint', 'zizmor'] as const)
    assert.equal(some[id].applicable, true, id);
  assert.equal(
    detectApplicability(['docs/workflows/x.yml']).actionlint.applicable,
    false,
  );
});

await test('batches respect the adapter argument limit and drop unusable names', () => {
  const paths = Array.from(
    { length: lintBatchSize * 2 + 1 },
    (_, i) => `s${String(i)}.sh`,
  );
  const plan = planBatches([...paths, '-rf.sh', `${'a'.repeat(300)}.sh`]);
  assert.equal(plan.batches.length, 3);
  assert.ok(plan.batches.every((b) => b.length <= lintBatchSize));
  assert.deepEqual(plan.unusable, ['-rf.sh', `${'a'.repeat(300)}.sh`]);
});

await test('pins: release assets agree with the engine pins and official versions', () => {
  for (const id of ['shellcheck', 'shfmt', 'actionlint', 'zizmor'] as const) {
    assert.match(lintPins[id].sha256, /^[a-f0-9]{64}$/, id);
    assert.equal(releaseAssets[id].binarySha256, lintPins[id].sha256, id);
    assert.match(releaseAssets[id].assetSha256, /^[a-f0-9]{64}$/, id);
    assert.ok(releaseAssets[id].url.startsWith('https://github.com/'), id);
    assert.ok(releaseAssets[id].url.includes(lintPins[id].version), id);
  }
  assert.equal(lintPins.shellcheck.license, 'GPL-3.0');
  // actionlint publishes checksums: the asset digest is the upstream one.
  assert.equal(
    releaseAssets.actionlint.assetSha256,
    '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',
  );
});

await test('cleanup', async () => {
  await rm(dir, { recursive: true, force: true });
});
