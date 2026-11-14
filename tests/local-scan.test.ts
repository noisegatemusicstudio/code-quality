/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Runs the real quality-scan CLI (bundled ESLint engine only) against a throwaway git repository to prove local-mode manifest identity, its equality with the GitHub Actions manifest, flag validation and refusal rules, and that the Actions path is unchanged; runs no other scanner, no project tests and no network, and does not exercise the Dev runner itself.
*/
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { systemGit } from '../src/system-git.js';

const git = systemGit(
  process.platform,
  process.env.CODE_QUALITY_GIT_EXECUTABLE,
);
const root = mkdtempSync(join(tmpdir(), 'local-scan-'));
process.on('exit', () => {
  rmSync(root, { recursive: true, force: true });
});
const repo = join(root, 'repo');
const g = (...args: string[]): string =>
  execFileSync(git, ['-C', repo, ...args], { encoding: 'utf8' }).trim();
execFileSync(git, ['init', '-q', '-b', 'main', repo]);
g('config', 'user.email', 'fixture@example.invalid');
g('config', 'user.name', 'Fixture');
g('config', 'commit.gpgsign', 'false');
writeFileSync(join(repo, 'a.ts'), 'export const a = 1;\n');
g('add', '-A');
g('commit', '-q', '-m', 'base');
const head = g('rev-parse', 'HEAD');
const cqRef = 'c'.repeat(40);

const cli = join(import.meta.dirname, '..', 'src', 'quality-scan-cli.js');
let counter = 0;
const scan = (
  extra: string[],
  env: Record<string, string> = {},
): { status: number | null; stderr: string; out: string } => {
  counter += 1;
  const out = join(root, `out-${String(counter)}`);
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
      '--code-quality-ref',
      cqRef,
      ...extra,
    ],
    {
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH ?? '',
        CODE_QUALITY_GIT_EXECUTABLE: git,
        ...env,
      },
    },
  );
  return { status: result.status, stderr: result.stderr, out };
};
const manifestOf = (out: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as Record<
    string,
    unknown
  >;

const localFlags = [
  '--manifest',
  'local',
  '--repository',
  'acme/widgets',
  '--ref',
  'refs/heads/feature/x',
  '--event',
  'push',
  '--run-id',
  '123456789',
  '--run-attempt',
  '2',
];
const actionsEnv = {
  GITHUB_ACTIONS: 'true',
  GITHUB_REPOSITORY: 'acme/widgets',
  GITHUB_SHA: head,
  GITHUB_REF: 'refs/heads/feature/x',
  GITHUB_EVENT_NAME: 'push',
  GITHUB_RUN_ID: '123456789',
  GITHUB_RUN_ATTEMPT: '2',
  GITHUB_WORKFLOW_REF:
    'acme/widgets/.github/workflows/quality.yml@refs/heads/feature/x',
};
/** Replace one flag's value in localFlags. */
const withFlag = (name: string, value: string | undefined): string[] => {
  const flags = [...localFlags];
  const at = flags.indexOf(name);
  if (value === undefined) flags.splice(at, 2);
  else flags[at + 1] = value;
  return flags;
};

await test('local mode writes a manifest with the flag identity, the git HEAD and a fixed local workflowRef', () => {
  const r = scan(localFlags);
  assert.equal(r.status, 0, r.stderr);
  const m = manifestOf(r.out);
  assert.equal(m.schemaVersion, 1);
  assert.equal(m.repository, 'acme/widgets');
  assert.equal(m.commitSha, head);
  assert.equal(m.ref, 'refs/heads/feature/x');
  assert.equal(m.event, 'push');
  assert.equal(m.pullRequest, null);
  assert.equal(m.runId, 123456789);
  assert.equal(m.runAttempt, 2);
  assert.equal(m.workflowRef, 'local:releaseready-dev');
  assert.equal(m.codeQualityRef, cqRef);
  const report = JSON.parse(
    readFileSync(join(r.out, 'report.json'), 'utf8'),
  ) as { repository: string };
  assert.equal(report.repository, 'acme/widgets');
});

await test('local mode envelopes name the scanned repository and each manifest version equals its envelope engine.version', () => {
  // The scan environment carries no GITHUB_REPOSITORY, so only --repository can name it.
  const r = scan(localFlags);
  assert.equal(r.status, 0, r.stderr);
  const engines = manifestOf(r.out).engines as {
    id: string;
    version: string | null;
    envelope: string | null;
  }[];
  assert.ok(engines.some((e) => e.envelope !== null));
  for (const entry of engines) {
    if (entry.envelope === null) continue;
    const envelope = JSON.parse(
      readFileSync(join(r.out, entry.envelope), 'utf8'),
    ) as { repository: string; engine: { id: string; version: string } };
    assert.equal(envelope.repository, 'acme/widgets', entry.id);
    assert.equal(entry.version, envelope.engine.version, entry.id);
    assert.notEqual(entry.version, 'bundled', entry.id);
  }
});

await test('local manifest equals the env-mode manifest for the same identity, except workflowRef', () => {
  const local = manifestOf(scan(localFlags).out);
  const env = scan([], actionsEnv);
  assert.equal(env.status, 0, env.stderr);
  const actions = manifestOf(env.out);
  assert.notEqual(local.workflowRef, actions.workflowRef);
  assert.deepEqual(
    { ...local, workflowRef: 'x' },
    { ...actions, workflowRef: 'x' },
  );
  assert.deepEqual(Object.keys(local), Object.keys(actions));
});

await test('local pull_request identity derives the PR number and run-attempt defaults to 1', () => {
  const r = scan(
    withFlag('--run-attempt', undefined).map((v) =>
      v === 'refs/heads/feature/x'
        ? 'refs/pull/42/merge'
        : v === 'push'
          ? 'pull_request'
          : v,
    ),
  );
  assert.equal(r.status, 0, r.stderr);
  const m = manifestOf(r.out);
  assert.equal(m.pullRequest, 42);
  assert.equal(m.event, 'pull_request');
  assert.equal(m.runAttempt, 1);
});

await test('the commit SHA comes from git, never from a flag', () => {
  const r = scan([...localFlags, '--commit-sha', 'f'.repeat(40)]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(manifestOf(r.out).commitSha, head);
});

await test('each invalid or missing local flag is rejected with exit 2 and no manifest', () => {
  const cases: [string, string | undefined][] = [
    ['--repository', 'no-slash'],
    ['--repository', undefined],
    ['--ref', 'refs/pull/1/merge'],
    ['--ref', 'feature/x'],
    ['--ref', 'refs/heads/x y'],
    ['--ref', undefined],
    ['--event', 'workflow_dispatch'],
    ['--event', undefined],
    ['--run-id', '0'],
    ['--run-id', '12a'],
    ['--run-id', undefined],
    ['--run-attempt', ''],
    ['--run-attempt', '0'],
    ['--run-attempt', '-1'],
    ['--run-attempt', '1.5'],
  ];
  for (const [flag, value] of cases) {
    const r = scan(withFlag(flag, value));
    const label = `${flag}=${String(value)}`;
    assert.equal(r.status, 2, label);
    assert.match(r.stderr, /invalid input: .*(flag|--)/i, label);
    assert.equal(existsSync(join(r.out, 'manifest.json')), false, label);
  }
  const mismatch = scan(
    withFlag('--event', 'pull_request'), // heads ref with a pull_request event
  );
  assert.equal(mismatch.status, 2);
  const pushPull = scan(withFlag('--ref', 'refs/pull/7/merge'));
  assert.equal(pushPull.status, 2);
});

await test('local identity flags without --manifest local are refused, not ignored', () => {
  for (const flag of [
    '--repository',
    '--ref',
    '--event',
    '--run-id',
    '--run-attempt',
  ]) {
    const value = localFlags[localFlags.indexOf(flag) + 1] ?? '';
    const r = scan([flag, value]);
    assert.equal(r.status, 2, flag);
    assert.match(r.stderr, /requires --manifest local/, flag);
  }
  const wrong = scan(['--manifest', 'github']);
  assert.equal(wrong.status, 2);
  assert.match(wrong.stderr, /--manifest must be local/);
  const bare = scan(['--manifest']);
  assert.equal(bare.status, 2);
});

await test('local mode is refused on GitHub Actions', () => {
  const r = scan(localFlags, { GITHUB_ACTIONS: 'true' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /cannot be used on GitHub Actions/);
  assert.equal(existsSync(join(r.out, 'manifest.json')), false);
});

await test('without --manifest local and outside Actions no manifest is written', () => {
  const r = scan([]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(existsSync(join(r.out, 'manifest.json')), false);
  assert.equal(existsSync(join(r.out, 'report.json')), true);
});

await test('Actions path is unchanged: env identity, env workflowRef, and the local workflowRef is not accepted from env', () => {
  const ok = scan([], actionsEnv);
  assert.equal(ok.status, 0, ok.stderr);
  const m = manifestOf(ok.out);
  assert.equal(m.workflowRef, actionsEnv.GITHUB_WORKFLOW_REF);
  assert.equal(m.runAttempt, 2);
  const forged = scan([], {
    ...actionsEnv,
    GITHUB_WORKFLOW_REF: 'local:releaseready-dev',
  });
  assert.equal(forged.status, 2);
  assert.match(
    forged.stderr,
    /manifest invalid: GITHUB_WORKFLOW_REF is missing or malformed/,
  );
  const missing = scan([], { ...actionsEnv, GITHUB_RUN_ID: '0' });
  assert.equal(missing.status, 2);
  assert.match(
    missing.stderr,
    /manifest invalid: GITHUB_RUN_ID is missing or malformed/,
  );
});

await test('a manual workflow_dispatch run on Actions writes no manifest and reports the gate result, while other events stay strict', () => {
  const manual = scan([], {
    ...actionsEnv,
    GITHUB_EVENT_NAME: 'workflow_dispatch',
  });
  assert.equal(manual.status, 0, manual.stderr);
  assert.equal(existsSync(join(manual.out, 'manifest.json')), false);
  assert.match(manual.stderr, /manifest skipped: manual workflow_dispatch run/);
  // The evidence is still produced; only the portal manifest is skipped.
  assert.equal(existsSync(join(manual.out, 'report.json')), true);
  assert.equal(existsSync(join(manual.out, 'summary.md')), true);
  // Only workflow_dispatch is exempt: every other unsupported event still fails.
  for (const event of ['schedule', 'release']) {
    const r = scan([], { ...actionsEnv, GITHUB_EVENT_NAME: event });
    assert.equal(r.status, 2, event);
    assert.match(r.stderr, /GITHUB_EVENT_NAME must be push or pull_request/);
    assert.equal(existsSync(join(r.out, 'manifest.json')), false, event);
  }
});
