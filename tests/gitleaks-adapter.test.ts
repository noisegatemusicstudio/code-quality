import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { type EnvelopeScope } from '../src/adapter-envelope.js';
import {
  type GitleaksException,
  classifyGitleaksEnvelope,
  createGitleaksAdapter,
  gitleaksVersion,
  parseGitleaksReport,
} from '../src/gitleaks-adapter.js';
import { runAdapter } from '../src/scanner-adapter.js';

// Synthetic values only (AWS documentation example key and made-up tokens).
const dummySecrets = [
  'AKIAIOSFODNN7EXAMPLE',
  'dummy-token-0123456789abcdef-not-real',
];
const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'b'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const record = (over: Record<string, unknown> = {}) => ({
  RuleID: 'aws-access-token',
  Description: 'AWS Access Key',
  StartLine: 3,
  EndLine: 3,
  StartColumn: 12,
  EndColumn: 31,
  Match: 'key = REDACTED',
  Secret: 'REDACTED',
  File: 'src/config.ts',
  Commit: '',
  Fingerprint: 'src/config.ts:aws-access-token:3',
  ...over,
});
const report = (...items: unknown[]) => JSON.stringify(items);

const fakeSource = `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === 'version') { console.log('${gitleaksVersion}'); process.exit(0); }
const mode = fs.readFileSync('mode.txt', 'utf8').trim();
const secrets = ${JSON.stringify(dummySecrets)};
console.error('log line leaking ' + secrets[0]);
if (mode === 'leaks') {
  console.log(JSON.stringify([
    { RuleID: 'aws-access-token', StartLine: 3, EndLine: 3, StartColumn: 12, EndColumn: 31, Match: 'key = REDACTED', Secret: 'REDACTED', File: './src/config.ts' },
    { RuleID: 'generic-api-key', StartLine: 9, EndLine: 9, StartColumn: 1, EndColumn: 40, Match: 'REDACTED', Secret: 'REDACTED', File: 'src/config.ts' },
  ]));
  process.exit(2);
}
if (mode === 'clean') { console.log('[]'); process.exit(0); }
if (mode === 'unredacted') {
  console.log(JSON.stringify([{ RuleID: 'aws-access-token', StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 5, Secret: secrets[0], Match: secrets[0], File: 'a.txt' }]));
  process.exit(2);
}
if (mode === 'crash') { console.log(secrets[1]); process.exit(1); }
console.log('not json ' + secrets[1]);
process.exit(0);
`;
const dir = await mkdtemp(join(tmpdir(), 'gitleaks-test-'));
const executable = join(dir, 'fake-gitleaks');
await writeFile(executable, fakeSource);
await chmod(executable, 0o755);
const base = {
  executable,
  configPath: join(dir, 'reviewed.toml'),
  ignorePath: join(dir, 'ignore'),
};
const run = (mode: string, options = {}) =>
  runAdapter(
    createGitleaksAdapter({ ...base, mode: 'working-tree', ...options })
      .adapter,
    {
      scope,
      files: { 'mode.txt': mode, 'src/config.ts': 'benign placeholder\n' },
    },
  );
const linuxOnly = { skip: process.platform !== 'linux' };

await test('parser keeps only rule, path and location', () => {
  const parsed = parseGitleaksReport(
    report(record(), record({ StartLine: 7, EndLine: 7 })),
  );
  assert.equal(parsed?.findings.length, 2);
  assert.equal(parsed?.partial, undefined);
  const text = JSON.stringify(parsed);
  assert.doesNotMatch(text, /REDACTED|Match|Secret|key =/);
  assert.equal(parsed?.findings[0]?.ruleId, 'aws-access-token');
  assert.equal(parsed?.findings[0]?.path, 'src/config.ts');
  assert.match(parsed?.findings[0]?.fingerprint ?? '', /^sha256:[a-f0-9]{64}$/);
});

await test('benign and empty reports yield no findings', () => {
  assert.deepEqual(parseGitleaksReport('[]'), { findings: [] });
});

await test('fingerprint is stable and independent of any secret value', () => {
  const a = parseGitleaksReport(report(record()));
  const b = parseGitleaksReport(
    report(record({ Match: 'other', Description: 'other', Commit: 'x' })),
  );
  assert.equal(a?.findings[0]?.fingerprint, b?.findings[0]?.fingerprint);
  const moved = parseGitleaksReport(
    report(record({ StartLine: 4, EndLine: 4 })),
  );
  assert.notEqual(a?.findings[0]?.fingerprint, moved?.findings[0]?.fingerprint);
});

await test('unredacted secrets reject the whole report without echoing it', () => {
  for (const secret of dummySecrets) {
    assert.equal(
      parseGitleaksReport(report(record({ Secret: secret }))),
      undefined,
    );
  }
});

await test('unsafe paths and bad locations are dropped as incomplete', () => {
  const parsed = parseGitleaksReport(
    report(
      record({ File: '../../etc/passwd' }),
      record({ File: '/abs/path' }),
      record({ StartLine: 0 }),
      record({ RuleID: 'bad rule!' }),
      record(),
    ),
  );
  assert.equal(parsed?.findings.length, 1);
  assert.equal(parsed?.partial, 'invalid-output');
  assert.equal(parseGitleaksReport('{}'), undefined);
  assert.equal(parseGitleaksReport('[1]'), undefined);
});

await test('adapter options are validated and arguments are fixed', () => {
  const sha1 = 'a'.repeat(40);
  const wt = createGitleaksAdapter({ ...base, mode: 'working-tree' });
  assert.deepEqual(wt.adapter.allowedArgs, []);
  assert.equal(wt.adapter.engine.version, gitleaksVersion);
  for (const flag of ['--redact', '--ignore-gitleaks-allow'])
    assert.ok(wt.adapter.fixedArgs.includes(flag));
  assert.ok(wt.adapter.fixedArgs.includes(base.configPath));
  const range = createGitleaksAdapter({
    ...base,
    mode: 'commit-range',
    range: { base: sha1, head: scope.commitSha },
    repoPath: '/srv/clone',
    shallow: true,
  });
  assert.deepEqual(range.record.range, { base: sha1, head: scope.commitSha });
  assert.equal(range.record.incompleteHistory, true);
  const bad = [
    { ...base, mode: 'working-tree', repoPath: '/x' },
    { ...base, mode: 'commit-range' },
    {
      ...base,
      mode: 'commit-range',
      range: { base: 'main', head: sha1 },
      repoPath: '/x',
    },
    {
      ...base,
      mode: 'commit-range',
      range: { base: sha1, head: sha1 },
      repoPath: 'rel',
    },
    { ...base, mode: 'history' },
    { ...base, executable: 'gitleaks', mode: 'working-tree' },
    { ...base, configPath: 'rel.toml', mode: 'working-tree' },
  ];
  for (const options of bad)
    assert.throws(() =>
      createGitleaksAdapter(
        options as Parameters<typeof createGitleaksAdapter>[0],
      ),
    );
});

await test('caller-supplied arguments are refused', linuxOnly, async () => {
  const { adapter } = createGitleaksAdapter({ ...base, mode: 'working-tree' });
  const envelope = await runAdapter(adapter, {
    scope,
    files: { 'mode.txt': 'clean' },
    args: ['--no-redact'],
  });
  assert.equal(envelope.status, 'skipped');
  assert.equal(envelope.reason, 'invalid-request');
});

await test(
  'leaks run through the adapter with redaction everywhere',
  linuxOnly,
  async () => {
    const envelope = await run('leaks');
    assert.equal(envelope.status, 'completed');
    assert.equal(envelope.provenance, 'adapter-executed');
    assert.equal(envelope.engine.id, 'gitleaks');
    assert.equal(envelope.engine.version, gitleaksVersion);
    assert.equal(envelope.findings.length, 2);
    assert.equal(envelope.findings[0]?.path, 'src/config.ts');
    const text = JSON.stringify(envelope);
    for (const secret of dummySecrets) assert.ok(!text.includes(secret));
    assert.doesNotMatch(text, /REDACTED|Secret|Match/);
  },
);

await test('clean scan completes with no findings', linuxOnly, async () => {
  const envelope = await run('clean');
  assert.equal(envelope.status, 'completed');
  assert.deepEqual(envelope.findings, []);
});

await test(
  'failed scans never leak output or look clean',
  linuxOnly,
  async () => {
    for (const mode of ['crash', 'garbage', 'unredacted']) {
      const envelope = await run(mode);
      assert.equal(envelope.status, 'failed', mode);
      assert.deepEqual(envelope.findings, []);
      const text = JSON.stringify(envelope);
      for (const secret of dummySecrets) assert.ok(!text.includes(secret));
    }
    assert.equal((await run('crash')).reason, 'engine-error');
    assert.equal((await run('unredacted')).reason, 'invalid-output');
  },
);

await test(
  'wrong engine version fails before scanning',
  linuxOnly,
  async () => {
    const { adapter } = createGitleaksAdapter({
      ...base,
      mode: 'working-tree',
    });
    const envelope = await runAdapter(
      { ...adapter, versionOutput: '8.0.0' },
      { scope, files: { 'mode.txt': 'leaks' } },
    );
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
  },
);

await test(
  'shallow history is disclosed as incomplete',
  linuxOnly,
  async () => {
    const sha1 = 'a'.repeat(40);
    const { adapter, record: scanRecord } = createGitleaksAdapter({
      ...base,
      mode: 'commit-range',
      range: { base: sha1, head: scope.commitSha },
      repoPath: dir,
      shallow: true,
    });
    const envelope = await runAdapter(adapter, {
      scope,
      files: { 'mode.txt': 'leaks' },
    });
    assert.equal(scanRecord.headCommit, scope.commitSha);
    assert.equal(envelope.status, 'incomplete');
    assert.equal(envelope.reason, 'incomplete-history');
    assert.equal(envelope.findings.length, 2);
  },
);

const today = new Date('2026-11-12T10:00:00Z');
const fixture = async () => {
  const envelope = await run('leaks');
  const [a, b] = envelope.findings;
  assert.ok(a && b);
  const exception = (f: typeof a, over: Partial<GitleaksException> = {}) => ({
    fingerprint: f.fingerprint,
    ruleId: f.ruleId,
    path: f.path,
    reviewedBy: 'reviewer-1',
    reviewedAt: '2026-11-01',
    expiresAt: '2026-12-01',
    reason: 'Synthetic fixture value',
    ...over,
  });
  return { envelope, a, b, exception };
};

await test(
  'valid exceptions are reported separately with new/existing counts',
  linuxOnly,
  async () => {
    const { envelope, a, b, exception } = await fixture();
    const result = classifyGitleaksEnvelope(envelope, {
      exceptions: [exception(a)],
      baseline: new Set([b.fingerprint]),
      now: today,
    });
    assert.equal(result.scanStatus, 'completed');
    assert.deepEqual(result.counts, {
      active: 1,
      new: 0,
      existing: 1,
      excepted: 1,
      expiredExceptions: 0,
      rejectedExceptions: 0,
      unusedExceptions: 0,
    });
    assert.equal(result.excepted[0]?.finding.fingerprint, a.fingerprint);
  },
);

await test(
  'expired, over-long, mismatched and malformed exceptions never apply',
  linuxOnly,
  async () => {
    const { envelope, a, b, exception } = await fixture();
    const result = classifyGitleaksEnvelope(envelope, {
      exceptions: [
        exception(a, { expiresAt: '2026-11-11' }),
        exception(b, { expiresAt: '2027-06-01' }),
        exception(b, { fingerprint: 'sha256:*' }),
        exception(b, { ruleId: 'other-rule' }),
        exception(b, { reason: ' ' }),
      ],
      now: today,
    });
    assert.equal(result.counts.excepted, 0);
    assert.equal(result.counts.active, 2);
    assert.equal(result.counts.expiredExceptions, 1);
    assert.equal(result.counts.rejectedExceptions, 3);
    assert.equal(result.counts.unusedExceptions, 1);
    assert.equal(result.counts.new, 2);
  },
);

await test(
  'exceptions never turn a failed scan into a clean result',
  linuxOnly,
  async () => {
    const { a, exception } = await fixture();
    const failed = await run('crash');
    const result = classifyGitleaksEnvelope(failed, {
      exceptions: [exception(a)],
      now: today,
    });
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.scanReason, 'engine-error');
    assert.equal(result.counts.excepted, 0);
    assert.equal(result.counts.active, 0);
  },
);

await test.after?.(async () => {
  await rm(dir, { recursive: true, force: true });
});
