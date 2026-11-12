/*
Test classification: contract
Review status: Not Reviewed
Evidence: synthetic
Scope: Parses recorded synthetic Trivy JSON, runs a fake executable through runAdapter and correlates OSV/Trivy findings; does not run the real Trivy binary, pull images, fetch a vulnerability database or contact a registry.
*/
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { EnvelopeScope } from '../src/adapter-envelope.js';
import { correlateDependencyFindings } from '../src/dependency-correlation.js';
import { parseOsvReport } from '../src/osv-adapter.js';
import {
  type TrivyAdapterOptions,
  type TrivyTarget,
  parseTrivyReport,
  runTrivyScan,
} from '../src/trivy-adapter.js';
import { artefact, vulnerableReport } from './osv-adapter-fixtures.js';
import {
  cleanImage,
  cleanImageNoResults,
  digest,
  iacMisconfig,
  imageName,
  malformedReports,
  vulnerableImage,
} from './trivy-adapter-fixtures.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'a'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const linux = process.platform === 'linux';

await test('parser reports package, advisory, severity source and fix version', () => {
  const parsed = parseTrivyReport(vulnerableImage);
  assert.ok(parsed);
  assert.equal(parsed.vulnerabilities.length, 4);
  assert.equal(parsed.envelope.length, 4);
  const os = parsed.vulnerabilities[0];
  assert.deepEqual(os?.package, {
    name: 'libssl3',
    version: '3.1.2-r0',
    ecosystem: 'alpine',
  });
  assert.equal(os?.advisory.id, 'CVE-2023-5363');
  assert.deepEqual(os?.severity, { label: 'HIGH', source: 'nvd' });
  assert.deepEqual(os?.fixedVersions, ['3.1.4-r0']);
  assert.equal(os?.artefactKind, 'image');
  const lodash = parsed.vulnerabilities[1];
  assert.equal(lodash?.package.ecosystem, 'npm');
  assert.equal(lodash?.artefactPath, 'app/package-lock.json');
  assert.deepEqual(lodash?.severity, { label: 'HIGH', source: 'ghsa' });
  const nofix = parsed.vulnerabilities.find(
    (v) => v.package.name === 'left-pad',
  );
  assert.deepEqual(nofix?.fixedVersions, []);
  assert.match(parsed.envelope[3]?.message ?? '', /no fix known/);
  assert.equal(parsed.envelope[0]?.fingerprint, os?.fingerprint);
  assert.deepEqual(parseTrivyReport(vulnerableImage), parsed);
});

await test('clean reports and malformed output', () => {
  assert.equal(parseTrivyReport(cleanImage)?.envelope.length, 0);
  assert.equal(parseTrivyReport(cleanImageNoResults)?.envelope.length, 0);
  for (const raw of malformedReports)
    assert.equal(parseTrivyReport(raw), undefined, raw);
});

await test('misconfigurations carry path, resource, rule, severity and remediation', () => {
  const parsed = parseTrivyReport(iacMisconfig);
  assert.ok(parsed);
  // The PASS entry is not a finding.
  assert.equal(parsed.misconfigurations.length, 2);
  const first = parsed.misconfigurations[0];
  assert.equal(first?.path, 'main.tf');
  assert.equal(first?.resource, 'aws_s3_bucket.logs');
  assert.equal(first?.ruleId, 'AWS-0086');
  assert.equal(first?.severity, 'HIGH');
  assert.match(first?.remediation ?? '', /public ACL/);
  assert.deepEqual([first?.startLine, first?.endLine], [5, 9]);
  assert.equal(parsed.envelope[0]?.range.startLine, 5);
  assert.equal(parsed.vulnerabilities.length, 0);
});

await test('secret values and echoed source lines never reach output', () => {
  const parsed = parseTrivyReport(iacMisconfig);
  const out = JSON.stringify(parsed);
  for (const secret of [
    'hunter2hunter2',
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'SYNTHETIC-CODE-LINE-SECRET',
  ])
    assert.equal(out.includes(secret), false, secret);
  assert.match(parsed?.envelope[1]?.message ?? '', /<redacted>/);
});

await test('OSV and Trivy findings for the same issue count once and keep both sources', () => {
  const osv = parseOsvReport(vulnerableReport, artefact);
  const trivy = parseTrivyReport(vulnerableImage);
  assert.ok(osv && trivy);
  const result = correlateDependencyFindings([
    { source: 'osv-scanner', findings: osv.findings },
    { source: 'trivy', findings: trivy.vulnerabilities },
  ]);
  // OSV: 3 findings; Trivy: 4. Shared: lodash@4.17.15 CVE-2020-8203 and CVE-2021-23337.
  assert.deepEqual(result.bySource, { 'osv-scanner': 3, trivy: 4 });
  assert.equal(result.total, 5);
  const shared = result.issues.filter((i) => i.sources.length === 2);
  assert.equal(shared.length, 2);
  for (const issue of shared) {
    assert.equal(issue.package.name, 'lodash');
    assert.equal(issue.occurrences.length, 2);
    assert.ok(issue.advisoryIds.some((id) => id.startsWith('GHSA-')));
    assert.ok(issue.advisoryIds.some((id) => id.startsWith('CVE-')));
  }
  assert.deepEqual(result.issues.flatMap((i) => i.occurrences).length, 7);
});

await test('different versions or unrelated advisories are never merged', () => {
  const trivy = parseTrivyReport(vulnerableImage);
  assert.ok(trivy);
  const other = trivy.vulnerabilities.map((v) => ({
    ...v,
    package: { ...v.package, version: '9.9.9' },
  }));
  const result = correlateDependencyFindings([
    { source: 'a', findings: trivy.vulnerabilities },
    { source: 'b', findings: other },
  ]);
  assert.equal(result.total, 8);
});

// ---- Adapter execution with a recorded-output fake binary -------------------
const dir = await mkdtemp(join(tmpdir(), 'trivy-adapter-test-'));
const exe = join(dir, 'fake-trivy');
const argvLog = join(dir, 'argv.log');
const reports: Record<string, string> = {
  vulnerable: vulnerableImage,
  clean: cleanImage,
  malformed: '{oops',
  iac: iacMisconfig,
};
for (const [key, body] of Object.entries(reports))
  await writeFile(join(dir, `${key}.json`), body);
// The environment is scrubbed, so behaviour is selected by the target.
await writeFile(
  exe,
  `#!${process.execPath}
const fs = require('node:fs');
const a = process.argv.slice(2);
if (a[0] === '--version') { console.log('Version: 0.76.2-fake'); process.exit(0); }
fs.appendFileSync('${argvLog}', JSON.stringify(a) + '\\n');
const target = a[a.length - 1];
let key;
if (a[0] === 'config') key = 'iac';
else if (target.includes('/hang@')) { setTimeout(() => {}, 60000); return; }
else if (target.includes('/error@')) { process.exit(1); }
else key = (target.match(/registry\\.test\\/(\\w+)@/) ?? target.match(/(\\w+)\\.tar/) ?? [])[1];
process.stdout.write(fs.readFileSync('${dir}/' + key + '.json', 'utf8'));
`,
);
await chmod(exe, 0o755);
const base: TrivyAdapterOptions = {
  executable: exe,
  versionOutput: 'Version: 0.76.2-fake',
  now: new Date('2026-11-12T00:00:00Z'),
};
const image = (key: string): TrivyTarget => ({
  kind: 'image-digest',
  reference: imageName(key),
});
const scan = (
  options: Partial<TrivyAdapterOptions>,
  target: TrivyTarget,
  signal?: AbortSignal,
) => runTrivyScan({ ...base, ...options }, { scope, target, signal });
const lastArgs = async (): Promise<string[]> => {
  const lines = (await readFile(argvLog, 'utf8')).trim().split('\n');
  return JSON.parse(lines[lines.length - 1] ?? '[]') as string[];
};

await test(
  'vulnerable image digest scan with only the vuln scanner and no socket',
  { skip: !linux },
  async () => {
    const r = await scan(
      { databaseVersion: '2', databaseUpdatedAt: '2026-11-11T06:00:00Z' },
      image('vulnerable'),
    );
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.vulnerabilities.length, 4);
    assert.equal(r.envelope.findings.length, 4);
    assert.equal(r.envelope.engine.version, '0.76.2');
    assert.equal(r.envelope.rulesetVersion, 'trivy-db-20261111');
    assert.deepEqual(r.disclosure.database, {
      version: '2',
      updatedAt: '2026-11-11T06:00:00.000Z',
    });
    assert.match(r.disclosure.notice, /does not guarantee/);
    const args = await lastArgs();
    assert.equal(args[0], 'image');
    assert.deepEqual(
      args.slice(args.indexOf('--scanners'), args.indexOf('--scanners') + 2),
      ['--scanners', 'vuln'],
    );
    assert.deepEqual(
      args.slice(args.indexOf('--image-src'), args.indexOf('--image-src') + 2),
      ['--image-src', 'remote'],
    );
    assert.equal(args.at(-1), imageName('vulnerable'));
    assert.equal(args.includes('--offline-scan'), false);
  },
);

await test('local image tarball uses --input', { skip: !linux }, async () => {
  const r = await scan(
    {},
    { kind: 'image-tarball', path: join(dir, 'clean.tar') },
  );
  assert.deepEqual(
    [r.envelope.status, r.vulnerabilities.length],
    ['completed', 0],
  );
  const args = await lastArgs();
  assert.deepEqual(args.slice(-2), ['--input', join(dir, 'clean.tar')]);
  assert.equal(args.includes('--image-src'), false);
});

await test(
  'clean image is completed with the notice',
  { skip: !linux },
  async () => {
    const r = await scan({}, image('clean'));
    assert.deepEqual(
      [r.envelope.status, r.envelope.findings.length],
      ['completed', 0],
    );
    assert.match(r.disclosure.notice, /known advisories/);
  },
);

await test(
  'IaC directory uses config scanning and drops Trivy control files',
  { skip: !linux },
  async () => {
    const r = await scan(
      {},
      {
        kind: 'iac',
        files: {
          'main.tf': 'resource "aws_s3_bucket" "logs" {}',
          'deploy/Dockerfile': 'FROM scratch',
          'trivy.yaml': 'scan:\n  scanners: [secret]',
          '.trivyignore': 'AWS-0086',
          'README.md': '# docs',
        },
      },
    );
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.misconfigurations.length, 2);
    assert.equal(r.envelope.findings.length, 2);
    assert.equal(r.envelope.configVersion, 'trivy-config-online-v1');
    assert.deepEqual(r.disclosure.droppedFiles.sort(), [
      '.trivyignore',
      'README.md',
      'trivy.yaml',
    ]);
    const args = await lastArgs();
    assert.equal(args[0], 'config');
    assert.equal(args.includes('--scanners'), false);
    assert.equal(args.at(-1), '.');
    assert.equal(JSON.stringify(r).includes('hunter2hunter2'), false);
  },
);

await test('unsupported targets are skipped without running', async () => {
  const cases: [TrivyTarget, string, string | undefined][] = [
    [
      { kind: 'image-digest', reference: 'registry.test/app:latest' },
      'unsupported-target',
      'invalid-request',
    ],
    [
      { kind: 'image-digest', reference: `--input@${digest}` },
      'unsupported-target',
      'invalid-request',
    ],
    [
      { kind: 'image-tarball', path: 'relative.tar' },
      'unsupported-target',
      'invalid-request',
    ],
    [
      { kind: 'image-tarball', path: '/tmp/../etc/image.tar' },
      'unsupported-target',
      'invalid-request',
    ],
    [
      { kind: 'image-tarball', path: '/tmp/image.zip' },
      'unsupported-target',
      'invalid-request',
    ],
    [
      { kind: 'iac', files: { 'README.md': 'x', 'trivy.yaml': 'x' } },
      'no-supported-files',
      'no-supported-files',
    ],
  ];
  for (const [target, outcome, reason] of cases) {
    const r = await scan({}, target);
    assert.deepEqual(
      [
        r.envelope.status,
        r.envelope.reason,
        r.envelope.findings.length,
        r.disclosure.outcome,
      ],
      ['skipped', reason, 0, outcome],
      outcome,
    );
  }
});

await test('registry denied and stale or missing offline database are skipped', async () => {
  const cases: [Partial<TrivyAdapterOptions>, string][] = [
    [{ registryAccess: false }, 'registry-denied'],
    [{ mode: 'offline' }, 'database-info-missing'],
    [
      { mode: 'offline', databaseUpdatedAt: 'nonsense' },
      'database-info-missing',
    ],
    [
      { mode: 'offline', databaseUpdatedAt: '2026-10-01T00:00:00Z' },
      'stale-database',
    ],
    [
      { mode: 'offline', databaseUpdatedAt: '2027-01-01T00:00:00Z' },
      'stale-database',
    ],
  ];
  for (const [options, outcome] of cases) {
    const r = await scan(options, image('vulnerable'));
    assert.deepEqual(
      [
        r.envelope.status,
        r.envelope.reason,
        r.vulnerabilities.length,
        r.disclosure.outcome,
      ],
      ['skipped', 'invalid-request', 0, outcome],
      outcome,
    );
  }
});

await test(
  'fresh offline database scans with offline flags and discloses its age',
  { skip: !linux },
  async () => {
    const r = await scan(
      {
        mode: 'offline',
        databaseVersion: '2',
        databaseUpdatedAt: '2026-11-10T00:00:00Z',
      },
      image('clean'),
    );
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.disclosure.database?.maxAgeDays, 7);
    const args = await lastArgs();
    assert.ok(
      args.includes('--skip-db-update') && args.includes('--offline-scan'),
    );
  },
);

await test(
  'IaC scans ignore database staleness',
  { skip: !linux },
  async () => {
    const r = await scan(
      { mode: 'offline' },
      { kind: 'iac', files: { 'main.tf': 'x' } },
    );
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.disclosure.database, undefined);
  },
);

await test(
  'malformed output fails and engine errors fail with no findings',
  { skip: !linux },
  async () => {
    const bad = await scan({}, image('malformed'));
    assert.deepEqual(
      [
        bad.envelope.status,
        bad.envelope.reason,
        bad.vulnerabilities.length,
        bad.disclosure.outcome,
      ],
      ['failed', 'invalid-output', 0, 'engine-failed'],
    );
    const err = await scan({}, image('error'));
    assert.deepEqual(
      [err.envelope.status, err.envelope.reason],
      ['failed', 'engine-error'],
    );
  },
);

await test('version mismatch never scans', { skip: !linux }, async () => {
  const r = await scan(
    { versionOutput: 'Version: 9.9.9' },
    image('vulnerable'),
  );
  assert.deepEqual(
    [r.envelope.status, r.envelope.reason],
    ['failed', 'engine-version-mismatch'],
  );
});

await test(
  'cancellation is incomplete with no findings',
  { skip: !linux },
  async () => {
    const controller = new AbortController();
    const pending = scan({}, image('hang'), controller.signal);
    setTimeout(() => {
      controller.abort();
    }, 400);
    const r = await pending;
    assert.deepEqual(
      [
        r.envelope.status,
        r.envelope.reason,
        r.vulnerabilities.length,
        r.disclosure.outcome,
      ],
      ['incomplete', 'cancelled', 0, 'cancelled'],
    );
    const pre = new AbortController();
    pre.abort();
    const early = await scan({}, image('vulnerable'), pre.signal);
    assert.deepEqual(
      [early.envelope.status, early.envelope.reason],
      ['skipped', 'cancelled'],
    );
  },
);
