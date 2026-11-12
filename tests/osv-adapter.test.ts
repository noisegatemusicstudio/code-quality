import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { EnvelopeScope } from '../src/adapter-envelope.js';
import {
  type OsvAdapterOptions,
  osvArtefactKind,
  parseOsvReport,
  runOsvScan,
} from '../src/osv-adapter.js';
import {
  artefact,
  emptyReport,
  fixedReport,
  malformedReports,
  otherPathReport,
  vulnerableReport,
} from './osv-adapter-fixtures.js';

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

await test('parser reports package, advisory, ranges and fix versions', () => {
  const parsed = parseOsvReport(vulnerableReport, artefact);
  assert.ok(parsed);
  assert.equal(parsed.findings.length, 3);
  const first = parsed.findings[0];
  assert.deepEqual(first?.package, {
    name: 'lodash',
    version: '4.17.15',
    ecosystem: 'npm',
  });
  assert.equal(first?.artefactPath, artefact);
  assert.equal(first?.advisory.id, 'GHSA-p6mc-m468-83gw');
  assert.deepEqual(first?.advisory.aliases, ['CVE-2020-8203']);
  assert.deepEqual(first?.affectedRanges, [
    { type: 'SEMVER', introduced: '0', fixed: '4.17.19' },
  ]);
  assert.deepEqual(first?.fixedVersions, ['4.17.19']);
  const nofix = parsed.findings.find((f) =>
    f.advisory.id.startsWith('GHSA-35'),
  );
  assert.deepEqual(nofix?.fixedVersions, []);
  assert.match(parsed.envelope[1]?.message ?? '', /no fix known/);
});

await test('aliases merge per package+version+path but versions never merge', () => {
  const parsed = parseOsvReport(vulnerableReport, artefact);
  const ids = parsed?.findings.map((f) => [f.package.version, f.advisory.id]);
  assert.deepEqual(ids, [
    ['4.17.15', 'GHSA-p6mc-m468-83gw'],
    ['4.17.15', 'GHSA-35jh-r3h4-6jhm'],
    ['4.17.16', 'GHSA-p6mc-m468-83gw'],
  ]);
  const prints = new Set(parsed?.envelope.map((f) => f.fingerprint));
  assert.equal(prints.size, 3);
  // Re-importing the same report is deterministic.
  assert.deepEqual(parseOsvReport(vulnerableReport, artefact), parsed);
});

await test('fixed and empty reports yield no findings', () => {
  assert.equal(parseOsvReport(fixedReport, artefact)?.findings.length, 0);
  assert.equal(parseOsvReport(emptyReport, artefact)?.findings.length, 0);
});

await test('malformed output and foreign paths are rejected', () => {
  for (const raw of malformedReports)
    assert.equal(parseOsvReport(raw, artefact), undefined, raw);
  assert.equal(parseOsvReport(otherPathReport, artefact), undefined);
  assert.equal(parseOsvReport(vulnerableReport, 'notes.txt'), undefined);
});

await test('artefact kinds', () => {
  assert.equal(osvArtefactKind('a/package-lock.json'), 'lockfile');
  assert.equal(osvArtefactKind('bom.cdx.json'), 'sbom');
  for (const bad of ['notes.txt', '../package-lock.json', '-L', 'a\\b.lock'])
    assert.equal(osvArtefactKind(bad), undefined);
});

// ---- Adapter execution with a recorded-output fake binary -------------------
const dir = await mkdtemp(join(tmpdir(), 'osv-adapter-test-'));
const exe = join(dir, 'fake-osv');
const reports: Record<string, string> = {
  vulnerable: vulnerableReport,
  fixed: fixedReport,
  malformed: '{oops',
};
for (const [name, body] of Object.entries(reports))
  await writeFile(join(dir, `${name}.json`), body);
// The scrubbed environment has no variables, so the report is picked by the
// artefact's directory name inside the workspace-relative path.
await writeFile(
  exe,
  `#!${process.execPath}
const a = process.argv.slice(2);
if (a[0] === '--version') { console.log('osv-scanner fake 2.7.1'); process.exit(0); }
const path = a[a.indexOf('-L') + 1] ?? a[a.indexOf('--sbom') + 1];
const kind = path.split('/')[0];
const raw = require('node:fs').readFileSync('${dir}/' + kind + '.json', 'utf8');
process.stdout.write(raw.replaceAll('/tmp/work/package-lock.json', process.cwd() + '/' + path));
process.exit(kind === 'vulnerable' ? 1 : 0);
`,
);
await chmod(exe, 0o755);
const base: OsvAdapterOptions = {
  executable: exe,
  versionOutput: 'osv-scanner fake 2.7.1',
  now: new Date('2026-11-12T00:00:00Z'),
};
const scan = (options: Partial<OsvAdapterOptions>, artefactPath: string) =>
  runOsvScan(
    { ...base, ...options },
    { scope, artefactPath, artefactContent: '{}' },
  );

await test(
  'online scan of a vulnerable lockfile',
  { skip: !linux },
  async () => {
    const r = await scan({}, 'vulnerable/package-lock.json');
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.envelope.findings.length, r.findings.length);
    assert.equal(r.findings.length, 3);
    assert.equal(r.disclosure.mode, 'online');
    assert.match(r.disclosure.transmitted, /OSV API/);
    assert.match(r.disclosure.notice, /does not guarantee/);
    assert.equal(r.envelope.configVersion, 'osv-online-v1');
  },
);

await test(
  'fixed lockfile is clean but still carries the notice',
  { skip: !linux },
  async () => {
    const r = await scan({}, 'fixed/package-lock.json');
    assert.deepEqual([r.envelope.status, r.findings.length], ['completed', 0]);
    assert.match(r.disclosure.notice, /unknown vulnerabilities/);
  },
);

await test(
  'malformed engine output fails with no findings',
  { skip: !linux },
  async () => {
    const r = await scan({}, 'malformed/package-lock.json');
    assert.deepEqual(
      [r.envelope.status, r.envelope.reason, r.findings.length],
      ['failed', 'invalid-output', 0],
    );
    assert.equal(r.disclosure.outcome, 'engine-failed');
  },
);

await test('unsupported, denied-network and stale/missing databases are skipped', async () => {
  const cases: [Partial<OsvAdapterOptions>, string, string][] = [
    [{}, 'notes.txt', 'unsupported-artefact'],
    [{ networkAvailable: false }, 'package-lock.json', 'network-denied'],
    [{ mode: 'offline' }, 'package-lock.json', 'database-timestamp-missing'],
    [
      { mode: 'offline', databaseTimestamp: '2026-10-01T00:00:00Z' },
      'package-lock.json',
      'stale-database',
    ],
    [
      { mode: 'offline', databaseTimestamp: '2027-01-01T00:00:00Z' },
      'package-lock.json',
      'stale-database',
    ],
  ];
  for (const [options, path, outcome] of cases) {
    const r = await scan(options, path);
    assert.deepEqual(
      [
        r.envelope.status,
        r.envelope.reason,
        r.findings.length,
        r.disclosure.outcome,
      ],
      ['skipped', 'invalid-request', 0, outcome],
      outcome,
    );
  }
});

await test(
  'offline mode discloses the database timestamp',
  { skip: !linux },
  async () => {
    const r = await scan(
      { mode: 'offline', databaseTimestamp: '2026-11-10T08:00:00Z' },
      'fixed/package-lock.json',
    );
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.disclosure.databaseTimestamp, '2026-11-10T08:00:00.000Z');
    assert.equal(r.envelope.rulesetVersion, 'osv-db-20261110');
    assert.equal(r.envelope.configVersion, 'osv-offline-v1');
    assert.match(r.disclosure.transmitted, /Nothing/);
  },
);

await rm(dir, { recursive: true, force: true });
