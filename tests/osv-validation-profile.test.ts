import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  validateOsvRecord,
  selectOsvValidationProfile,
} from '../src/osv-record-validation.js';
import {
  validateOsvDatabaseZip,
  validateOsvDatabaseFile,
} from '../src/osv-database.js';
import { runOfflineOsv } from '../src/osv-scanner.js';
import { makeSyntheticOsvZip, syntheticAdvisory } from './osv-fixtures.js';

const vector =
  'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const uriRecord = () => ({
  ...syntheticAdvisory(),
  references: [{ type: 'WEB', url: 'example.invalid/synthetic' }],
});
const scoreRecord = () => ({
  ...syntheticAdvisory(),
  severity: [{ type: 'CVSS_V4', score: `${vector}/` }],
});
const hash = (data: Buffer) => createHash('sha256').update(data).digest('hex');

await test('metadata opt-in recognizes only URI format and one trailing CVSS4 slash without changing input', () => {
  for (const value of [uriRecord(), scoreRecord()]) {
    const before = JSON.stringify(value);
    assert.throws(() => validateOsvRecord(value));
    const result = validateOsvRecord(value, 'npm-metadata-v1');
    assert.equal(result.records, 1);
    assert.equal(result.referenceUriFormat + result.cvssV4TrailingSlash, 1);
    assert.equal(JSON.stringify(value), before);
  }
  const valid = syntheticAdvisory();
  assert.deepEqual(validateOsvRecord(valid, 'npm-metadata-v1'), {
    records: 0,
    referenceUriFormat: 0,
    cvssV4TrailingSlash: 0,
  });
});

await test('buffer and file metadata count occurrences and records, preserving source bytes', async () => {
  const advisory = (id: string, urls: string[]) => ({
    ...syntheticAdvisory(id),
    references: urls.map((url) => ({ type: 'WEB', url })),
  });
  const archive = makeSyntheticOsvZip([
    {
      advisory: advisory('GHSA-2345-6789-cfgh', [
        'https://example.invalid/a]',
        'https://example.invalid/b]',
      ]),
      deflate: true,
      descriptor: true,
    },
    { advisory: advisory('GHSA-3456-789c-fghj', ['example.invalid/c']) },
    {
      advisory: advisory('GHSA-4567-89cf-ghjm', ['example.invalid/d']),
      deflate: true,
    },
    { advisory: { ...scoreRecord(), id: 'GHSA-5678-9cfg-hjmp' } },
  ]);
  const originalHash = hash(archive);
  const directory = await mkdtemp(join(tmpdir(), 'osv-profile-'));
  const path = join(directory, 'all.zip');
  try {
    await writeFile(path, archive);
    await assert.rejects(validateOsvDatabaseZip(archive, 'npm'));
    await assert.rejects(validateOsvDatabaseFile(path, 'npm'));
    const buffer = await validateOsvDatabaseZip(
      archive,
      'npm',
      'npm-metadata-v1',
    );
    const file = await validateOsvDatabaseFile(path, 'npm', 'npm-metadata-v1');
    assert.deepEqual(file, buffer);
    assert.equal(file.validationProfile, 'npm-metadata-v1');
    assert.equal(file.schemaConformance, 'metadata-warnings');
    assert.deepEqual(file.metadataWarningCounts, {
      records: 4,
      referenceUriFormat: 4,
      cvssV4TrailingSlash: 1,
    });
    assert.equal(file.sha256, originalHash);
    assert.equal(hash(archive), originalHash);
    assert.equal(hash(await readFile(path)), originalHash);
    for (const forbidden of ['example.invalid', 'GHSA-', 'CVSS:4.0'])
      assert.ok(!JSON.stringify(file).includes(forbidden));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('metadata exception never hides independent schema, matching-field or nested-severity errors', () => {
  const invalid: Record<string, unknown>[] = [
    { ...uriRecord(), id: 3 },
    { ...uriRecord(), modified: 'invalid' },
    { ...uriRecord(), withdrawn: 'invalid' },
    { ...uriRecord(), unrecognized: true },
    { ...uriRecord(), references: [{ type: 'not-a-type', url: 'bad-url' }] },
    { ...uriRecord(), references: [{ type: 'WEB', url: 3 }] },
    { ...uriRecord(), affected: [{ package: { name: 2, ecosystem: 'npm' } }] },
    {
      ...uriRecord(),
      affected: [{ package: { name: 'synthetic', ecosystem: 2 } }],
    },
    { ...uriRecord(), affected: [{ versions: [2] }] },
    {
      ...uriRecord(),
      affected: [
        { ranges: [{ type: 'not-a-range', events: [{ introduced: '0' }] }] },
      ],
    },
    {
      ...uriRecord(),
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: 3 }] }] }],
    },
    {
      ...uriRecord(),
      affected: [{ severity: [{ type: 'CVSS_V4', score: `${vector}/` }] }],
    },
    {
      ...scoreRecord(),
      severity: [
        { type: 'CVSS_V4', score: `${vector}/` },
        { type: 'CVSS_V4', score: 'garbage' },
      ],
    },
    { ...scoreRecord(), severity: [{ type: 'CVSS_V4', score: `${vector}//` }] },
    { ...scoreRecord(), severity: [{ type: 'CVSS_V4', score: 'garbage/' }] },
    { ...scoreRecord(), severity: [{ type: 'CVSS_V3', score: `${vector}/` }] },
    { ...scoreRecord(), severity: [{ type: 'CVSS_V4', score: 3 }] },
  ];
  for (const value of invalid)
    assert.throws(
      () => validateOsvRecord(value, 'npm-metadata-v1'),
      JSON.stringify(value),
    );
});

await test('accepted metadata does not skip duplicate IDs, bad CRC or later malformed JSON', async () => {
  const duplicate = makeSyntheticOsvZip([
    { advisory: uriRecord() },
    { advisory: uriRecord() },
  ]);
  const malformed = makeSyntheticOsvZip([
    { advisory: uriRecord() },
    { data: Buffer.from('{broken') },
  ]);
  const corrupt = makeSyntheticOsvZip([{ advisory: uriRecord() }]);
  corrupt[50] ^= 1;
  for (const archive of [duplicate, malformed, corrupt])
    await assert.rejects(
      validateOsvDatabaseZip(archive, 'npm', 'npm-metadata-v1'),
    );
});

await test('profile opt-in ignores inherited values/getters, captures own getter once and rejects unknown values', () => {
  assert.equal(selectOsvValidationProfile({}), 'strict-schema-v1');
  assert.equal(
    selectOsvValidationProfile({ validationProfile: undefined }),
    'strict-schema-v1',
  );
  const inherited: object = Object.create({
    validationProfile: 'npm-metadata-v1',
  }) as object;
  assert.equal(selectOsvValidationProfile(inherited), 'strict-schema-v1');
  let inheritedReads = 0;
  const inheritedGetter: object = Object.create({
    get validationProfile() {
      inheritedReads++;
      throw new Error();
    },
  }) as object;
  assert.equal(selectOsvValidationProfile(inheritedGetter), 'strict-schema-v1');
  assert.equal(inheritedReads, 0);
  let ownReads = 0;
  assert.equal(
    selectOsvValidationProfile({
      get validationProfile() {
        ownReads++;
        return 'npm-metadata-v1';
      },
    }),
    'npm-metadata-v1',
  );
  assert.equal(ownReads, 1);
  for (const value of [null, '', 'unknown', 1, false])
    assert.throws(() =>
      selectOsvValidationProfile({ validationProfile: value }),
    );
});

await test('scanner captures an own profile getter once before rejecting an unavailable tool', async () => {
  let reads = 0;
  const database = {
    archivePath: '/missing/all.zip',
    sha256: 'a'.repeat(64),
    asOf: '2026-11-01T00:00:00Z',
    get validationProfile() {
      reads++;
      return 'npm-metadata-v1' as const;
    },
  };
  const result = await runOfflineOsv(
    '/missing/source',
    '/missing/tool',
    database,
  );
  assert.equal(reads, 1);
  assert.equal(result.state, 'failed');
  assert.equal(result.evidence, 'none');
});

await test('CLI rejects null or unknown profile with bounded invalid JSON and exit 2', () => {
  const cli = resolve(import.meta.dirname, '../src/scan-cli.js');
  for (const validationProfile of [null, 'unknown']) {
    const input = {
      gitExecutable: '/usr/bin/git',
      gitDirectory: '/missing/.git',
      commitSha: 'a'.repeat(40),
      osvDatabase: {
        archivePath: '/missing/all.zip',
        sha256: 'a'.repeat(64),
        asOf: '2026-11-01T00:00:00Z',
        validationProfile,
      },
    };
    const result = spawnSync(process.execPath, [cli], {
      input: JSON.stringify(input),
      encoding: 'utf8',
      timeout: 30000,
      env: { LANG: 'C' },
    });
    assert.equal(result.status, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout) as unknown, {
      schemaVersion: 2,
      status: 'invalid',
    });
  }
});

await test('API reports sanitized opt-in metadata without native execution and inherited opt-in stays strict', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'osv-profile-api-'));
  try {
    const archive = makeSyntheticOsvZip([{ advisory: uriRecord() }]);
    const archivePath = join(directory, 'all.zip');
    await writeFile(archivePath, archive);
    const source = join(directory, 'source');
    const { mkdir, access } = await import('node:fs/promises');
    await mkdir(source);
    const executable = resolve(
      import.meta.dirname,
      '../../.fixtures/scanner-tools/osv-scanner',
    );
    try {
      await access(executable);
    } catch {
      t.skip('Pinned development binary absent; no automatic download');
      return;
    }
    const database = {
      archivePath,
      sha256: hash(archive),
      asOf: '2026-11-01T00:00:00Z',
    };
    let reads = 0;
    const inherited = Object.assign(
      Object.create({
        get validationProfile() {
          reads++;
          throw new Error('inherited getter must not run');
        },
      }) as typeof database,
      database,
    );
    const strict = await runOfflineOsv(source, executable, inherited);
    assert.equal(reads, 0);
    assert.equal(strict.state, 'failed');
    assert.equal(strict.database, undefined);
    let ownReads = 0;
    const accepted = await runOfflineOsv(source, executable, {
      ...database,
      get validationProfile() {
        ownReads++;
        return 'npm-metadata-v1' as const;
      },
    });
    assert.equal(ownReads, 1);
    assert.equal(accepted.reason, 'no-supported-lockfiles');
    assert.equal(accepted.state, 'limited');
    assert.equal(accepted.evidence, 'none');
    assert.equal(accepted.database?.validationProfile, 'npm-metadata-v1');
    assert.equal(accepted.database?.schemaConformance, 'metadata-warnings');
    assert.deepEqual(accepted.database?.metadataWarningCounts, {
      records: 1,
      referenceUriFormat: 1,
      cvssV4TrailingSlash: 0,
    });
    assert.equal(accepted.database?.completeness, 'unverified');
    assert.equal(hash(await readFile(archivePath)), database.sha256);
    for (const forbidden of [directory, 'example.invalid', 'GHSA-'])
      assert.ok(!JSON.stringify(accepted).includes(forbidden));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
