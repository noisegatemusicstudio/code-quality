import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  OSV_DATABASE_LIMITS,
  OSV_SCHEMA_METADATA,
  validateOsvDatabaseZip,
} from '../src/osv-database.js';

import { makeSyntheticOsvZip, syntheticAdvisory } from './osv-fixtures.js';

async function rejected(input: Buffer): Promise<void> {
  await assert.rejects(validateOsvDatabaseZip(input, 'npm'), {
    message: 'Invalid or unsupported offline OSV database',
  });
}

void test('active empty and withdrawn affected records do not imply usable coverage', async () => {
  const empty = { ...syntheticAdvisory(), affected: [] };
  const withdrawn = {
    ...syntheticAdvisory('GHSA-3456-789c-fghj'),
    withdrawn: '2026-11-02T00:00:00Z',
  };
  const result = await validateOsvDatabaseZip(
    makeSyntheticOsvZip([{ advisory: empty }, { advisory: withdrawn }]),
    'npm',
  );
  assert.equal(result.usableCount, 0);
  assert.equal(result.activeCount, 1);
  assert.equal(result.withdrawnCount, 1);
  assert.equal(result.noAffectedCount, 1);
  const noPackage = { ...syntheticAdvisory(), affected: [{}] };
  const noPackageResult = await validateOsvDatabaseZip(
    makeSyntheticOsvZip([{ advisory: noPackage }]),
    'npm',
  );
  assert.equal(noPackageResult.usableCount, 0);
  assert.equal(noPackageResult.noAffectedCount, 1);
});

void test('pinned schema bytes and license metadata match provenance declaration', () => {
  const bytes = readFileSync(
    new URL('../src/osv-schema-v1.9.2.json', import.meta.url),
  );
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    OSV_SCHEMA_METADATA.sha256,
  );
  assert.equal(OSV_SCHEMA_METADATA.license, 'Apache-2.0');
});

void test('rejects excessive record count and JSON depth before schema traversal', async () => {
  const input = makeSyntheticOsvZip([{}]);
  input.writeUInt16LE(OSV_DATABASE_LIMITS.entries + 1, input.length - 14);
  input.writeUInt16LE(OSV_DATABASE_LIMITS.entries + 1, input.length - 12);
  await rejected(input);
  let nested: unknown = {};
  for (let i = 0; i < 70; i++) nested = { child: nested };
  await rejected(
    makeSyntheticOsvZip([
      { advisory: { ...syntheticAdvisory(), database_specific: nested } },
    ]),
  );
});

void test('stored, deflated, signed and unsigned descriptor ZIPs return only aggregate metadata', async () => {
  for (const deflate of [false, true])
    for (const descriptor of [false, true])
      for (const unsignedDescriptor of [false, true]) {
        const input = makeSyntheticOsvZip([
          { deflate, descriptor, unsignedDescriptor },
        ]);
        const result = await validateOsvDatabaseZip(input, 'npm');
        assert.equal(result.entryCount, 1);
        assert.equal(result.activeCount, 1);
        assert.equal(result.usableCount, 1);
        assert.equal(result.noAffectedCount, 0);
        assert.equal(
          result.sha256,
          createHash('sha256').update(input).digest('hex'),
        );
        assert.equal(JSON.stringify(result).includes('synthetic'), false);
      }
});

void test('empty archives and withdrawn, absent/null/empty affected records expose lack of coverage', async () => {
  assert.equal(
    (await validateOsvDatabaseZip(makeSyntheticOsvZip([]), 'npm')).entryCount,
    0,
  );
  for (const affected of [undefined, null, []]) {
    const advisory = {
      id: 'GHSA-2345-6789-cfgh',
      modified: '2026-11-01T00:00:00Z',
      withdrawn: '2026-11-02T00:00:00Z',
      affected,
    };
    const result = await validateOsvDatabaseZip(
      makeSyntheticOsvZip([{ advisory }]),
      'npm',
    );
    assert.equal(result.withdrawnCount, 1);
    assert.equal(result.activeCount, 0);
    assert.equal(result.noAffectedCount, 1);
  }
});

void test('every JSON entry is validated, without silently skipping malformed records', async () => {
  const invalid: unknown[] = [
    null,
    {},
    { ...syntheticAdvisory(), modified: 'not-a-date' },
    { ...syntheticAdvisory(), unexpected: true },
    {
      ...syntheticAdvisory(),
      affected: [{ package: { name: 'x', ecosystem: 'unrecognized' } }],
    },
    {
      ...syntheticAdvisory(),
      affected: [
        {
          package: { name: 'x', ecosystem: 'npm' },
          ranges: [{ type: 'GIT', events: [{ introduced: '0' }] }],
        },
      ],
    },
  ];
  for (const advisory of invalid)
    await rejected(makeSyntheticOsvZip([{ advisory }]));
  await rejected(
    makeSyntheticOsvZip([
      { advisory: syntheticAdvisory() },
      { data: Buffer.from('{broken private-name') },
    ]),
  );
  await rejected(makeSyntheticOsvZip([{ data: Buffer.from([0xff]) }]));
});

void test('rejects wrong ecosystems, duplicate IDs/names and unsafe paths', async () => {
  await rejected(
    makeSyntheticOsvZip([
      {
        advisory: {
          ...syntheticAdvisory(),
          affected: [
            { package: { name: 'x', ecosystem: 'PyPI' }, versions: ['1'] },
          ],
        },
      },
    ]),
  );
  await rejected(makeSyntheticOsvZip([{}, {}]));
  for (const name of [
    '../secret.json',
    '/secret.json',
    'a\\secret.json',
    'C:secret.json',
    'a/./secret.json',
    'a//secret.json',
    'not-json.txt',
  ])
    await rejected(makeSyntheticOsvZip([{ name }]));
  await rejected(
    makeSyntheticOsvZip([
      { name: 'same.json' },
      { name: 'SAME.json', advisory: syntheticAdvisory('GHSA-3456-789c-fghj') },
    ]),
  );
});

void test('rejects CRC corruption, truncation, encryption, ZIP64, multidisk and unsupported methods', async () => {
  const original = makeSyntheticOsvZip([{ deflate: true }]);
  const central = original.readUInt32LE(original.length - 6);
  for (const mutate of [
    (b: Buffer) => {
      b.writeUInt32LE(1, central + 16);
      b.writeUInt32LE(1, 14);
    },
    (b: Buffer) => {
      b.writeUInt16LE(1, central + 8);
      b.writeUInt16LE(1, 6);
    },
    (b: Buffer) => {
      b.writeUInt16LE(99, central + 10);
      b.writeUInt16LE(99, 8);
    },
    (b: Buffer) => {
      b.writeUInt16LE(45, central + 6);
    },
    (b: Buffer) => {
      b.writeUInt16LE(1, b.length - 18);
    },
    (b: Buffer) => {
      b.writeUInt32LE(0xffffffff, b.length - 6);
    },
  ]) {
    const changed = Buffer.from(original);
    mutate(changed);
    await rejected(changed);
  }
  for (const length of [0, 10, original.length - 1, original.length - 22])
    await rejected(original.subarray(0, length));
});

void test('rejects malformed descriptors and bounded expansion', async () => {
  const bad = makeSyntheticOsvZip([{ descriptor: true, deflate: true }]);
  const central = bad.readUInt32LE(bad.length - 6);
  bad.writeUInt32LE(0, central - 12);
  await rejected(bad);
  const oversized = makeSyntheticOsvZip([
    {
      deflate: true,
      data: Buffer.alloc(OSV_DATABASE_LIMITS.entryBytes + 1, 32),
    },
  ]);
  await rejected(oversized);
  await rejected(Buffer.alloc(OSV_DATABASE_LIMITS.compressedBytes + 1));
  const lying = makeSyntheticOsvZip([{ deflate: true }]);
  const start = lying.readUInt32LE(lying.length - 6);
  lying.writeUInt32LE(1, start + 24);
  lying.writeUInt32LE(1, 22);
  await rejected(lying);
});
