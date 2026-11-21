// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: OSV database ZIP validation reads archives only through yauzl (no hand-written data-descriptor signature handling) and rejects truncated or malformed archives with the standard error; it does not exercise real OSV data or the scanner.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { validateOsvDatabaseZip } from '../src/osv-database.js';
import { makeSyntheticOsvZip, syntheticAdvisory } from './osv-fixtures.js';

const ERROR = { message: 'Invalid or unsupported offline OSV database' };

void test('valid archives give the same records for every descriptor and compression mode', async () => {
  const records = [
    { advisory: syntheticAdvisory('GHSA-2345-6789-cfgh') },
    {
      advisory: {
        ...syntheticAdvisory('GHSA-3456-789c-fghj'),
        withdrawn: '2026-11-02T00:00:00Z',
      },
    },
  ];
  for (const deflate of [false, true])
    for (const descriptor of [false, true])
      for (const unsignedDescriptor of [false, true]) {
        const result = await validateOsvDatabaseZip(
          makeSyntheticOsvZip(
            records.map((r) => ({
              ...r,
              deflate,
              descriptor,
              unsignedDescriptor,
            })),
          ),
          'npm',
        );
        assert.equal(result.entryCount, 2);
        assert.equal(result.usableCount, 1);
        assert.equal(result.withdrawnCount, 1);
      }
});

void test('every truncation and descriptor corruption fails with the standard error', async () => {
  const archive = makeSyntheticOsvZip([
    { descriptor: true, deflate: true },
    { descriptor: true, unsignedDescriptor: true },
  ]);
  for (let length = 0; length < archive.length; length++)
    await assert.rejects(
      validateOsvDatabaseZip(archive.subarray(0, length), 'npm'),
      ERROR,
    );
  const central = archive.readUInt32LE(archive.length - 6);
  for (const position of [central - 1, central - 12, central - 20]) {
    const bad = Buffer.from(archive);
    bad[position] ^= 0xff;
    await assert.rejects(validateOsvDatabaseZip(bad, 'npm'), ERROR);
  }
});

void test('source has no hand-written ZIP data-descriptor signature handling', () => {
  const source = readFileSync(
    new URL('../../src/osv-database.ts', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /0x08074b50/i);
});
