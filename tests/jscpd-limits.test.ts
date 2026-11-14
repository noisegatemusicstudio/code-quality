/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Exercises the jscpd suppression pre-scan file bound and the per-engine report size caps against synthetic trees and reports; does not run the real jscpd binary (not runnable here) or the full scan.
*/
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { snapshotBounds } from '../src/committed-snapshot.js';
import {
  findJscpdSuppression,
  parseExternalReport,
  reportBytesCapFor,
  suppressionScanBounds,
} from '../src/external-scanners.js';

const body = 'const value = 1;\n'.repeat(12);

async function tree(files: number): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'jscpd-limits-'));
  for (let d = 0; d < Math.ceil(files / 100); d += 1)
    await mkdir(join(directory, `d${String(d)}`));
  for (let i = 0; i < files; i += 1)
    await writeFile(
      join(directory, `d${String(Math.floor(i / 100))}/f${String(i)}.ts`),
      body,
    );
  return directory;
}

await test('pre-scan file bound matches the snapshot bound and passes a 1134-file repo', async () => {
  assert.equal(suppressionScanBounds.files, snapshotBounds.sourceFiles);
  const directory = await tree(1134);
  try {
    assert.equal(await findJscpdSuppression(directory), 'none');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('a repo over the pre-scan file bound still fails closed', async () => {
  const directory = await tree(2000);
  try {
    assert.equal(
      await findJscpdSuppression(directory, {
        ...suppressionScanBounds,
        files: 1999,
      }),
      'limit',
    );
    assert.equal(
      await findJscpdSuppression(directory, {
        ...suppressionScanBounds,
        files: 2000,
      }),
      'none',
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function bigReport(pairs: number, fragmentBytes: number): string {
  const fragment = 'x'.repeat(fragmentBytes);
  const side = (name: string, start: number, end: number) => ({
    name,
    start,
    end,
    startLoc: { line: start, column: 0, position: 0 },
    endLoc: { line: end, column: 1, position: 1 },
  });
  const duplicates = Array.from({ length: pairs }, (_, i) => ({
    format: 'typescript',
    lines: 11,
    tokens: 62,
    fragment,
    firstFile: side(`d0/a${String(i)}.ts`, 1, 11),
    secondFile: side(`d0/b${String(i)}.ts`, 2, 12),
  }));
  const stats = {
    clones: pairs,
    lines: pairs * 24,
    sources: pairs * 2,
  };
  return JSON.stringify({
    duplicates,
    statistics: { formats: { typescript: stats }, total: stats },
  });
}

await test('a ~2.8 MB report with large duplicated text parses and keeps every clone', async () => {
  const pairs = 300;
  const directory = await mkdtemp(join(tmpdir(), 'jscpd-big-'));
  try {
    await mkdir(join(directory, 'd0'));
    for (let i = 0; i < pairs; i += 1)
      for (const name of ['a', 'b'])
        await writeFile(join(directory, `d0/${name}${String(i)}.ts`), body);
    const raw = Buffer.from(bigReport(pairs, 9000));
    assert.ok(raw.length > 2_700_000 && raw.length < 3_000_000);
    const parsed = parseExternalReport('jscpd', raw, directory);
    assert.equal(parsed?.findingCount, pairs);
    assert.equal(parsed.findings.length, pairs * 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('report caps stay fail-closed per engine', () => {
  assert.equal(reportBytesCapFor('gitleaks'), 1048576);
  assert.equal(reportBytesCapFor('jscpd'), 8388608);
  assert.equal(
    parseExternalReport('jscpd', Buffer.alloc(reportBytesCapFor('jscpd') + 1)),
    null,
  );
  assert.equal(
    parseExternalReport(
      'gitleaks',
      Buffer.alloc(reportBytesCapFor('gitleaks') + 1),
    ),
    null,
  );
});
