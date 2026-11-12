/*
Test classification: component
Review status: Not Reviewed
Evidence: real
Scope: Parses a report recorded from the real pinned jscpd 5.4.3 binary (run over the recorded source tree) with line counts taken from a snapshot directory; does not execute jscpd or run the full scan.
*/
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import {
  jscpdFindings,
  parseJscpdReport,
  snapshotLineCounter,
} from '../src/duplication.js';
import { parseExternalReport } from '../src/external-scanners.js';

const report = await readFile(
  resolve('tests/fixtures/jscpd-5.4.3-report.json'),
  'utf8',
);
const tree = JSON.parse(
  await readFile(resolve('tests/fixtures/jscpd-5.4.3-tree.json'), 'utf8'),
) as Record<string, string>;

async function snapshot(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'jscpd-snapshot-'));
  for (const [path, text] of Object.entries(tree)) {
    await mkdir(dirname(join(directory, path)), { recursive: true });
    await writeFile(join(directory, path), text);
  }
  return directory;
}

await test('real jscpd 5.4.3 report is complete with snapshot-counted lines', async () => {
  const directory = await snapshot();
  try {
    const detail = parseJscpdReport(report, {
      pathRoot: directory,
      files: undefined,
      lineCount: snapshotLineCounter(directory),
    });
    assert.equal(detail.state, 'complete');
    assert.equal(detail.cloneCount, 1);
    assert.deepEqual(detail.analyzed, { 'src/a.ts': 12, 'src/b.ts': 12 });
    assert.deepEqual(detail.totals, { covered: 11 + 11, total: 33 });
    assert.equal(detail.sourceCount, 3);
    assert.equal(
      detail.counting?.denominator,
      'report-total-lines-cross-checked-against-snapshot',
    );
    assert.equal(jscpdFindings(detail.clones).length, 2);
    const external = parseExternalReport(
      'jscpd',
      Buffer.from(report),
      directory,
    );
    assert.equal(external?.findingCount, 1);
    assert.equal(external.coveredFileCount, 3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('report without a usable snapshot count is rejected, not guessed', async () => {
  const directory = await snapshot();
  try {
    const base = { pathRoot: directory, files: undefined };
    assert.equal(parseJscpdReport(report, base).state, 'invalid');
    assert.equal(
      parseJscpdReport(report, { ...base, lineCount: () => undefined }).state,
      'invalid',
    );
    // A clone reaching past the snapshot file means report and tree differ.
    assert.equal(
      parseJscpdReport(report, { ...base, lineCount: () => 3 }).state,
      'invalid',
    );
    // Snapshot files larger than the report's own total are impossible.
    assert.equal(
      parseJscpdReport(report, { ...base, lineCount: () => 40 }).state,
      'invalid',
    );
    assert.equal(
      parseExternalReport('jscpd', Buffer.from(report), '/nonexistent'),
      null,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('snapshot line counter is bounded to the snapshot root', async () => {
  const directory = await snapshot();
  try {
    const count = snapshotLineCounter(directory);
    assert.equal(count('src/c.ts'), 1);
    assert.equal(count('src/missing.ts'), undefined);
    assert.equal(count('../etc/passwd'), undefined);
    assert.equal(count('/etc/passwd'), undefined);
    await writeFile(join(directory, 'noeol.ts'), 'a\nb');
    assert.equal(count('noeol.ts'), 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
