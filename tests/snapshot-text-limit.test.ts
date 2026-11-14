// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: the 4 MiB text-blob snapshot limit, the jscpd pre-scan bounds aligned to it, trivy content-based JSON input selection and the cause breakdown in report rows, against synthetic local Git fixtures and temp directories; no real scanner binary is run and no hosted service is involved.
import { requireSupportedGit } from './git-requirement.js';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createCommittedSnapshot,
  describeOmissions,
  formatMegabytes,
  SnapshotError,
  snapshotBounds,
} from '../src/committed-snapshot.js';
import { scanCommittedSource } from '../src/customer-scan.js';
import {
  scanJscpdSuppression,
  suppressionScanBounds,
  type SuppressionLimit,
} from '../src/external-scanners.js';
import {
  applyOmitted,
  fromSlot,
  readBoundedFiles,
} from '../src/quality-scan-run.js';
import { isIacContent } from '../src/trivy-adapter.js';
import type { EngineResult } from '../src/quality-scan.js';

async function fixture(files: Record<string, string | Buffer>) {
  const root = await mkdtemp(join(tmpdir(), 'text-limit-'));
  const git = (...args: string[]) =>
    execFileSync(requireSupportedGit(), args, {
      cwd: root,
      encoding: 'utf8',
      env: {
        PATH: '/usr/bin',
        HOME: root,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
    }).trim();
  git('init', '-q');
  await writeFile(join(root, 'source.ts'), 'const value: number = 1;\n');
  for (const [name, content] of Object.entries(files))
    await writeFile(join(root, name), content);
  git('add', '.');
  git(
    '-c',
    'user.name=Fixture',
    '-c',
    'user.email=fixture@example.invalid',
    'commit',
    '-qm',
    'fixture',
    '--no-verify',
  );
  return {
    root,
    options: {
      gitExecutable: requireSupportedGit(),
      gitDirectory: join(root, '.git'),
      commitSha: git('rev-parse', 'HEAD'),
    },
    dispose: () => rm(root, { recursive: true, force: true }),
  };
}
const text = (bytes: number): string => `{"a":"${'x'.repeat(bytes - 9)}"}\n`;

await test('snapshot bounds: text limit is 4 MiB, the engine bound stays 1 MiB, the pre-scan is never stricter than the snapshot', () => {
  assert.equal(snapshotBounds.sourceFileBytes, 4 * 1024 * 1024);
  assert.equal(snapshotBounds.engineFileBytes, 1024 * 1024);
  assert.ok(suppressionScanBounds.fileBytes >= snapshotBounds.sourceFileBytes);
  assert.ok(suppressionScanBounds.totalBytes >= snapshotBounds.sourceBytes);
  assert.ok(suppressionScanBounds.files >= snapshotBounds.sourceFiles);
});

await test('a text blob between 1 MiB and 4 MiB is materialised and scanned, one byte over 4 MiB still fails closed as oversized-blob', async () => {
  const f = await fixture({
    'central.openapi.json': text(1800000),
    'at-limit.json': text(snapshotBounds.sourceFileBytes),
    'over-limit.json': text(snapshotBounds.sourceFileBytes + 1),
  });
  try {
    const snapshot = await createCommittedSnapshot(f.options);
    try {
      assert.equal(snapshot.omitted['oversized-blob'], 1);
      assert.equal(
        snapshot.largestOversizedBytes,
        snapshotBounds.sourceFileBytes + 1,
      );
      assert.equal(snapshot.fileCount, 3);
      assert.equal(
        (await readFile(join(snapshot.directory, 'central.openapi.json')))
          .length,
        1800000,
      );
      assert.equal(
        (await readFile(join(snapshot.directory, 'at-limit.json'))).length,
        snapshotBounds.sourceFileBytes,
      );
    } finally {
      await snapshot.dispose();
    }
  } finally {
    await f.dispose();
  }
});

await test('a repository above the 64 MiB text total still fails closed with source-bytes', async () => {
  const files: Record<string, string> = {};
  const each = snapshotBounds.sourceFileBytes;
  const count = Math.floor(snapshotBounds.sourceBytes / each) + 1;
  for (let index = 0; index < count; index++)
    files[`t${String(index)}.json`] = text(each - index);
  const f = await fixture(files);
  try {
    await assert.rejects(
      createCommittedSnapshot(f.options),
      (error: unknown) =>
        error instanceof SnapshotError && error.detail === 'source-bytes',
    );
  } finally {
    await f.dispose();
  }
});

await test('a text .ts file over the engine bound is not linted: ESLint is limited, not completed', async () => {
  const big = 'export const v = 1;\n'.repeat(
    Math.ceil((snapshotBounds.engineFileBytes + 1) / 19),
  );
  const f = await fixture({ 'generated.ts': big });
  try {
    const report = await scanCommittedSource(f.options);
    assert.equal(report.source?.omitted['oversized-blob'], 0);
    const eslint = report.scanners.find((slot) => slot.id === 'eslint');
    assert.equal(eslint?.state, 'limited');
    assert.equal(eslint.unresolvedDependencyCount, 1);
  } finally {
    await f.dispose();
  }
});

await test('jscpd pre-scan reads a snapshot-sized tree: 4 MiB files and totals beyond the old 16 MiB are scanned, not limited', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'prescan-limit-'));
  try {
    for (let index = 0; index < 5; index++)
      await writeFile(
        join(directory, `f${String(index)}.json`),
        text(snapshotBounds.sourceFileBytes),
      );
    assert.deepEqual(await scanJscpdSuppression(directory), { state: 'none' });
    await writeFile(join(directory, 'over.json'), text(4194305));
    assert.deepEqual(await scanJscpdSuppression(directory), {
      state: 'limit',
      limit: 'fileBytes',
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('jscpd pre-scan names the bound it hit and still fails closed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'prescan-cause-'));
  try {
    await mkdir(join(directory, 'a'));
    await writeFile(join(directory, 'a/x.ts'), 'const x = 1;\n');
    await writeFile(join(directory, 'a/y.ts'), 'const y = 1;\n');
    const hit = (bounds: Partial<Record<SuppressionLimit, number>>) =>
      scanJscpdSuppression(directory, { ...suppressionScanBounds, ...bounds });
    assert.deepEqual(await hit({ files: 1 }), {
      state: 'limit',
      limit: 'files',
    });
    assert.deepEqual(await hit({ directories: 1 }), {
      state: 'limit',
      limit: 'directories',
    });
    assert.deepEqual(await hit({ totalBytes: 20 }), {
      state: 'limit',
      limit: 'totalBytes',
    });
    assert.deepEqual(await hit({ fileBytes: 4 }), {
      state: 'limit',
      limit: 'fileBytes',
    });
    await writeFile(join(directory, 'a/s.ts'), '// jscpd:ignore\n');
    assert.deepEqual(await scanJscpdSuppression(directory), {
      state: 'found',
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('omission breakdown names causes and the largest oversized blob without paths', () => {
  const none = {
    symlink: 0,
    submodule: 0,
    'oversized-blob': 0,
    'unsupported-path': 0,
    'binary-limit': 0,
  };
  assert.equal(formatMegabytes(1850000), '1.85 MB');
  assert.equal(
    describeOmissions(
      { ...none, 'oversized-blob': 3, 'binary-limit': 1 },
      1850000,
      { count: 750, bytes: 9 },
    ),
    'oversized-blob: 3 (largest 1.85 MB), binary-limit: 1, binary-skipped: 750',
  );
  assert.equal(describeOmissions(none, 0), '');
});

const slot = (reason: string, detail?: string) =>
  ({
    id: 'jscpd',
    state: reason === 'suppression-scan-limit' ? 'failed' : 'limited',
    evidence: 'none',
    reason,
    detail,
  }) as never;
const scope = {
  repository: 'o/r',
  commitSha: 'a'.repeat(40),
  runId: 'r',
} as never;

await test('report rows keep the stable reason token first and add the cause breakdown after it', () => {
  const omitted = fromSlot(
    'gitleaks',
    slot('snapshot-entries-omitted'),
    undefined,
    scope,
    { count: 750, bytes: 1 },
    'oversized-blob: 3 (largest 1.85 MB), binary-skipped: 750',
  );
  assert.equal(
    omitted.reason,
    'snapshot-entries-omitted (oversized-blob: 3 (largest 1.85 MB), binary-skipped: 750)',
  );
  const limit = fromSlot(
    'jscpd',
    slot('suppression-scan-limit', 'totalBytes'),
    undefined,
    scope,
  );
  assert.equal(limit.reason, 'suppression-scan-limit (totalBytes)');
  assert.equal(
    fromSlot('jscpd', slot('source-suppression-directive'), undefined, scope)
      .reason,
    'source-suppression-directive',
  );
});

await test('bounded-file omissions report the largest oversized file and per-cause counts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qs-largest-'));
  try {
    await writeFile(join(dir, 'a.md'), 'x'.repeat(1100000));
    await writeFile(join(dir, 'b.md'), 'x'.repeat(1500000));
    const read = await readBoundedFiles(dir, ['a.md', 'b.md'], () => true);
    assert.equal(read.causes['file-too-large'], 2);
    assert.equal(read.largestOversizedBytes, 1500000);
    const completed = {
      engine: 'prettier',
      status: 'completed',
      findings: [],
    } as unknown as EngineResult;
    assert.match(
      applyOmitted(
        completed,
        read.omitted,
        read.causes,
        read.largestOversizedBytes,
      ).reason ?? '',
      /\(file-too-large: 2 \(largest 1\.50 MB\)\)$/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('trivy input selection is by content: non-IaC JSON is excluded, over-bound IaC JSON is still omitted', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qs-trivy-'));
  try {
    const openapi = JSON.stringify({
      openapi: '3.1.0',
      paths: { '/a': { get: { summary: 'x'.repeat(1600000) } } },
    });
    const template = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: { B: { Type: 'AWS::S3::Bucket', Pad: 'x'.repeat(1600000) } },
    });
    await writeFile(join(dir, 'openapi.json'), openapi);
    await writeFile(join(dir, 'template.json'), template);
    await writeFile(join(dir, 'data.json'), JSON.stringify([1, 2, 3]));
    await writeFile(join(dir, 'small-template.json'), '{"Resources":{}}');
    await writeFile(join(dir, 'broken.json'), '{ not json');
    await writeFile(join(dir, 'ci.yml'), 'a: 1\n');
    const classify = {
      bytes: snapshotBounds.sourceFileBytes,
      isInput: isIacContent,
    };
    const read = await readBoundedFiles(
      dir,
      [
        'openapi.json',
        'template.json',
        'data.json',
        'small-template.json',
        'broken.json',
        'ci.yml',
      ],
      () => true,
      classify,
    );
    assert.deepEqual(Object.keys(read.files).sort(), [
      'broken.json',
      'ci.yml',
      'small-template.json',
    ]);
    assert.equal(read.notInput, 2);
    assert.deepEqual(read.causes, { 'file-too-large': 1 });
    assert.equal(read.omitted, 1);
    // Without the classifier the OpenAPI document is an omission, as before.
    const plain = await readBoundedFiles(dir, ['openapi.json'], () => true);
    assert.equal(plain.omitted, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('non-IaC JSON does not spend the trivy total-size budget; real IaC past the budget is still omitted', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qs-trivy-total-'));
  try {
    const names: string[] = [];
    for (let index = 0; index < 20; index++) {
      names.push(`design${String(index)}.json`);
      await writeFile(
        join(dir, names[index]),
        JSON.stringify({ screens: 'x'.repeat(900000) }),
      );
    }
    await writeFile(join(dir, 'k8s.json'), '{"apiVersion":"v1","kind":"Pod"}');
    names.push('k8s.json');
    const classify = {
      bytes: snapshotBounds.sourceFileBytes,
      isInput: isIacContent,
    };
    const read = await readBoundedFiles(dir, names, () => true, classify);
    assert.deepEqual(Object.keys(read.files), ['k8s.json']);
    assert.equal(read.omitted, 0);
    assert.equal(read.notInput, 20);
    const without = await readBoundedFiles(dir, names, () => true);
    assert.equal(without.causes['total-size-limit'], 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('isIacContent keeps every JSON shape trivy can parse and anything it cannot judge', () => {
  const keep = (path: string, value: unknown) =>
    isIacContent(
      path,
      typeof value === 'string' ? value : JSON.stringify(value),
    );
  assert.equal(
    keep('a.json', { AWSTemplateFormatVersion: '2010-09-09' }),
    true,
  );
  assert.equal(keep('a.json', { apiVersion: 'v1', kind: 'Pod' }), true);
  assert.equal(keep('a.json', { planned_values: {} }), true);
  assert.equal(
    keep('a.json', {
      $schema:
        'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    }),
    true,
  );
  assert.equal(keep('a.json', { contentVersion: '1', resources: [] }), true);
  assert.equal(keep('a.json', '{ unparseable'), true);
  assert.equal(keep('x.tf.json', [1]), true);
  assert.equal(keep('a.yaml', 'a: 1'), true);
  assert.equal(keep('a.json', { openapi: '3.0.0', paths: {} }), false);
  assert.equal(keep('a.json', [{ kind: 'x' }]), false);
  assert.equal(keep('a.json', 3), false);
  assert.equal(keep('a.json', null), false);
});
