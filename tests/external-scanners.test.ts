/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Exercises external scanner report parsing and tool refusal with synthetic reports; real pinned binaries run only when already installed locally.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  runExternalScanner,
  parseExternalReport,
} from '../src/external-scanners.js';

const installed = async (name: string) => {
  try {
    await access(resolve('.fixtures/scanner-tools', name));
    return true;
  } catch {
    return false;
  }
};

await test('external parsers remain count-only and reject malformed/contradictory reports', () => {
  assert.deepEqual(parseExternalReport('gitleaks', Buffer.from('[]')), {
    findingCount: 0,
    findings: [],
  });
  assert.equal(
    parseExternalReport('gitleaks', Buffer.from('[{"Secret":"RAW_SECRET"}]')),
    null,
  );
  assert.equal(
    parseExternalReport(
      'jscpd',
      Buffer.from('{"statistics":{},"duplicates":[]}'),
    ),
    null,
  );
  assert.equal(parseExternalReport('jscpd', Buffer.alloc(1048577)), null);
  assert.equal(parseExternalReport('gitleaks', Buffer.from([255])), null);
});

await test('absent and mismatched native tools never imply execution', async () => {
  assert.equal(
    (await runExternalScanner('gitleaks', tmpdir())).state,
    'missing',
  );
  const result = await runExternalScanner(
    'gitleaks',
    tmpdir(),
    process.execPath,
  );
  assert.equal(result.state, 'failed');
  assert.equal(result.evidence, 'none');
  assert.ok(!JSON.stringify(result).includes(process.execPath));
});

await test(
  'real pinned Gitleaks executes offline with default rules and distinguishes findings',
  {
    skip: !(await installed('gitleaks'))
      ? 'Pinned development binary not installed; no automatic download'
      : false,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'gitleaks-fixture-'));
    try {
      await writeFile(
        join(directory, 'source.ts'),
        'export const value = 7;\n',
      );
      const executable = resolve('.fixtures/scanner-tools/gitleaks');
      let report = await runExternalScanner('gitleaks', directory, executable);
      assert.equal(report.state, 'completed');
      assert.equal(report.findingCount, 0);
      const synthetic = 'ghp_' + 'G7xQ4m2V9pR6zH8k3J5sN1wB0tC4yF7dL9uE';
      await writeFile(
        join(directory, 'source.ts'),
        `const token = "${synthetic}"; // gitleaks:allow\n`,
      );
      await writeFile(
        join(directory, '.gitleaks.toml'),
        'title="Caller suppression must not load"\n[allowlist]\nregexes=[".*"]\n',
      );
      report = await runExternalScanner('gitleaks', directory, executable);
      assert.equal(report.state, 'completed');
      assert.ok((report.findingCount ?? 0) > 0);
      assert.ok(!JSON.stringify(report).includes(synthetic));
      assert.ok(!JSON.stringify(report).includes(directory));
      await writeFile(join(directory, '.gitleaksignore'), '*');
      report = await runExternalScanner('gitleaks', directory, executable);
      assert.equal(report.state, 'limited');
      assert.equal(report.reason, 'source-suppression-file');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

await test(
  'real pinned native jscpd counts duplicates without project config or JavaScript reporters',
  {
    skip: !(await installed('jscpd'))
      ? 'Pinned development binary not installed; no automatic download'
      : false,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'jscpd-fixture-'));
    try {
      await mkdir(join(directory, 'src'));
      const code = Array.from(
        { length: 30 },
        (_, i) => `export const value${i} = ${i} + 3;`,
      ).join('\n');
      await writeFile(join(directory, 'src/a.ts'), code);
      await writeFile(join(directory, 'src/b.ts'), code);
      await writeFile(
        join(directory, '.jscpd.json'),
        '{"ignore":["**/*"],"reporters":["./evil.js"]}',
      );
      await writeFile(join(directory, '.gitignore'), '*');
      const report = await runExternalScanner(
        'jscpd',
        directory,
        resolve('.fixtures/scanner-tools/jscpd'),
      );
      assert.equal(report.state, 'completed');
      assert.ok((report.findingCount ?? 0) > 0);
      assert.equal(report.evidence, 'executed');
      assert.ok(!JSON.stringify(report).includes('value29'));
      assert.ok(!JSON.stringify(report).includes(directory));
      const marker = 'jscpd' + ':ignore';
      await writeFile(
        join(directory, 'src/a.ts'),
        // Assembled at runtime so no committed file contains the directive
        // text, which would itself trip the scanner's suppression guard.
        `// ${marker}-start\n${code}\n// ${marker}-end\n`,
      );
      const suppressed = await runExternalScanner(
        'jscpd',
        directory,
        resolve('.fixtures/scanner-tools/jscpd'),
      );
      assert.equal(suppressed.state, 'limited');
      assert.equal(suppressed.reason, 'source-suppression-directive');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
