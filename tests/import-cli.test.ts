import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { scannerIds } from '../src/scan-report.js';

const sha = 'a'.repeat(40);
const cli = new URL('../src/import-cli.js', import.meta.url);
const invoke = (args: string[], input: string | Buffer) => {
  const result = spawnSync(process.execPath, [fileURLToPath(cli), ...args], {
    input,
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.stderr, '');
  assert.equal(result.signal, null);
  const output: unknown = JSON.parse(result.stdout);
  return { status: result.status, output, text: result.stdout };
};

await test('CLI returns versioned count-only parser wrappers, not completion', () => {
  const result = invoke(['eslint', sha], '[]');
  assert.equal(result.status, 0);
  assert.deepEqual(result.output, {
    schemaVersion: 1,
    commitSha: sha,
    provenance: 'imported-unverified',
    dialect: 'eslint-10.13.0-json',
    status: 'parsed',
    findingCount: 0,
  });
  const metrics = Object.fromEntries(
    ['lines', 'statements', 'functions', 'branches'].map((name) => [
      name,
      { total: 0, covered: 0, skipped: 0, pct: 'SECRET' },
    ]),
  );
  const coverage = invoke(
    ['coverage', sha],
    JSON.stringify({ total: metrics, SECRET: '/private/path' }),
  );
  assert.equal(coverage.status, 0);
  assert.equal(coverage.text.includes('SECRET'), false);
  assert.equal(coverage.text.includes('/private/path'), false);
  assert.deepEqual(coverage.output, {
    schemaVersion: 1,
    commitSha: sha,
    provenance: 'imported-unverified',
    dialect: 'istanbul-reports-3.1.7-json-summary',
    status: 'parsed',
    metrics: Object.fromEntries(
      Object.keys(metrics).map((name) => [
        name,
        { total: 0, covered: 0, skipped: 0, percentage: null },
      ]),
    ),
  });
});

await test('CLI aggregate completion and incomplete exit codes preserve all slots', () => {
  const input = Object.fromEntries(
    scannerIds.map((id) => [
      id,
      { commitSha: sha, state: 'completed', findingCount: 8, secret: 'SECRET' },
    ]),
  );
  const complete = invoke(['aggregate', sha], JSON.stringify(input));
  assert.equal(complete.status, 0);
  assert.deepEqual(complete.output, {
    schemaVersion: 1,
    commitSha: sha,
    provenance: 'imported-unverified',
    status: 'complete',
    scanners: scannerIds.map((id) => ({
      id,
      state: 'completed',
      findingCount: 8,
    })),
  });
  assert.equal(complete.text.includes('SECRET'), false);
  for (const raw of ['{}', 'null', '{"eslint":{"state":"failed"}}']) {
    assert.equal(invoke(['aggregate', sha], raw).status, 1);
  }
});

await test('CLI rejects malformed, oversized and invalid UTF-8 stdin without leaks', () => {
  for (const command of ['aggregate', 'eslint', 'coverage']) {
    for (const raw of [
      '{SECRET/private/path',
      ' '.repeat(262145),
      JSON.stringify('é'.repeat(140000)),
      Buffer.from([0xff]),
      Buffer.concat([Buffer.from('[] '), Buffer.from([0xc0, 0xaf])]),
    ]) {
      const result = invoke([command, sha], raw);
      assert.equal(result.status, 2);
      assert.equal(result.text.includes('SECRET'), false);
      assert.equal(result.text.includes('/private/path'), false);
    }
  }
  assert.equal(invoke(['eslint', sha], '[]' + ' '.repeat(262142)).status, 0);
  assert.equal(
    invoke(['eslint', sha], '[{"messages":[],"source":"é"}]').status,
    2,
  );
});

await test('CLI accepts exactly a known command and lowercase declared commit', () => {
  for (const args of [
    [],
    ['eslint'],
    ['unknown', sha],
    ['eslint', sha, '/private/SECRET'],
    ['eslint', sha + '\n'],
    ['eslint', sha.toUpperCase()],
    ['eslint', '--config'],
    ['--help', sha],
    ['coverage', 'a'.repeat(39)],
  ]) {
    const result = invoke(args, '[]');
    assert.equal(result.status, 2);
    assert.deepEqual(result.output, { schemaVersion: 1, status: 'invalid' });
  }
});

await test('CLI help explains import limits without reading stdin', () => {
  const result = invoke(['--help'], 'SECRET');
  assert.equal(result.status, 0);
  assert.equal(result.text.includes('SECRET'), false);
  assert.deepEqual(result.output, {
    schemaVersion: 1,
    status: 'help',
    usage:
      'node dist/src/import-cli.js aggregate|eslint|coverage <declared-commit>',
    input: 'UTF-8 JSON on stdin only, at most 262144 bytes',
    declaredCommit: 'Exactly 40 lowercase hexadecimal characters',
    provenance: 'imported-unverified',
    meaning:
      'Parsed or complete imported evidence is not a passing quality gate or proof of scanner execution.',
    exitCodes: {
      '0': 'Parsed import or complete aggregate',
      '1': 'Incomplete aggregate',
      '2': 'Invalid arguments, input or I/O',
    },
  });
});

await test('CLI closed stdout fails quietly without stack or path leakage', async () => {
  const child = spawn(process.execPath, [fileURLToPath(cli), '--help'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 5000,
  });
  child.stdout.destroy();
  child.stdin.end();
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  const result = await new Promise<{
    code: number | null;
    signal: string | null;
  }>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      resolve({ code, signal });
    });
  });
  assert.deepEqual(result, { code: 2, signal: null });
  assert.equal(stderr, '');
});

await test('package consumer can import each public import API', async () => {
  const report = await import('@releaseready/code-quality/scan-report');
  const eslint = await import('@releaseready/code-quality/eslint-import');
  const coverage = await import('@releaseready/code-quality/coverage-import');
  assert.equal(report.aggregateScanReport(sha, {}).status, 'incomplete');
  assert.deepEqual(eslint.parseEslintJson('[]'), {
    status: 'parsed',
    findingCount: 0,
  });
  assert.deepEqual(coverage.parseCoverageSummary('{}'), { status: 'invalid' });
});
