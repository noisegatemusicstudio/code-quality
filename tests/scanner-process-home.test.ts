// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: Runs real bounded Node child processes through runScannerProcess to prove HOME is absent by default, set only on request to a private absolute directory, and that tflint opts in; runs no scanner engine and touches no network.
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { tflintAdapter } from '../src/lint-adapters.js';
import { runScannerProcess } from '../src/scanner-process.js';

const linux = process.platform === 'linux';
const base = {
  executable: process.execPath,
  cwd: tmpdir(),
  timeoutMs: 5000,
  outputLimit: 1024,
  args: ['-e', 'console.log(process.env.HOME ?? "absent")'],
};

await test(
  'HOME is not inherited: absent by default',
  { skip: !linux },
  async () => {
    const r = await runScannerProcess(base);
    assert.equal(r.state, 'exited');
    assert.equal(r.stdout.toString(), 'absent\n');
  },
);

await test(
  'an opted-in HOME is the given private directory, not the real one',
  { skip: !linux },
  async () => {
    const r = await runScannerProcess({ ...base, home: '/private/scan-home' });
    assert.equal(r.state, 'exited');
    assert.equal(r.stdout.toString(), '/private/scan-home\n');
  },
);

await test(
  'a relative or NUL-containing HOME is refused before anything runs',
  { skip: !linux },
  async () => {
    for (const home of ['relative/home', '', '/a\0b'])
      assert.equal(
        (await runScannerProcess({ ...base, home })).state,
        'failed',
        JSON.stringify(home),
      );
  },
);

await test('the tflint adapter opts in to a private HOME', () => {
  const adapter = tflintAdapter({
    executable: '/usr/bin/tflint',
    files: [],
  } as unknown as Parameters<typeof tflintAdapter>[0]);
  assert.equal(adapter.privateHome, true);
});
