import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  aggregateScanReport as run,
  scannerIds as ids,
} from '../src/scan-report.js';
const sha = 'a'.repeat(40);
const good = () =>
  Object.fromEntries(
    ids.map((id) => [
      id,
      { commitSha: sha, state: 'completed', findingCount: 2 },
    ]),
  );
const slot = (value: unknown) => run(sha, { eslint: value }).scanners[0];
await test('fixed required slots and no implied execution', () => {
  assert.deepEqual(ids, [
    'eslint',
    'typescript',
    'gitleaks',
    'osv',
    'jscpd',
    'tests',
    'coverage',
  ]);
  assert.deepEqual(run(sha, {}), {
    schemaVersion: 1,
    commitSha: sha,
    provenance: 'imported-unverified',
    status: 'incomplete',
    scanners: ids.map((id) => ({ id, state: 'missing' })),
  });
  assert.equal(run(sha, { eslint: good().eslint }).status, 'incomplete');
});
await test('completion is independent of findings; order and output are deterministic', () => {
  const input = good();
  const before = JSON.stringify(input);
  const report = run(sha, input);
  assert.deepEqual(report, {
    schemaVersion: 1,
    commitSha: sha,
    provenance: 'imported-unverified',
    status: 'complete',
    scanners: ids.map((id) => ({ id, state: 'completed', findingCount: 2 })),
  });
  assert.deepEqual(
    run(sha, Object.fromEntries(Object.entries(input).reverse())),
    report,
  );
  assert.equal(JSON.stringify(input), before);
  assert.equal(
    run(
      sha,
      Object.fromEntries(
        ids.map((id) => [id, { ...input[id], findingCount: 0 }]),
      ),
    ).status,
    'complete',
  );
});
await test('each required slot fails closed', () => {
  for (const id of ids) {
    for (const state of ['failed', 'timed-out']) {
      const report = run(sha, {
        ...good(),
        [id]: { commitSha: sha, state, findingCount: 999, message: 'secret' },
      });
      assert.equal(report.status, 'incomplete');
      assert.deepEqual(
        report.scanners.find((x) => x.id === id),
        { id, state },
      );
    }
    const input = good();
    delete input[id];
    assert.equal(run(sha, input).status, 'incomplete');
  }
});
await test('malformed imports cannot claim completion', () => {
  for (const value of [
    null,
    [],
    1,
    'completed',
    {},
    { state: 'completed' },
    { commitSha: sha, state: 'registered' },
    { commitSha: 'b'.repeat(40), state: 'completed', findingCount: 0 },
    ...[
      undefined,
      -1,
      1.5,
      NaN,
      Infinity,
      Number.MAX_SAFE_INTEGER + 1,
      '0',
    ].map((findingCount) => ({
      commitSha: sha,
      state: 'completed',
      findingCount,
    })),
  ]) {
    assert.deepEqual(slot(value), { id: 'eslint', state: 'invalid' });
  }
  for (const value of [null, [], 1, 'x', undefined]) {
    assert.deepEqual(
      run(sha, value).scanners,
      ids.map((id) => ({ id, state: 'invalid' })),
    );
  }
});
await test('only own slot and record fields count; metadata is allowlisted', () => {
  assert.equal(run(sha, Object.create(good())).status, 'incomplete');
  assert.deepEqual(slot(Object.create(good().eslint)), {
    id: 'eslint',
    state: 'invalid',
  });
  const clean = { id: 'eslint', state: 'completed', findingCount: 0 };
  assert.deepEqual(
    slot({
      commitSha: sha,
      state: 'completed',
      findingCount: 0,
      message: 'secret',
      payload: { source: 'private' },
    }),
    clean,
  );
  assert.deepEqual(
    run(sha, { ...good(), unknown: { message: 'secret' } }),
    run(sha, good()),
  );
  const frozen = Object.freeze(
    Object.fromEntries(ids.map((id) => [id, Object.freeze(good()[id])])),
  );
  assert.equal(run(sha, frozen).status, 'complete');
});
await test('target SHA is exactly lowercase 40-digit hexadecimal', () => {
  for (const value of [
    '',
    'a'.repeat(39),
    'a'.repeat(41),
    'A'.repeat(40),
    'g'.repeat(40),
    'a'.repeat(40) + '\n',
  ])
    assert.throws(() => run(value, good()), TypeError);
});

await test('required scanner slots are immutable for JavaScript consumers', () => {
  assert.equal(Object.isFrozen(ids), true);
  assert.equal(Reflect.defineProperty(ids, '0', { value: 'unknown' }), false);
  assert.equal(Reflect.set(ids, 'length', 0), false);
  assert.equal(ids.length, 7);
  assert.equal(ids[0], 'eslint');
});
await test('target SHA rejects non-string runtime values without coercion', () => {
  const boxed: unknown = Object(sha);
  for (const value of [
    null,
    undefined,
    123,
    boxed,
    {},
    { toString: () => sha },
  ]) {
    assert.throws(() => run(value as string, good()), TypeError);
  }
});
