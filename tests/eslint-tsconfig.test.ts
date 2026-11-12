/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves the eslint-tsconfig admission rules (repo-relative, no "..", JSON only, tracked, extends only tracked repository files, bounded chain) on in-memory file sets; runs no ESLint and reads no disk.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  resolveTsconfigChain,
  tsconfigChainLimits,
  tsconfigPathProblem,
} from '../src/eslint-tsconfig.js';

const chain = (files: Record<string, string>, path: string) =>
  resolveTsconfigChain(path, new Set(Object.keys(files)), (p) =>
    Promise.resolve(files[p]),
  );
const refusal = async (files: Record<string, string>, path: string) => {
  const r = await chain(files, path);
  return r.ok ? 'accepted' : r.refusal;
};

await test('a tracked repo-relative tsconfig .json is accepted with its own text', async () => {
  const files = {
    'packages/a/tsconfig.json': '{ /* comment */ "include": [] }',
  };
  const r = await chain(files, 'packages/a/tsconfig.json');
  assert.ok(r.ok);
  assert.deepEqual(r.files, files);
});

await test('path traversal and non-repo-relative forms are refused', async () => {
  const files = { 'tsconfig.json': '{}' };
  for (const bad of [
    '../tsconfig.json',
    'a/../tsconfig.json',
    '/etc/tsconfig.json',
    './tsconfig.json',
    'C:/tsconfig.json',
    'a\\tsconfig.json',
    'node_modules/pkg/tsconfig.json',
    'sp ace/tsconfig.json',
    '',
  ]) {
    assert.equal(await refusal(files, bad), 'invalid-path', bad);
    assert.ok(tsconfigPathProblem(bad), bad);
  }
});

await test('a non-JSON file is refused even when tracked', async () => {
  const files = { 'tsconfig.ts': 'export default {}', tsconfig: '{}' };
  assert.equal(await refusal(files, 'tsconfig.ts'), 'not-json');
  assert.equal(await refusal(files, 'tsconfig'), 'not-json');
});

await test('an untracked tsconfig is refused', async () => {
  assert.equal(
    await refusal({ 'other.json': '{}' }, 'tsconfig.json'),
    'not-tracked',
  );
});

await test('extends may point at tracked repository files only', async () => {
  const files = {
    'tsconfig.json': '{"extends":["./base","./configs/strict.json"]}',
    'base.json': '{}',
    'configs/strict.json': '{"extends":"../base.json"}',
  };
  const r = await chain(files, 'tsconfig.json');
  assert.ok(r.ok);
  assert.deepEqual(Object.keys(r.files).sort(), Object.keys(files).sort());
});

await test('extends of a package or node_modules file is refused', async () => {
  for (const entry of [
    '@tsconfig/node20/tsconfig.json',
    'some-package',
    './node_modules/@tsconfig/node20/tsconfig.json',
    '/abs/base.json',
  ]) {
    const files = {
      'tsconfig.json': JSON.stringify({ extends: entry }),
      'node_modules/@tsconfig/node20/tsconfig.json': '{}',
    };
    const r = await chain(files, 'tsconfig.json');
    assert.ok(!r.ok, entry);
    assert.equal(r.refusal, 'extends-package', entry);
    assert.match(r.detail, /extends/);
  }
});

await test('extends that leaves the repository or is untracked is refused', async () => {
  assert.equal(
    await refusal(
      { 'tsconfig.json': '{"extends":"../../base.json"}' },
      'tsconfig.json',
    ),
    'extends-outside-repository',
  );
  assert.equal(
    await refusal(
      { 'tsconfig.json': '{"extends":"./missing.json"}' },
      'tsconfig.json',
    ),
    'extends-untracked',
  );
});

await test('a malformed tsconfig or extends value is refused, a cycle is tolerated', async () => {
  assert.equal(
    await refusal({ 'tsconfig.json': '{' }, 'tsconfig.json'),
    'invalid-config',
  );
  assert.equal(
    await refusal({ 'tsconfig.json': '{"extends":3}' }, 'tsconfig.json'),
    'invalid-config',
  );
  const cyclic = {
    'a.json': '{"extends":"./b.json"}',
    'b.json': '{"extends":"./a.json"}',
  };
  assert.equal(await refusal(cyclic, 'a.json'), 'accepted');
});

await test('an unreadable file is refused and the chain is bounded', async () => {
  const unreadable = await resolveTsconfigChain(
    'tsconfig.json',
    new Set(['tsconfig.json']),
    () => Promise.resolve(undefined),
  );
  assert.ok(!unreadable.ok && unreadable.refusal === 'unreadable');
  const deep: Record<string, string> = {};
  const n = tsconfigChainLimits.depth + 2;
  for (let i = 0; i < n; i += 1)
    deep[`c${String(i)}.json`] = JSON.stringify({
      extends: `./c${String(i + 1)}.json`,
    });
  deep[`c${String(n)}.json`] = '{}';
  assert.equal(await refusal(deep, 'c0.json'), 'extends-too-deep');
  const wide: Record<string, string> = {
    'tsconfig.json': JSON.stringify({
      extends: Array.from(
        { length: tsconfigChainLimits.files + 1 },
        (_, i) => `./w${String(i)}.json`,
      ),
    }),
  };
  for (let i = 0; i <= tsconfigChainLimits.files; i += 1)
    wide[`w${String(i)}.json`] = '{}';
  assert.equal(await refusal(wide, 'tsconfig.json'), 'extends-too-deep');
});
