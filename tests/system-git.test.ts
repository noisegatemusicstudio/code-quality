import assert from 'node:assert/strict';
import { test } from 'node:test';
import { systemGit } from '../src/system-git.js';

await test('Git selection uses fixed system paths on each platform', () => {
  assert.equal(systemGit('linux'), '/usr/bin/git');
  assert.equal(systemGit('darwin'), '/usr/bin/git');
  assert.equal(systemGit('freebsd'), '/usr/local/bin/git');
  assert.equal(systemGit('win32'), 'C:\\Program Files\\Git\\cmd\\git.exe');
});

await test('Explicit trusted absolute Git installations work across OS path conventions', () => {
  for (const path of [
    '/nix/store/hash-git/bin/git',
    '/opt/custom git/bin/git',
  ]) {
    assert.equal(systemGit('linux', path), path);
    assert.equal(systemGit('darwin', path), path);
  }
  for (const path of [
    'D:\\Program Files\\Git\\cmd\\git.exe',
    'D:/Git/cmd/git.exe',
  ]) {
    assert.equal(systemGit('win32', path), path);
  }
});

await test('Invalid overrides fail closed instead of using defaults or PATH', () => {
  for (const platform of ['linux', 'darwin', 'win32'] as const) {
    for (const path of ['', 'git', './git', '../git', '/git\0evil']) {
      assert.throws(() => systemGit(platform, path), /absolute local Git/);
    }
  }
  for (const path of [
    'C:git.exe',
    '\\git.exe',
    '\\\\server\\share\\git.exe',
    '/usr/bin/git',
  ]) {
    assert.throws(() => systemGit('win32', path), /absolute local Git/);
  }
});
