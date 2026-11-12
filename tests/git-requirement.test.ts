// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: Git version gate and its failure message using literal version strings; does not run Git.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isSupportedGitVersion } from '../src/committed-snapshot.js';
import { assertGitVersion } from './git-requirement.js';

await test('Git version gate accepts 2.47+ and rejects older or malformed Git', () => {
  for (const ok of ['2.47.0', '2.50.1', '2.53.2'])
    assert.equal(isSupportedGitVersion(`git version ${ok}\n`), true, ok);
  for (const bad of ['2.43.0', '2.46.9', '1.9.0', '3.0.0'])
    assert.equal(isSupportedGitVersion(`git version ${bad}\n`), false, bad);
  assert.equal(isSupportedGitVersion('git version 2.50.1 extra\n'), false);
});

await test('unsupported Git yields an actionable requirement message', () => {
  assert.throws(
    () => assertGitVersion('git version 2.43.0\n', '/usr/bin/git'),
    /Git >= 2\.47.*\/usr\/bin\/git.*2\.43\.0.*CODE_QUALITY_GIT_EXECUTABLE/s,
  );
  assert.doesNotThrow(() => assertGitVersion('git version 2.47.1\n', 'g'));
});
