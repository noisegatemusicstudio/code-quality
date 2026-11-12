// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: shared helper that resolves the Git used by fixtures and fails with an explicit requirement message when it is too old; it is not itself a test.
import { execFileSync } from 'node:child_process';
import {
  isSupportedGitVersion,
  MINIMUM_GIT_VERSION,
} from '../src/committed-snapshot.js';
import { systemGit } from '../src/system-git.js';

/** Git executable for fixtures: the system Git, or CODE_QUALITY_GIT_EXECUTABLE. */
export function requireSupportedGit(): string {
  const executable = systemGit(
    process.platform,
    process.env.CODE_QUALITY_GIT_EXECUTABLE,
  );
  let version: string;
  try {
    version = execFileSync(executable, ['--version'], {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
    });
  } catch {
    version = '';
  }
  assertGitVersion(version, executable);
  return executable;
}

export function assertGitVersion(version: string, executable: string): void {
  if (!isSupportedGitVersion(version))
    throw new Error(
      `Tests need Git >= ${MINIMUM_GIT_VERSION} (committed snapshots rely on GIT_NO_LAZY_FETCH); ` +
        `${executable} reports ${JSON.stringify(version.trim() || 'no version')}. ` +
        'Install a newer Git or set CODE_QUALITY_GIT_EXECUTABLE to an absolute path of one.',
    );
}
