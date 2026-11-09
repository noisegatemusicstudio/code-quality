import { posix, win32 } from 'node:path';

// Never resolve Git through PATH: hooks prepend repository-owned node_modules/.bin.
// An override is an explicit trusted installation choice, not discovered input.
export function systemGit(
  platform: NodeJS.Platform,
  override?: string,
): string {
  if (override !== undefined) {
    const absolute =
      platform === 'win32'
        ? win32.isAbsolute(override) && /^[a-z]:[\\/]/i.test(override)
        : posix.isAbsolute(override);
    if (!absolute || override.includes('\0')) {
      throw new Error(
        'CODE_QUALITY_GIT_EXECUTABLE must name an absolute local Git executable (a drive-rooted path on Windows).',
      );
    }
    return override;
  }
  if (platform === 'win32') return 'C:\\Program Files\\Git\\cmd\\git.exe';
  if (platform === 'freebsd') return '/usr/local/bin/git';
  return '/usr/bin/git';
}
