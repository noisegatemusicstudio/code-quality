import { spawnSync } from 'node:child_process';
import { systemGit } from './system-git.js';

let executable: string;
try {
  executable = systemGit(
    process.platform,
    process.env.CODE_QUALITY_GIT_EXECUTABLE,
  );
} catch {
  console.error(
    'Invalid CODE_QUALITY_GIT_EXECUTABLE: use an absolute local Git executable path; commit checks stopped.',
  );
  process.exit(1);
}

const result = spawnSync(
  executable,
  ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'],
  { encoding: 'utf8' },
);
if (result.error || result.status !== 0) {
  console.error(
    `Unable to read staged filenames using ${executable}; commit checks stopped. Install Git at this location or explicitly set CODE_QUALITY_GIT_EXECUTABLE to your trusted absolute Git path.`,
  );
  process.exit(1);
}
const unsupported = result.stdout
  .split('\0')
  .filter((name) => name.includes('\\'));
if (unsupported.length) {
  console.error(
    'Literal backslashes in filenames are unsupported. Rename these paths explicitly and stage the changes before committing:',
  );
  for (const name of unsupported) console.error(JSON.stringify(name));
  process.exit(1);
}
