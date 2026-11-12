import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const maxTreeFiles = 2000;
const maxTreeBytes = 512 * 1024 * 1024;

/**
 * Digest of an installed distribution (PMD ships as a directory of jars, not
 * one executable). It is the sha256 of the text made of one line per regular
 * file, `<file sha256>  <path relative to the root>`, sorted by path, each line
 * ending in a newline. A symlink, device or any other non-regular entry, an
 * oversized tree, or an unreadable file throws, so a tampered or surprising
 * tree can never hash to a pin.
 */
export async function treeDigest(root: string): Promise<string> {
  const lines: string[] = [];
  let total = 0;
  const walk = async (relative: string): Promise<void> => {
    for (const entry of await readdir(join(root, relative))) {
      const path = relative === '' ? entry : `${relative}/${entry}`;
      const info = await lstat(join(root, path));
      if (info.isDirectory()) await walk(path);
      else if (info.isFile()) {
        total += info.size;
        if (lines.length >= maxTreeFiles || total > maxTreeBytes)
          throw new Error('tree too large');
        const hash = createHash('sha256')
          .update(await readFile(join(root, path)))
          .digest('hex');
        lines.push(`${hash}  ${path}\n`);
      } else throw new Error('unexpected entry in tree');
    }
  };
  await walk('');
  lines.sort((a, b) => {
    const pa = a.slice(66);
    const pb = b.slice(66);
    return pa < pb ? -1 : pa > pb ? 1 : 0;
  });
  return createHash('sha256').update(lines.join('')).digest('hex');
}

/** True only when the tree at `root` exists and hashes to `expected`. */
export async function treeMatches(
  root: string,
  expected: string,
): Promise<boolean> {
  try {
    return (await treeDigest(root)) === expected;
  } catch {
    return false;
  }
}

/**
 * Extract a verified zip into `target` and refuse unless the extracted tree
 * (below the archive's single top-level `member` directory) matches the pinned
 * digest. The tree is built in a temporary directory and only renamed into
 * place after the check, so a failed install leaves nothing behind.
 */
export async function installZipTree(options: {
  bytes: Uint8Array;
  member: string;
  treeSha256: string;
  target: string;
}): Promise<string> {
  // Work beside the target so the final rename stays on one filesystem.
  await mkdir(dirname(options.target), { recursive: true });
  const work = await mkdtemp(join(dirname(options.target), '.install-'));
  try {
    const archive = join(work, 'asset.zip');
    await writeFile(archive, options.bytes, { flag: 'wx' });
    const out = join(work, 'out');
    await mkdir(out);
    await exec('unzip', ['-q', archive, '-d', out]);
    const extracted = join(out, options.member);
    if (!(await treeMatches(extracted, options.treeSha256)))
      throw new Error('extracted tree sha256 mismatch');
    await rm(options.target, { recursive: true, force: true });
    await rename(extracted, options.target);
    return options.target;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
