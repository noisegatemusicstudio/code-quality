import { createHash } from 'node:crypto';
import {
  mkdtemp,
  mkdir,
  writeFile,
  rm,
  lstat,
  readdir,
  realpath,
  open,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, isAbsolute, resolve } from 'node:path';
import { runScannerProcess } from './scanner-process.js';

export interface Snapshot {
  directory: string;
  commitSha: string;
  manifestSha256: string;
  fileCount: number;
  byteCount: number;
  gitVersion: string;
  dispose(): Promise<void>;
}
export class SnapshotError extends Error {
  constructor(
    public readonly code:
      'source-unavailable' | 'cleanup-failed' | 'cleanup-uncertain',
  ) {
    super(
      code === 'source-unavailable'
        ? 'Committed snapshot unavailable'
        : 'Committed snapshot cleanup failed',
    );
  }
}
/** Scans the immutable committed tree ONLY, not the checkout (dirty or clean).
 * The caller explicitly trusts its Git executable and object database directory.
 * No status/diff/archive, checkout, filters, project config or working-tree reads.
 * Rejects non-regular blobs, non-ASCII/unsafe paths and oversized trees.
 */
export async function createCommittedSnapshot(options: {
  gitExecutable: string;
  gitDirectory: string;
  commitSha: string;
}): Promise<Snapshot> {
  const fail = () => new SnapshotError('source-unavailable');
  if (
    typeof options.commitSha !== 'string' ||
    options.commitSha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(options.commitSha) ||
    typeof options.gitDirectory !== 'string' ||
    typeof options.gitExecutable !== 'string' ||
    !isAbsolute(options.gitDirectory) ||
    !isAbsolute(options.gitExecutable)
  )
    throw fail();
  let directory = '';
  let gitDirectory = '';
  let uncertain = false;
  const dispose = async () => {
    try {
      if (directory) await rm(directory, { recursive: true, force: true });
    } catch {
      throw new SnapshotError('cleanup-failed');
    }
  };
  const disposeObjects = async () => {
    try {
      if (gitDirectory)
        await rm(gitDirectory, { recursive: true, force: true });
    } catch {
      await dispose();
      throw new SnapshotError('cleanup-failed');
    }
  };
  const deadline = Date.now() + 30000;
  const checkDeadline = () => {
    if (Date.now() >= deadline) throw fail();
  };
  try {
    directory = await mkdtemp(join(tmpdir(), 'code-quality-snapshot-'));
    gitDirectory = await mkdtemp(join(tmpdir(), 'code-quality-objects-'));
    if (
      !(await lstat(options.gitDirectory)).isDirectory() ||
      (await realpath(options.gitDirectory)) !== resolve(options.gitDirectory)
    )
      throw fail();
    // Worktrees/alternates require a separately reviewed explicit object-store
    // strategy; do not silently traverse outside the supplied database.
    for (const path of ['commondir', 'shallow']) {
      try {
        await lstat(join(options.gitDirectory, path));
        throw fail();
      } catch (error) {
        if (
          !(error instanceof Error) ||
          !('code' in error) ||
          error.code !== 'ENOENT'
        )
          throw fail();
      }
    }
    // Copy only bounded ordinary object files into a config-free owned Git-dir.
    // Original local config, include/includeIf, refs and credentials are NEVER read.
    // Copying also closes races with concurrent repository object repacking.
    const objects = join(options.gitDirectory, 'objects');
    if (
      !(await lstat(objects)).isDirectory() ||
      (await realpath(objects)) !== objects
    )
      throw fail();
    await mkdir(join(gitDirectory, 'objects'), { mode: 0o700 });
    await mkdir(join(gitDirectory, 'refs'), { mode: 0o700 });
    await writeFile(join(gitDirectory, 'HEAD'), 'ref: refs/heads/unused\n', {
      mode: 0o600,
    });
    await writeFile(
      join(gitDirectory, 'config'),
      '[core]\nrepositoryformatversion = 0\nbare = true\n',
      { mode: 0o600 },
    );
    let objectBytes = 0;
    let objectFiles = 0;
    for (const name of await readdir(objects)) {
      checkDeadline();
      if (!/^(?:[a-f0-9]{2}|pack|info)$/.test(name)) throw fail();
      const from = join(objects, name);
      if (!(await lstat(from)).isDirectory() || (await realpath(from)) !== from)
        throw fail();
      if (name === 'info') {
        const names = await readdir(from);
        if (names.includes('alternates') || names.includes('http-alternates'))
          throw fail();
        continue;
      }
      await mkdir(join(gitDirectory, 'objects', name), { mode: 0o700 });
      for (const file of await readdir(from)) {
        checkDeadline();
        if (
          !(name === 'pack'
            ? /^pack-[a-f0-9]{40}\.(?:pack|idx|rev)$/.test(file)
            : /^[a-f0-9]{38}$/.test(file))
        )
          throw fail();
        if (++objectFiles > 20000) throw fail();
        const handle = await open(
          join(from, file),
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        try {
          const stat = await handle.stat();
          if (!stat.isFile() || stat.size > 67108864 - objectBytes)
            throw fail();
          objectBytes += stat.size;
          const bytes = Buffer.alloc(stat.size);
          let offset = 0;
          while (offset < bytes.length) {
            checkDeadline();
            const read = await handle.read(
              bytes,
              offset,
              bytes.length - offset,
              offset,
            );
            if (!read.bytesRead) throw fail();
            offset += read.bytesRead;
          }
          if ((await handle.stat()).size !== stat.size) throw fail();
          await writeFile(join(gitDirectory, 'objects', name, file), bytes, {
            flag: 'wx',
            mode: 0o600,
          });
        } finally {
          await handle.close();
        }
      }
    }
    const git = async (args: string[], limit: number) => {
      checkDeadline();
      const result = await runScannerProcess({
        executable: '/usr/bin/prlimit',
        args: [
          '--as=1073741824:1073741824',
          '--data=536870912:536870912',
          '--cpu=30:30',
          '--fsize=1048576:1048576',
          '--',
          options.gitExecutable,
          '--no-pager',
          '--git-dir',
          gitDirectory,
          ...args,
        ],
        cwd: directory,
        timeoutMs: Math.max(1, Math.min(5000, deadline - Date.now())),
        outputLimit: limit,
      });
      if (result.state === 'cleanup-uncertain') {
        uncertain = true;
        throw new SnapshotError('cleanup-uncertain');
      }
      if (result.state !== 'exited' || result.code !== 0) throw fail();
      return result.stdout;
    };
    const version = (await git(['--version'], 128)).toString();
    // GIT_NO_LAZY_FETCH is supported by this tested Git generation.
    if (!/^git version 2\.(?:4[7-9]|[5-9][0-9])\.\d+\n$/.test(version))
      throw fail();
    await git(
      [
        'fsck',
        '--full',
        '--strict',
        '--no-reflogs',
        '--no-dangling',
        options.commitSha,
      ],
      262144,
    );
    if (
      (await git(['cat-file', '-t', options.commitSha], 128)).toString() !==
      'commit\n'
    )
      throw fail();
    const commit = await git(['cat-file', 'commit', options.commitSha], 262144);
    if (
      createHash('sha1')
        .update(`commit ${commit.length}\0`)
        .update(commit)
        .digest('hex') !== options.commitSha
    )
      throw fail();
    const tree = await git(
      ['ls-tree', '-rz', '--full-tree', options.commitSha],
      262144,
    );
    const entries = tree.toString('utf8').split('\0');
    if (entries.pop() !== '' || entries.length > 1000) throw fail();
    const manifest = createHash('sha256');
    let byteCount = 0;
    for (const entry of entries) {
      const match =
        /^(100644|100755) blob ([a-f0-9]{40})\t([\x20-\x7e]+)$/.exec(entry);
      if (!match) throw fail();
      const [, mode, oid, path] = match;
      if (
        path.length > 240 ||
        path.includes('\\') ||
        path
          .split('/')
          .some(
            (part) =>
              !part ||
              part === '.' ||
              part === '..' ||
              part.toLowerCase() === '.git',
          )
      )
        throw fail();
      const bytes = await git(['cat-file', 'blob', oid], 1048576);
      byteCount += bytes.length;
      if (byteCount > 16777216) throw fail();
      // Verify each returned blob against the committed object identifier.
      const actual = createHash('sha1')
        .update(`blob ${bytes.length}\0`)
        .update(bytes)
        .digest('hex');
      if (actual !== oid) throw fail();
      manifest.update(`${mode}\0${path}\0${oid}\0`);
      await mkdir(dirname(join(directory, path)), {
        recursive: true,
        mode: 0o700,
      });
      await writeFile(join(directory, path), bytes, {
        flag: 'wx',
        mode: 0o600,
      });
    }
    return {
      directory,
      commitSha: options.commitSha,
      manifestSha256: manifest.digest('hex'),
      fileCount: entries.length,
      byteCount,
      gitVersion: version.trim().slice('git version '.length),
      dispose,
    };
  } catch (error) {
    if (!uncertain) await dispose();
    throw error instanceof SnapshotError ? error : fail();
  } finally {
    if (!uncertain) await disposeObjects();
  }
}
