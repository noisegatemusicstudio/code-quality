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
  /** Tree entries that could not be materialised (never scanned, never clean). */
  omitted: SnapshotOmissions;
  gitVersion: string;
  dispose(): Promise<void>;
}
export type OmissionReason =
  'symlink' | 'submodule' | 'oversized-blob' | 'unsupported-path';
export type SnapshotOmissions = Record<OmissionReason, number>;
export const omittedTotal = (o: SnapshotOmissions): number =>
  o.symlink + o.submodule + o['oversized-blob'] + o['unsupported-path'];

/**
 * Safety bounds of the committed-snapshot API. Each is a hard cap: exceeding
 * one fails closed with a named `detail`, never a clean result.
 */
export const snapshotBounds = Object.freeze({
  objectStoreBytes: 536870912,
  objectFiles: 100000,
  sourceBytes: 67108864,
  sourceFiles: 10000,
  sourceFileBytes: 1048576,
  treeListingBytes: 4194304,
  deadlineMs: 120000,
  gitCallMs: 60000,
  gitAddressSpaceBytes: 1073741824,
  gitDataBytes: 536870912,
  gitCpuSeconds: 100,
});
export class SnapshotError extends Error {
  constructor(
    public readonly code:
      'source-unavailable' | 'cleanup-failed' | 'cleanup-uncertain',
    /** Fixed reason token (never repository content) naming the failed guard. */
    public readonly detail?: string,
  ) {
    super(
      code === 'source-unavailable'
        ? 'Committed snapshot unavailable'
        : 'Committed snapshot cleanup failed',
    );
  }
}
/** Oldest Git generation the committed-snapshot isolation has been verified on. */
export const MINIMUM_GIT_VERSION = '2.47';
export function isSupportedGitVersion(output: string): boolean {
  return /^git version 2\.(?:4[7-9]|[5-9][0-9])\.\d+\n$/.test(output);
}

/** Scans the immutable committed tree ONLY, not the checkout (dirty or clean).
 * The caller explicitly trusts its Git executable and object database directory.
 * No status/diff/archive, checkout, filters, project config or working-tree reads.
 * Symlinks, submodules, oversized blobs and non-ASCII paths are not
 * materialised; they are counted in `omitted` so callers report incomplete.
 * Unsafe paths and trees beyond `snapshotBounds` are rejected.
 */
export async function createCommittedSnapshot(options: {
  gitExecutable: string;
  gitDirectory: string;
  commitSha: string;
}): Promise<Snapshot> {
  const fail = (detail = 'invalid-input') =>
    new SnapshotError('source-unavailable', detail);
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
  const deadline = Date.now() + snapshotBounds.deadlineMs;
  const checkDeadline = () => {
    if (Date.now() >= deadline) throw fail('deadline');
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
    for (const [path, detail] of [
      ['commondir', 'worktree'],
      ['shallow', 'shallow-history'],
    ] as const) {
      try {
        await lstat(join(options.gitDirectory, path));
      } catch (error) {
        if (
          error instanceof Error &&
          'code' in error &&
          error.code === 'ENOENT'
        )
          continue;
        throw fail('git-directory-unreadable');
      }
      throw fail(detail);
    }
    // Copy only bounded ordinary object files into a config-free owned Git-dir.
    // Original local config, include/includeIf, refs and credentials are NEVER read.
    // Copying also closes races with concurrent repository object repacking.
    const objects = join(options.gitDirectory, 'objects');
    if (
      !(await lstat(objects)).isDirectory() ||
      (await realpath(objects)) !== objects
    )
      throw fail('object-store-unsafe');
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
    const chunk = Buffer.alloc(1048576);
    for (const name of await readdir(objects)) {
      checkDeadline();
      if (!/^(?:[a-f0-9]{2}|pack|info)$/.test(name))
        throw fail('object-store-unexpected-entry');
      const from = join(objects, name);
      if (!(await lstat(from)).isDirectory() || (await realpath(from)) !== from)
        throw fail('object-store-unsafe');
      if (name === 'info') {
        const names = await readdir(from);
        if (names.includes('alternates') || names.includes('http-alternates'))
          throw fail('alternates');
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
          throw fail('object-store-unexpected-entry');
        if (++objectFiles > snapshotBounds.objectFiles)
          throw fail('object-file-count');
        const handle = await open(
          join(from, file),
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        try {
          const stat = await handle.stat();
          if (!stat.isFile()) throw fail('object-store-unsafe');
          if (stat.size > snapshotBounds.objectStoreBytes - objectBytes)
            throw fail('object-store-bytes');
          objectBytes += stat.size;
          // Stream in fixed chunks so large packs never sit in memory.
          const target = await open(
            join(gitDirectory, 'objects', name, file),
            'wx',
            0o600,
          );
          try {
            let offset = 0;
            while (offset < stat.size) {
              checkDeadline();
              const read = await handle.read(
                chunk,
                0,
                Math.min(chunk.length, stat.size - offset),
                offset,
              );
              if (!read.bytesRead) throw fail('object-store-unstable');
              await target.write(chunk, 0, read.bytesRead);
              offset += read.bytesRead;
            }
          } finally {
            await target.close();
          }
          if ((await handle.stat()).size !== stat.size)
            throw fail('object-store-unstable');
        } finally {
          await handle.close();
        }
      }
    }
    const git = async (
      args: string[],
      limit: number,
      detail = 'git-failed',
    ) => {
      checkDeadline();
      const result = await runScannerProcess({
        executable: '/usr/bin/prlimit',
        args: [
          `--as=${snapshotBounds.gitAddressSpaceBytes}:${snapshotBounds.gitAddressSpaceBytes}`,
          `--data=${snapshotBounds.gitDataBytes}:${snapshotBounds.gitDataBytes}`,
          `--cpu=${snapshotBounds.gitCpuSeconds}:${snapshotBounds.gitCpuSeconds}`,
          '--fsize=1048576:1048576',
          '--',
          options.gitExecutable,
          '--no-pager',
          '--git-dir',
          gitDirectory,
          ...args,
        ],
        cwd: directory,
        timeoutMs: Math.max(
          1,
          Math.min(snapshotBounds.gitCallMs, deadline - Date.now()),
        ),
        outputLimit: limit,
      });
      if (result.state === 'cleanup-uncertain') {
        uncertain = true;
        throw new SnapshotError('cleanup-uncertain');
      }
      if (result.state === 'timed-out') throw fail(`${detail}-timeout`);
      if (result.state !== 'exited' || result.code !== 0) throw fail(detail);
      return result.stdout;
    };
    const version = (await git(['--version'], 128)).toString();
    // GIT_NO_LAZY_FETCH is supported by this tested Git generation.
    if (!isSupportedGitVersion(version)) throw fail('git-version');
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
      'fsck',
    );
    if (
      (
        await git(['cat-file', '-t', options.commitSha], 128, 'commit-type')
      ).toString() !== 'commit\n'
    )
      throw fail('commit-type');
    const commit = await git(
      ['cat-file', 'commit', options.commitSha],
      262144,
      'commit-read',
    );
    const commitPath = join(gitDirectory, 'verified-commit');
    await writeFile(commitPath, commit, { flag: 'wx', mode: 0o600 });
    if (
      (
        await git(
          ['hash-object', '-t', 'commit', '--no-filters', '--', commitPath],
          128,
          'commit-hash',
        )
      ).toString() !== `${options.commitSha}\n`
    )
      throw fail('commit-hash');
    const tree = await git(
      ['ls-tree', '-rzl', '--full-tree', options.commitSha],
      snapshotBounds.treeListingBytes,
      'tree-listing',
    );
    const entries = tree.toString('utf8').split('\0');
    if (entries.pop() !== '') throw fail('tree-listing');
    if (entries.length > snapshotBounds.sourceFiles) throw fail('tree-entries');
    const manifest = createHash('sha256');
    const blobPaths: string[] = [];
    const expectedBlobIds: string[] = [];
    const omitted: SnapshotOmissions = {
      symlink: 0,
      submodule: 0,
      'oversized-blob': 0,
      'unsupported-path': 0,
    };
    let byteCount = 0;
    for (const entry of entries) {
      const match =
        /^(\d{6}) (blob|commit) ([a-f0-9]{40}) +(\d+|-)\t(.+)$/s.exec(entry);
      if (!match) throw fail('tree-entry-format');
      const [, mode, type, oid, size, path] = match;
      // Hostile path shapes are rejected outright; they cannot be skipped safely.
      if (
        path.includes('\0') ||
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
        throw fail('unsafe-path');
      // Entries that cannot be materialised are counted, never silently dropped,
      // and stay bound into the manifest hash.
      const omit = (reason: OmissionReason): void => {
        omitted[reason] += 1;
        manifest.update(`omitted:${reason}\0${mode}\0${path}\0${oid}\0`);
      };
      if (mode === '120000') {
        omit('symlink');
        continue;
      }
      if (type === 'commit' || mode === '160000') {
        omit('submodule');
        continue;
      }
      if (
        (mode !== '100644' && mode !== '100755') ||
        !/^[\x20-\x7e]+$/.test(path) ||
        path.length > 240 ||
        path.includes('\\')
      ) {
        omit('unsupported-path');
        continue;
      }
      if (Number(size) > snapshotBounds.sourceFileBytes) {
        omit('oversized-blob');
        continue;
      }
      byteCount += Number(size);
      if (byteCount > snapshotBounds.sourceBytes) throw fail('source-bytes');
      const bytes = await git(
        ['cat-file', 'blob', oid],
        snapshotBounds.sourceFileBytes,
        'blob-read',
      );
      if (bytes.length !== Number(size)) throw fail('blob-size-mismatch');
      manifest.update(`${mode}\0${path}\0${oid}\0`);
      const blobPath = join(directory, path);
      await mkdir(dirname(blobPath), {
        recursive: true,
        mode: 0o700,
      });
      await writeFile(blobPath, bytes, {
        flag: 'wx',
        mode: 0o600,
      });
      blobPaths.push(blobPath);
      expectedBlobIds.push(`${oid}\n`);
    }
    // Use Git's object-format implementation to verify the bytes the scanners
    // will read. Batched so neither argv nor output size bounds the file count.
    for (let from = 0; from < blobPaths.length; from += 200) {
      const actualBlobIds = await git(
        [
          'hash-object',
          '--no-filters',
          '--',
          ...blobPaths.slice(from, from + 200),
        ],
        200 * 41 + 64,
        'blob-hash',
      );
      if (
        actualBlobIds.toString() !==
        expectedBlobIds.slice(from, from + 200).join('')
      )
        throw fail('blob-hash');
    }
    return {
      directory,
      commitSha: options.commitSha,
      manifestSha256: manifest.digest('hex'),
      fileCount: blobPaths.length,
      byteCount,
      omitted,
      gitVersion: version.trim().slice('git version '.length),
      dispose,
    };
  } catch (error) {
    if (!uncertain) await dispose();
    throw error instanceof SnapshotError ? error : fail('io-error');
  } finally {
    if (!uncertain) await disposeObjects();
  }
}
