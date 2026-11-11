import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  writeFile,
  readFile,
  rm,
  stat,
  symlink,
  rename,
  open,
  access,
} from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  validateOsvDatabaseFile,
  validateOsvDatabaseZip,
  OSV_FILE_DATABASE_LIMITS,
} from '../src/osv-database.js';
import { copyOsvCache } from '../src/osv-cache-copy.js';
import { makeSyntheticOsvZip, syntheticAdvisory } from './osv-fixtures.js';
import { runScannerProcess } from '../src/scanner-process.js';

const digest = (bytes: Buffer) =>
  createHash('sha256').update(bytes).digest('hex');
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'osv-file-validation-'));
  return {
    directory,
    source: join(directory, 'source.zip'),
    cache: join(directory, 'cache.zip'),
    dispose: () => rm(directory, { recursive: true, force: true }),
  };
}
function countZip64(input: Buffer): Buffer {
  const end = input.length - 22;
  const count = input.readUInt16LE(end + 10);
  const record = Buffer.alloc(56);
  record.writeUInt32LE(0x06064b50);
  record.writeBigUInt64LE(44n, 4);
  record.writeUInt16LE(45, 12);
  record.writeUInt16LE(45, 14);
  record.writeBigUInt64LE(BigInt(count), 24);
  record.writeBigUInt64LE(BigInt(count), 32);
  record.writeBigUInt64LE(BigInt(input.readUInt32LE(end + 12)), 40);
  record.writeBigUInt64LE(BigInt(input.readUInt32LE(end + 16)), 48);
  const locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50);
  locator.writeBigUInt64LE(BigInt(end), 8);
  locator.writeUInt32LE(1, 16);
  const trailer = Buffer.from(input.subarray(end));
  trailer.writeUInt16LE(0xffff, 8);
  trailer.writeUInt16LE(0xffff, 10);
  return Buffer.concat([input.subarray(0, end), record, locator, trailer]);
}

await test('file-backed validation matches Buffer metadata for all supported descriptor and compression modes', async () => {
  const f = await fixture();
  try {
    for (const deflate of [false, true])
      for (const descriptor of [false, true])
        for (const unsignedDescriptor of [false, true]) {
          const bytes = makeSyntheticOsvZip([
            { deflate, descriptor, unsignedDescriptor },
          ]);
          await writeFile(f.source, bytes);
          assert.deepEqual(
            await validateOsvDatabaseFile(f.source, 'npm'),
            await validateOsvDatabaseZip(bytes, 'npm'),
          );
        }
  } finally {
    await f.dispose();
  }
});

await test('streamed copy binds hash and private read-only bytes independently of later source replacement', async () => {
  const f = await fixture();
  try {
    const bytes = makeSyntheticOsvZip([{}]);
    await writeFile(f.source, bytes);
    await copyOsvCache(f.source, f.cache, digest(bytes));
    assert.equal((await stat(f.cache)).mode & 0o777, 0o400);
    await rename(f.source, join(f.directory, 'old.zip'));
    await writeFile(f.source, 'replacement');
    assert.deepEqual(await readFile(f.cache), bytes);
    assert.equal(
      (await validateOsvDatabaseFile(f.cache, 'npm')).sha256,
      digest(bytes),
    );
  } finally {
    await f.dispose();
  }
});

await test('bad digest removes partial output and preexisting destinations are never changed', async () => {
  const f = await fixture();
  try {
    const bytes = makeSyntheticOsvZip([{}]);
    await writeFile(f.source, bytes);
    await assert.rejects(copyOsvCache(f.source, f.cache, '0'.repeat(64)));
    await assert.rejects(access(f.cache));
    await writeFile(f.cache, 'preserve');
    await assert.rejects(copyOsvCache(f.source, f.cache, digest(bytes)));
    assert.equal(await readFile(f.cache, 'utf8'), 'preserve');
  } finally {
    await f.dispose();
  }
});

await test('symlinks, directories and oversized sparse archives fail without source reads or replacement', async () => {
  const f = await fixture();
  try {
    const bytes = makeSyntheticOsvZip([{}]);
    await writeFile(f.source, bytes);
    const link = join(f.directory, 'link.zip');
    await symlink(f.source, link);
    await assert.rejects(copyOsvCache(link, f.cache, digest(bytes)));
    await assert.rejects(validateOsvDatabaseFile(link, 'npm'));
    await symlink(f.source, f.cache);
    await assert.rejects(copyOsvCache(f.source, f.cache, digest(bytes)));
    assert.deepEqual(await readFile(f.source), bytes);
    await assert.rejects(
      copyOsvCache(f.directory, join(f.directory, 'other.zip'), digest(bytes)),
    );
    await assert.rejects(validateOsvDatabaseFile(f.directory, 'npm'));
    const handle = await open(join(f.directory, 'large.zip'), 'wx');
    await handle.truncate(OSV_FILE_DATABASE_LIMITS.compressedBytes + 1);
    await handle.close();
    await assert.rejects(
      validateOsvDatabaseFile(join(f.directory, 'large.zip'), 'npm'),
    );
    await assert.rejects(
      copyOsvCache(
        join(f.directory, 'large.zip'),
        join(f.directory, 'oversize-copy.zip'),
        digest(bytes),
      ),
    );
    await assert.rejects(access(join(f.directory, 'oversize-copy.zip')));
  } finally {
    await f.dispose();
  }
});

await test('count-only ZIP64 works for files while Buffer policy stays ZIP32-only', async () => {
  const f = await fixture();
  try {
    const ordinary = makeSyntheticOsvZip([{}]);
    const bytes = countZip64(ordinary);
    await writeFile(f.source, bytes);
    const result = await validateOsvDatabaseFile(f.source, 'npm');
    assert.equal(result.entryCount, 1);
    assert.equal(result.sha256, digest(bytes));
    await assert.rejects(validateOsvDatabaseZip(bytes, 'npm'));
    for (const change of [
      (b: Buffer) => b.writeBigUInt64LE(45n, b.length - 94),
      (b: Buffer) => b.writeUInt16LE(46, b.length - 84),
      (b: Buffer) => b.writeUInt32LE(1, b.length - 82),
      (b: Buffer) => b.writeBigUInt64LE(2n, b.length - 74),
      (b: Buffer) => b.writeBigUInt64LE(500001n, b.length - 66),
      (b: Buffer) => b.writeBigUInt64LE(0xffffffffffffffffn, b.length - 58),
      (b: Buffer) => b.writeUInt32LE(1, b.length - 38),
      (b: Buffer) => b.writeBigUInt64LE(0n, b.length - 34),
      (b: Buffer) => b.writeUInt32LE(2, b.length - 26),
      (b: Buffer) => b.writeUInt32LE(0xffffffff, b.length - 10),
    ]) {
      const invalid = Buffer.from(bytes);
      change(invalid);
      await writeFile(f.source, invalid);
      await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
    }
  } finally {
    await f.dispose();
  }
});

await test('hidden central entries cannot be concealed by a smaller declared count', async () => {
  const f = await fixture();
  try {
    const ordinary = makeSyntheticOsvZip([{}]);
    const end = ordinary.length - 22;
    const start = ordinary.readUInt32LE(end + 16);
    const central = ordinary.subarray(start, end);
    const footer = Buffer.from(ordinary.subarray(end));
    footer.writeUInt32LE(central.length * 2, 12);
    const hidden = Buffer.concat([ordinary.subarray(0, end), central, footer]);
    await writeFile(f.source, hidden);
    await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
    await assert.rejects(validateOsvDatabaseZip(hidden, 'npm'));
    await writeFile(f.source, countZip64(hidden));
    await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
  } finally {
    await f.dispose();
  }
});

await test('file validator rejects corruption, local-central disagreements and late malformed records', async () => {
  const f = await fixture();
  try {
    const bytes = makeSyntheticOsvZip([{ descriptor: true }]);
    const central = bytes.readUInt32LE(bytes.length - 6);
    const cases = [
      bytes.subarray(0, bytes.length - 1),
      makeSyntheticOsvZip([{}, { data: Buffer.from('{broken') }]),
      makeSyntheticOsvZip([{}, {}]),
      makeSyntheticOsvZip([
        { data: Buffer.alloc(8 * 1024 * 1024 + 1, 32), deflate: true },
      ]),
    ];
    for (const position of [6, 30, central - 8, central + 16]) {
      const invalid = Buffer.from(bytes);
      invalid[position] ^= 1;
      cases.push(invalid);
    }
    for (const invalid of cases) {
      await writeFile(f.source, invalid);
      await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
    }
    await writeFile(
      f.source,
      makeSyntheticOsvZip([
        { advisory: { ...syntheticAdvisory(), modified: 'invalid' } },
      ]),
    );
    await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
  } finally {
    await f.dispose();
  }
});

await test('FIFO inputs are rejected by regular-file readers within a supervised deadline', async () => {
  const f = await fixture();
  try {
    execFileSync('/usr/bin/mkfifo', [f.source]);
    const databaseUrl = new URL('../src/osv-database.js', import.meta.url).href;
    const copyUrl = new URL('../src/osv-cache-copy.js', import.meta.url).href;
    const readerUrl = new URL('../src/external-scanners.js', import.meta.url)
      .href;
    const code = `import {validateOsvDatabaseFile} from ${JSON.stringify(databaseUrl)}; import {copyOsvCache} from ${JSON.stringify(copyUrl)}; import {readBoundedRegular} from ${JSON.stringify(readerUrl)}; let rejected=0; for(const fn of [()=>validateOsvDatabaseFile(${JSON.stringify(f.source)},'npm'),()=>copyOsvCache(${JSON.stringify(f.source)},${JSON.stringify(f.cache)},'0'.repeat(64)),()=>readBoundedRegular(${JSON.stringify(f.source)},100)]) {try {await fn()} catch {rejected++}} if(rejected!==3) process.exit(1);`;
    const result = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', code],
      { timeout: 3000, encoding: 'utf8' },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    await f.dispose();
  }
});

await test('owned worker copies and validates under the process supervisor and timeout cleanup', async () => {
  const f = await fixture();
  try {
    const bytes = makeSyntheticOsvZip([{}]);
    await writeFile(f.source, bytes);
    const worker = fileURLToPath(
      new URL('../src/osv-database-worker.js', import.meta.url),
    );
    const args = [
      '--max-old-space-size=256',
      worker,
      f.source,
      f.cache,
      digest(bytes),
      'strict-schema-v1',
    ];
    const result = await runScannerProcess({
      executable: process.execPath,
      args,
      cwd: f.directory,
      timeoutMs: 120000,
      outputLimit: 16384,
    });
    assert.equal(result.state, 'exited');
    assert.equal(result.code, 0);
    const metadata = JSON.parse(result.stdout.toString()) as {
      sha256: string;
      entryCount: number;
    };
    assert.equal(metadata.sha256, digest(bytes));
    assert.equal(metadata.entryCount, 1);
    const timeout = await runScannerProcess({
      executable: process.execPath,
      args: ['-e', 'setInterval(()=>{},1000)'],
      cwd: f.directory,
      timeoutMs: 10,
      outputLimit: 16384,
    });
    assert.equal(timeout.state, 'timed-out');
  } finally {
    await f.dispose();
  }
});

await test('unknown profiles and central disk numbers reject even with otherwise valid envelopes', async () => {
  const f = await fixture();
  try {
    const empty = makeSyntheticOsvZip([]);
    await writeFile(f.source, empty);
    for (const invalid of [null, 'unknown'] as unknown as [
      'strict-schema-v1',
      'strict-schema-v1',
    ]) {
      await assert.rejects(validateOsvDatabaseZip(empty, 'npm', invalid));
      await assert.rejects(validateOsvDatabaseFile(f.source, 'npm', invalid));
    }
    const bytes = makeSyntheticOsvZip([{}]);
    const central = bytes.readUInt32LE(bytes.length - 6);
    bytes.writeUInt16LE(1, central + 34);
    await writeFile(f.source, bytes);
    await assert.rejects(validateOsvDatabaseFile(f.source, 'npm'));
    await assert.rejects(validateOsvDatabaseZip(bytes, 'npm'));
  } finally {
    await f.dispose();
  }
});
