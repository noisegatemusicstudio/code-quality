import { constants } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';

export const OSV_CACHE_COMPRESSED_LIMIT = 384 * 1024 * 1024;

/** Copy into a caller-owned private directory, without replacing any destination.
 * The source descriptor is never reopened, and no archive-sized Buffer is made.
 */
export async function copyOsvCache(
  sourcePath: string,
  destinationPath: string,
  expectedSha256: string,
): Promise<void> {
  let source: Awaited<ReturnType<typeof open>> | undefined;
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  let created = false;
  try {
    if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error();
    source = await open(
      sourcePath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await source.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(OSV_CACHE_COMPRESSED_LIMIT))
      throw new Error();
    destination = await open(
      destinationPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    created = true;
    const digest = createHash('sha256');
    const chunk = Buffer.alloc(64 * 1024);
    let total = 0;
    for (;;) {
      const { bytesRead } = await source.read(chunk, 0, chunk.length, total);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > OSV_CACHE_COMPRESSED_LIMIT || BigInt(total) > before.size)
        throw new Error();
      digest.update(chunk.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await destination.write(
          chunk,
          written,
          bytesRead - written,
        );
        if (result.bytesWritten === 0) throw new Error();
        written += result.bytesWritten;
      }
    }
    const after = await source.stat({ bigint: true });
    if (
      BigInt(total) !== before.size ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      digest.digest('hex') !== expectedSha256
    )
      throw new Error();
    await destination.chmod(0o400);
    await destination.close();
    destination = undefined;
  } catch {
    await destination?.close().catch(() => undefined);
    if (created) await unlink(destinationPath).catch(() => undefined);
    throw new Error('Invalid or unsupported offline OSV cache');
  } finally {
    await source?.close();
  }
}
