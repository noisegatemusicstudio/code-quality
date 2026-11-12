/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Shared helper that writes a fake node-script executable into a temp directory and returns its path and sha256; asserts nothing itself.
*/
import { createHash } from 'node:crypto';
import { chmod, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Write `body` as an executable node script; `sha256` is of the exact file bytes. */
export async function writeFakeExecutable(
  directory: string,
  name: string,
  body: string,
): Promise<{ path: string; sha256: string }> {
  const source = `#!${process.execPath}\n${body}`;
  const path = join(directory, name);
  await writeFile(path, source);
  await chmod(path, 0o755);
  return { path, sha256: createHash('sha256').update(source).digest('hex') };
}
