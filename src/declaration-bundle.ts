import { createHash } from 'node:crypto';

export interface DeclarationBundle {
  files: Record<string, string>;
  sha256: string;
  fileCount: number;
  byteCount: number;
}
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
/** Explicit caller-supplied declaration content, not a directory to traverse.
 * Package metadata is deliberately restricted to static type entry points.
 */
export function validateDeclarationBundle(
  input: unknown,
): DeclarationBundle | null {
  if (!record(input) || !Object.hasOwn(input, 'files') || !record(input.files))
    return null;
  const entries = Object.entries(input.files).sort(([a], [b]) =>
    a.localeCompare(b, 'en'),
  );
  if (!entries.length || entries.length > 2000) return null;
  const files: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  const hash = createHash('sha256');
  let byteCount = 0;
  for (const [path, value] of entries) {
    if (
      path.length > 240 ||
      typeof value !== 'string' ||
      !/^[a-zA-Z0-9@_./-]+$/.test(path) ||
      path
        .split('/')
        .some(
          (part) => !part || part === '.' || part === '..' || part === '.git',
        ) ||
      !/\/(?:[^/]+\.d\.(?:ts|mts|cts)|package\.json)$/.test(path)
    )
      return null;
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes > 1048576 || (byteCount += bytes) > 8388608) return null;
    if (path.endsWith('/package.json')) {
      let metadata: unknown;
      try {
        metadata = JSON.parse(value);
      } catch {
        return null;
      }
      if (
        !record(metadata) ||
        Object.keys(metadata).some(
          (key) =>
            !['name', 'version', 'types', 'typings', 'type'].includes(key),
        )
      )
        return null;
      for (const [key, item] of Object.entries(metadata)) {
        if (typeof item !== 'string' || item.length > 240) return null;
        if (
          (key === 'types' || key === 'typings') &&
          (!/^[a-zA-Z0-9_./-]+\.d\.(?:ts|mts|cts)$/.test(item) ||
            item.startsWith('/') ||
            item.split('/').some((part) => part === '..'))
        )
          return null;
        if (key === 'type' && item !== 'module' && item !== 'commonjs')
          return null;
      }
    }
    files[path] = value;
    hash
      .update(path)
      .update('\0')
      .update(String(bytes))
      .update('\0')
      .update(value)
      .update('\0');
  }
  return {
    files,
    sha256: hash.digest('hex'),
    fileCount: entries.length,
    byteCount,
  };
}
