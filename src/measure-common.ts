import ignore from 'ignore';
import { isSafeRelativePath } from './adapter-envelope.js';

/** Schema version of every typed measure structure in this family. */
export const measuresSchemaVersion = 1;

export interface Ratio {
  covered: number;
  total: number;
}
export const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
export const isCommit = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);

/**
 * Gitignore-style exclusion matcher over validated repository-relative paths.
 * Invalid patterns throw so a typo can never silently widen the scope.
 */
export function exclusionMatcher(
  patterns: readonly string[],
): (path: string) => boolean {
  const matcher = ignore();
  for (const pattern of patterns) {
    if (
      typeof pattern !== 'string' ||
      pattern.length === 0 ||
      pattern.length > 256 ||
      pattern.startsWith('!') ||
      pattern.startsWith('#') ||
      pattern.includes('\\')
    )
      throw new TypeError('Invalid exclusion pattern');
    matcher.add(pattern);
  }
  return (path) => isSafeRelativePath(path) && matcher.ignores(path);
}

/**
 * Convert a report path to a repository-relative path. Absolute paths must lie
 * under `root`; relative paths are taken as already relative. Anything else
 * (traversal, other roots, Windows paths) yields `undefined`.
 */
export function toRepositoryPath(
  key: string,
  root: string,
): string | undefined {
  let path = key;
  if (key.startsWith('/')) {
    const prefix = root.endsWith('/') ? root : `${root}/`;
    if (!key.startsWith(prefix)) return undefined;
    path = key.slice(prefix.length);
  }
  return isSafeRelativePath(path) ? path : undefined;
}

export const percent = (r: Ratio): number | null =>
  r.total === 0 ? null : (r.covered / r.total) * 100;
