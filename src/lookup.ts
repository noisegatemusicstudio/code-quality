/**
 * Reads `record[key]` with the honest type. TypeScript types an index signature
 * as always present; for data keyed by file path or line number a missing key
 * is normal, so callers must handle `undefined`.
 */
export function lookup<T>(
  record: Readonly<Record<string | number, T>>,
  key: string | number,
): T | undefined {
  return record[key];
}
