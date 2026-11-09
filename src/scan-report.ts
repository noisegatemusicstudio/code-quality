export const scannerIds = Object.freeze([
  'eslint',
  'typescript',
  'gitleaks',
  'osv',
  'jscpd',
  'tests',
  'coverage',
] as const);
export type ScannerId = (typeof scannerIds)[number];
export type ImportState = 'completed' | 'failed' | 'timed-out';
export interface ScannerImport {
  commitSha: string;
  state: ImportState;
  findingCount?: number;
}
export interface ScannerResult {
  id: ScannerId;
  state: ImportState | 'missing' | 'invalid';
  findingCount?: number;
}
export interface ScanReport {
  schemaVersion: 1;
  commitSha: string;
  provenance: 'imported-unverified';
  status: 'complete' | 'incomplete';
  scanners: ScannerResult[];
}
/** Pure import aggregation. Declared commit association is NOT execution proof. */
export function aggregateScanReport(
  commitSha: string,
  imports: unknown,
): ScanReport {
  if (
    typeof commitSha !== 'string' ||
    commitSha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(commitSha)
  ) {
    throw new TypeError('Invalid declared commit');
  }
  const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);
  const scanners = scannerIds.map((id): ScannerResult => {
    const invalid: ScannerResult = { id, state: 'invalid' };
    if (!isRecord(imports)) return invalid;
    if (!Object.hasOwn(imports, id)) return { id, state: 'missing' };
    const item = imports[id];
    if (
      !isRecord(item) ||
      !Object.hasOwn(item, 'commitSha') ||
      !Object.hasOwn(item, 'state') ||
      item.commitSha !== commitSha
    )
      return invalid;
    if (item.state === 'failed' || item.state === 'timed-out') {
      return { id, state: item.state };
    }
    if (
      item.state !== 'completed' ||
      !Object.hasOwn(item, 'findingCount') ||
      typeof item.findingCount !== 'number' ||
      !Number.isSafeInteger(item.findingCount) ||
      item.findingCount < 0
    )
      return invalid;
    return { id, state: 'completed', findingCount: item.findingCount };
  });
  return {
    schemaVersion: 1,
    commitSha,
    provenance: 'imported-unverified',
    status: scanners.every((item) => item.state === 'completed')
      ? 'complete'
      : 'incomplete',
    scanners,
  };
}
