export interface CoverageMetric {
  total: number;
  covered: number;
  skipped: number;
  percentage: number | null;
}
export type CoverageImport =
  | {
      status: 'parsed';
      metrics: Record<
        'lines' | 'statements' | 'functions' | 'branches',
        CoverageMetric
      >;
    }
  | { status: 'invalid' };
/** Imported totals are unverified; zero totals have unknown percentages. */
export function parseCoverageSummary(raw: unknown): CoverageImport {
  const invalid: CoverageImport = { status: 'invalid' };
  if (
    typeof raw !== 'string' ||
    raw.length > 262144 ||
    new TextEncoder().encode(raw).length > 262144
  )
    return invalid;
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return invalid;
  }
  const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);
  if (
    !isRecord(root) ||
    Object.keys(root).length > 1001 ||
    !Object.hasOwn(root, 'total') ||
    !isRecord(root.total)
  )
    return invalid;
  const summary = root.total;
  const metric = (name: string): CoverageMetric | null => {
    if (!Object.hasOwn(summary, name)) return null;
    const item = summary[name];
    if (!isRecord(item)) return null;
    const ownCount = (key: string): number | null => {
      if (!Object.hasOwn(item, key)) return null;
      const value = item[key];
      return typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0
        ? value
        : null;
    };
    const total = ownCount('total');
    const covered = ownCount('covered');
    const skipped = ownCount('skipped');
    if (
      total === null ||
      covered === null ||
      skipped === null ||
      covered > total ||
      skipped > total
    )
      return null;
    return {
      total,
      covered,
      skipped,
      percentage: total === 0 ? null : (covered / total) * 100,
    };
  };
  const lines = metric('lines');
  const statements = metric('statements');
  const functions = metric('functions');
  const branches = metric('branches');
  if (!lines || !statements || !functions || !branches) return invalid;
  return {
    status: 'parsed',
    metrics: { lines, statements, functions, branches },
  };
}
