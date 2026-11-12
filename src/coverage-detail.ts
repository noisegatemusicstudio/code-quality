import {
  type Ratio,
  exclusionMatcher,
  isCommit,
  isCount,
  isRecord,
  measuresSchemaVersion,
  toRepositoryPath,
} from './measure-common.js';

/**
 * Per-file coverage import with exact line and branch numerators/denominators.
 * Two Istanbul dialects are read: `json-summary` (counts only) and
 * `coverage-final` (statement/branch maps, which also give per-line hits for
 * new-code measures). Imports are unverified customer data: nothing here runs
 * tests, and a report is only usable when it maps to the exact commit and file
 * set supplied by the caller.
 */
export const coverageInputLimits = Object.freeze({
  summaryBytes: 2097152,
  finalBytes: 8388608,
  files: 5000,
  entries: 500000,
});
export type CoverageFormat = 'json-summary' | 'coverage-final';
/**
 * `missing`: no report supplied. `unsupported`: not a readable Istanbul report
 * of the declared dialect. `invalid`: malformed or inconsistent numbers.
 * `stale`: report not produced at the expected commit. `unmatched`: report
 * names files outside the file set. `partial`: some in-scope files absent.
 * `complete`: every in-scope file reported; a 0% result is still `complete`.
 */
export type CoverageState =
  | 'complete'
  | 'partial'
  | 'missing'
  | 'unsupported'
  | 'invalid'
  | 'stale'
  | 'unmatched';

export interface FileCoverage {
  path: string;
  lines: Ratio;
  branches: Ratio;
  /** Executable line -> hit count; only for `coverage-final`. */
  lineHits?: Record<number, number>;
  /** One entry per branch location; only for `coverage-final`. */
  branchHits?: { line: number; hits: number }[];
}
export interface CoverageContext {
  /** Commit the measures are for. */
  commitSha: string;
  /** Commit the customer says produced the report (reports carry none). */
  reportCommitSha?: string;
  /** Absolute checkout root used to relativize report paths. */
  pathRoot: string;
  /** Exact set of repository-relative files at `commitSha`. */
  files: readonly string[];
  /** Gitignore-style patterns for files excluded from the measure. */
  exclusions?: readonly string[];
  /** Report path -> current path for renamed files. */
  renames?: Readonly<Record<string, string>>;
}
export interface CoverageDetail {
  schemaVersion: 1;
  provenance: 'imported-unverified';
  format: CoverageFormat;
  state: CoverageState;
  commitSha: string;
  reportCommitSha: string | null;
  /** In-scope reported files, sorted by path. */
  files: FileCoverage[];
  /** Reported files dropped by exclusions. */
  excluded: string[];
  exclusionPatterns: string[];
  /** In-scope files absent from the report. */
  missing: string[];
  /** Report paths outside the file set. */
  unmatched: string[];
  /** Totals over `files`; null unless `complete` or `partial`. */
  lines: Ratio | null;
  branches: Ratio | null;
}

export function parseCoverageDetail(
  raw: unknown,
  format: CoverageFormat,
  ctx: CoverageContext,
): CoverageDetail {
  const exclusionPatterns = [...(ctx.exclusions ?? [])];
  const result = (
    state: CoverageState,
    extra: Partial<CoverageDetail> = {},
  ): CoverageDetail => ({
    schemaVersion: measuresSchemaVersion,
    provenance: 'imported-unverified',
    format,
    state,
    commitSha: ctx.commitSha,
    reportCommitSha: ctx.reportCommitSha ?? null,
    files: [],
    excluded: [],
    exclusionPatterns,
    missing: [],
    unmatched: [],
    lines: null,
    branches: null,
    ...extra,
  });
  if (!isCommit(ctx.commitSha) || !ctx.pathRoot.startsWith('/'))
    throw new TypeError('Invalid coverage context');
  const isExcluded = exclusionMatcher(exclusionPatterns);
  if (raw === undefined || raw === null || raw === '') return result('missing');
  const limit =
    format === 'json-summary'
      ? coverageInputLimits.summaryBytes
      : coverageInputLimits.finalBytes;
  if (
    typeof raw !== 'string' ||
    raw.length > limit ||
    Buffer.byteLength(raw, 'utf8') > limit
  )
    return result('invalid');
  if (format !== 'json-summary' && format !== 'coverage-final')
    return result('unsupported');
  if (/^\s*(TN:|SF:)/.test(raw) || !/^\s*\{/.test(raw))
    return result('unsupported');
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return result('invalid');
  }
  if (!isRecord(root)) return result('unsupported');
  const keys = Object.keys(root).filter((k) => k !== 'total');
  if (keys.length > coverageInputLimits.files) return result('invalid');
  const entries: { key: string; value: unknown }[] = keys.map((key) => ({
    key,
    value: root[key],
  }));
  // Dialect check before any numbers are trusted.
  if (format === 'json-summary') {
    if (!Object.hasOwn(root, 'total') || !isRecord(root.total))
      return result('unsupported');
  } else if (
    Object.hasOwn(root, 'total') ||
    entries.some(
      (e) =>
        !isRecord(e.value) ||
        !isRecord(e.value.statementMap) ||
        !isRecord(e.value.s),
    )
  )
    return result('unsupported');

  if (!isCommit(ctx.reportCommitSha) || ctx.reportCommitSha !== ctx.commitSha)
    return result('stale');

  const renames = ctx.renames ?? {};
  const inSet = new Set(ctx.files);
  const seen = new Set<string>();
  const files: FileCoverage[] = [];
  const excluded: string[] = [];
  const unmatched: string[] = [];
  let budget = coverageInputLimits.entries;
  for (const { key, value } of entries) {
    const reported = toRepositoryPath(key, ctx.pathRoot);
    if (reported === undefined) {
      unmatched.push(key);
      continue;
    }
    const path = Object.hasOwn(renames, reported)
      ? renames[reported]
      : reported;
    if (isExcluded(path) || isExcluded(reported)) {
      excluded.push(path);
      continue;
    }
    if (!inSet.has(path) || seen.has(path)) {
      unmatched.push(path);
      continue;
    }
    seen.add(path);
    const parsed =
      format === 'json-summary'
        ? summaryEntry(path, value)
        : finalEntry(path, value, () => budget--);
    if (!parsed || budget < 0) return result('invalid');
    files.push(parsed);
  }
  if (unmatched.length > 0)
    return result('unmatched', { unmatched: unmatched.sort() });
  files.sort((a, b) => (a.path < b.path ? -1 : 1));
  const missing = [...inSet]
    .filter((f) => !seen.has(f) && !isExcluded(f))
    .sort();
  const sum = (pick: (f: FileCoverage) => Ratio): Ratio =>
    files.reduce(
      (a, f) => ({
        covered: a.covered + pick(f).covered,
        total: a.total + pick(f).total,
      }),
      { covered: 0, total: 0 },
    );
  return result(missing.length > 0 ? 'partial' : 'complete', {
    files,
    excluded: excluded.sort(),
    missing,
    lines: sum((f) => f.lines),
    branches: sum((f) => f.branches),
  });
}

function ratio(value: unknown): Ratio | undefined {
  if (!isRecord(value)) return undefined;
  const { total, covered } = value;
  return isCount(total) && isCount(covered) && covered <= total
    ? { covered, total }
    : undefined;
}

function summaryEntry(path: string, value: unknown): FileCoverage | undefined {
  if (!isRecord(value)) return undefined;
  const lines = ratio(value.lines);
  const branches = ratio(value.branches);
  return lines && branches ? { path, lines, branches } : undefined;
}

function finalEntry(
  path: string,
  value: unknown,
  spend: () => number,
): FileCoverage | undefined {
  if (!isRecord(value) || !isRecord(value.statementMap) || !isRecord(value.s))
    return undefined;
  const branchMap = isRecord(value.branchMap) ? value.branchMap : {};
  const b = isRecord(value.b) ? value.b : {};
  const lineHits: Record<number, number> = {};
  for (const id of Object.keys(value.statementMap)) {
    if (spend() <= 0) return undefined;
    const loc: unknown = value.statementMap[id];
    const hits = value.s[id];
    const start = isRecord(loc) && isRecord(loc.start) ? loc.start.line : null;
    if (!isCount(start) || start < 1 || !isCount(hits)) return undefined;
    lineHits[start] = Math.max(lineHits[start] ?? 0, hits);
  }
  const branchHits: { line: number; hits: number }[] = [];
  for (const id of Object.keys(branchMap)) {
    const entry = branchMap[id];
    const counts = b[id];
    if (
      !isRecord(entry) ||
      !Array.isArray(entry.locations) ||
      !Array.isArray(counts) ||
      counts.length !== entry.locations.length
    )
      return undefined;
    for (let i = 0; i < counts.length; i++) {
      if (spend() <= 0) return undefined;
      const loc: unknown = entry.locations[i];
      const line = isRecord(loc) && isRecord(loc.start) ? loc.start.line : null;
      const hits: unknown = counts[i];
      if (!isCount(line) || line < 1 || !isCount(hits)) return undefined;
      branchHits.push({ line, hits });
    }
  }
  const executable = Object.values(lineHits);
  return {
    path,
    lines: {
      total: executable.length,
      covered: executable.filter((h) => h > 0).length,
    },
    branches: {
      total: branchHits.length,
      covered: branchHits.filter((h) => h.hits > 0).length,
    },
    lineHits,
    branchHits,
  };
}
