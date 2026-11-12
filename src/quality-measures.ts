import {
  type EnvelopeScope,
  isSafeRelativePath,
  isValidScope,
} from './adapter-envelope.js';
import type { CoverageDetail } from './coverage-detail.js';
import { duplicatedLineSets, type DuplicationDetail } from './duplication.js';
import {
  type Ratio,
  exclusionMatcher,
  isCommit,
  measuresSchemaVersion,
  percent,
} from './measure-common.js';

export { measuresSchemaVersion };
/**
 * Measures deliberately NOT produced: no maintainability or security rating,
 * technical-debt estimate or composite quality score exists in this module.
 */
export const measuresNotProvided = Object.freeze([
  'maintainability-rating',
  'security-rating',
  'technical-debt-estimate',
  'quality-score',
] as const);

export type MeasureId =
  | 'coverage.lines'
  | 'coverage.branches'
  | 'duplication.lines';
export type MeasureScopeKind = 'overall' | 'new-code';
export type UnknownReason =
  | 'no-report'
  | 'unsupported-report'
  | 'invalid-report'
  | 'stale-report'
  | 'unmatched-report'
  | 'partial-report'
  | 'zero-denominator'
  | 'no-line-data'
  | 'invalid-reference'
  | 'diff-mismatch'
  | 'changed-file-not-in-report';
export interface KnownMeasure {
  id: MeasureId;
  scope: MeasureScopeKind;
  state: 'known';
  numerator: number;
  denominator: number;
  /** numerator/denominator * 100; the denominator is never zero here. */
  percent: number;
  /** Duplication only: changed lines in files the engine did not analyze. */
  unanalyzedLines?: number;
}
export interface UnknownMeasure {
  id: MeasureId;
  scope: MeasureScopeKind;
  state: 'unknown';
  reason: UnknownReason;
}
export type Measure = KnownMeasure | UnknownMeasure;

const known = (
  id: MeasureId,
  scope: MeasureScopeKind,
  r: Ratio,
  extra: Partial<KnownMeasure> = {},
): Measure =>
  r.total === 0
    ? { id, scope, state: 'unknown', reason: 'zero-denominator' }
    : {
        id,
        scope,
        state: 'known',
        numerator: r.covered,
        denominator: r.total,
        percent: percent(r) as number,
        ...extra,
      };
const unknown = (
  id: MeasureId,
  scope: MeasureScopeKind,
  reason: UnknownReason,
): Measure => ({ id, scope, state: 'unknown', reason });

const stateReason = (state: string): UnknownReason =>
  state === 'missing'
    ? 'no-report'
    : state === 'unsupported'
      ? 'unsupported-report'
      : state === 'stale'
        ? 'stale-report'
        : state === 'unmatched'
          ? 'unmatched-report'
          : state === 'partial'
            ? 'partial-report'
            : 'invalid-report';

/** Whole-file-set measures; anything but a complete report is `unknown`. */
export function overallMeasures(
  coverage?: CoverageDetail,
  duplication?: DuplicationDetail,
): Measure[] {
  const out: Measure[] = [];
  for (const [id, pick] of [
    ['coverage.lines', (c: CoverageDetail) => c.lines],
    ['coverage.branches', (c: CoverageDetail) => c.branches],
  ] as const) {
    if (!coverage) out.push(unknown(id, 'overall', 'no-report'));
    else if (coverage.state !== 'complete')
      out.push(unknown(id, 'overall', stateReason(coverage.state)));
    else out.push(known(id, 'overall', pick(coverage) as Ratio));
  }
  if (!duplication)
    out.push(unknown('duplication.lines', 'overall', 'no-report'));
  else if (duplication.state !== 'complete' || !duplication.totals)
    out.push(
      unknown('duplication.lines', 'overall', stateReason(duplication.state)),
    );
  else out.push(known('duplication.lines', 'overall', duplication.totals));
  return out;
}

/** Added/modified lines of one file on the head side of the diff. */
export interface ChangedFile {
  path: string;
  /** Previous path for renames; only informational. */
  oldPath?: string;
  status: 'added' | 'modified' | 'renamed' | 'deleted';
  /** 1-based head-side line numbers that were added or changed. */
  lines: readonly number[];
}
export interface ChangedLinesDiff {
  baseCommitSha: string;
  headCommitSha: string;
  files: readonly ChangedFile[];
}
export interface NewCodeInput {
  /** The configured reference commit the diff must be taken against. */
  referenceCommitSha: string;
  headCommitSha: string;
  diff: ChangedLinesDiff;
  coverage?: CoverageDetail;
  duplication?: DuplicationDetail;
  exclusions?: readonly string[];
}

function diffProblem(input: NewCodeInput): boolean {
  const { diff } = input;
  if (
    !isCommit(input.referenceCommitSha) ||
    !isCommit(input.headCommitSha) ||
    input.referenceCommitSha === input.headCommitSha
  )
    return true;
  if (
    diff.baseCommitSha !== input.referenceCommitSha ||
    diff.headCommitSha !== input.headCommitSha
  )
    return true;
  const seen = new Set<string>();
  for (const f of diff.files) {
    if (
      !isSafeRelativePath(f.path) ||
      seen.has(f.path) ||
      !['added', 'modified', 'renamed', 'deleted'].includes(f.status) ||
      f.lines.some((l) => !Number.isSafeInteger(l) || l < 1) ||
      new Set(f.lines).size !== f.lines.length ||
      (f.status === 'deleted' && f.lines.length > 0)
    )
      return true;
    seen.add(f.path);
  }
  return false;
}

/**
 * New-code measures over an explicit reference commit and changed-lines diff.
 * A report for another commit, one that does not match the diff, or one lacking
 * a changed file yields `unknown` with a reason, never a percentage.
 */
export function newCodeMeasures(input: NewCodeInput): Measure[] {
  const ids: MeasureId[] = [
    'coverage.lines',
    'coverage.branches',
    'duplication.lines',
  ];
  if (diffProblem(input)) {
    const reason: UnknownReason =
      isCommit(input.referenceCommitSha) &&
      isCommit(input.headCommitSha) &&
      input.referenceCommitSha !== input.headCommitSha
        ? 'diff-mismatch'
        : 'invalid-reference';
    return ids.map((id) => unknown(id, 'new-code', reason));
  }
  const isExcluded = exclusionMatcher(input.exclusions ?? []);
  const changed = input.diff.files.filter(
    (f) => f.status !== 'deleted' && f.lines.length > 0 && !isExcluded(f.path),
  );
  return [
    ...newCodeCoverage(input, changed),
    newCodeDuplication(input, changed),
  ];
}

function newCodeCoverage(
  input: NewCodeInput,
  changed: readonly ChangedFile[],
): Measure[] {
  const ids = ['coverage.lines', 'coverage.branches'] as const;
  const c = input.coverage;
  const fail = (reason: UnknownReason): Measure[] =>
    ids.map((id) => unknown(id, 'new-code', reason));
  if (!c) return fail('no-report');
  if (c.state !== 'complete') return fail(stateReason(c.state));
  if (c.commitSha !== input.headCommitSha) return fail('stale-report');
  const byPath = new Map(c.files.map((f) => [f.path, f]));
  const lines: Ratio = { covered: 0, total: 0 };
  const branches: Ratio = { covered: 0, total: 0 };
  for (const file of changed) {
    const report = byPath.get(file.path);
    if (!report) return fail('changed-file-not-in-report');
    if (!report.lineHits || !report.branchHits) return fail('no-line-data');
    const set = new Set(file.lines);
    for (const line of set) {
      const hits = report.lineHits[line];
      if (hits === undefined) continue; // not executable: not in the denominator
      lines.total++;
      if (hits > 0) lines.covered++;
    }
    for (const b of report.branchHits)
      if (set.has(b.line)) {
        branches.total++;
        if (b.hits > 0) branches.covered++;
      }
  }
  return [
    known('coverage.lines', 'new-code', lines),
    known('coverage.branches', 'new-code', branches),
  ];
}

function newCodeDuplication(
  input: NewCodeInput,
  changed: readonly ChangedFile[],
): Measure {
  const id = 'duplication.lines';
  const d = input.duplication;
  if (!d) return unknown(id, 'new-code', 'no-report');
  if (d.state !== 'complete')
    return unknown(id, 'new-code', stateReason(d.state));
  if (d.commitSha !== input.headCommitSha)
    return unknown(id, 'new-code', 'stale-report');
  const dup = duplicatedLineSets(d.clones);
  const r: Ratio = { covered: 0, total: 0 };
  let unanalyzedLines = 0;
  for (const file of changed) {
    const length = d.analyzed[file.path];
    if (length === undefined) {
      unanalyzedLines += file.lines.length;
      continue;
    }
    // A changed line beyond the analyzed file means the report is not this tree.
    if (file.lines.some((l) => l > length))
      return unknown(id, 'new-code', 'diff-mismatch');
    r.total += file.lines.length;
    r.covered += file.lines.filter((l) => dup[file.path]?.has(l)).length;
  }
  return known(id, 'new-code', r, { unanalyzedLines });
}

export interface QualityMeasures {
  schemaVersion: 1;
  kind: 'quality-measures';
  scope: EnvelopeScope;
  provenance: {
    coverage: {
      source: 'imported-unverified';
      format: CoverageDetail['format'];
      state: CoverageDetail['state'];
      reportCommitSha: string | null;
      exclusionPatterns: string[];
      excluded: string[];
      missing: string[];
      fileCount: number;
    } | null;
    duplication: {
      tool: DuplicationDetail['tool'];
      config: DuplicationDetail['config'];
      state: DuplicationDetail['state'];
      reportCommitSha: string | null;
      exclusionPatterns: string[];
      excluded: string[];
      notAnalyzed: string[];
      cloneCount: number;
    } | null;
    newCode: { referenceCommitSha: string; headCommitSha: string } | null;
  };
  measures: Measure[];
  notProvided: readonly string[];
}

/** Assemble the versioned output; scope is the envelope scope of the analysis. */
export function buildQualityMeasures(input: {
  scope: EnvelopeScope;
  coverage?: CoverageDetail;
  duplication?: DuplicationDetail;
  newCode?: NewCodeInput;
}): QualityMeasures {
  if (!isValidScope(input.scope)) throw new TypeError('Invalid scope');
  const { coverage: c, duplication: d, newCode } = input;
  return {
    schemaVersion: measuresSchemaVersion,
    kind: 'quality-measures',
    scope: { ...input.scope },
    provenance: {
      coverage: !c
        ? null
        : {
            source: c.provenance,
            format: c.format,
            state: c.state,
            reportCommitSha: c.reportCommitSha,
            exclusionPatterns: c.exclusionPatterns,
            excluded: c.excluded,
            missing: c.missing,
            fileCount: c.files.length,
          },
      duplication: !d
        ? null
        : {
            tool: d.tool,
            config: d.config,
            state: d.state,
            reportCommitSha: d.reportCommitSha,
            exclusionPatterns: d.exclusionPatterns,
            excluded: d.excluded,
            notAnalyzed: d.notAnalyzed,
            cloneCount: d.cloneCount,
          },
      newCode: !newCode
        ? null
        : {
            referenceCommitSha: newCode.referenceCommitSha,
            headCommitSha: newCode.headCommitSha,
          },
    },
    measures: [
      ...overallMeasures(c, d),
      ...(newCode
        ? newCodeMeasures({ ...newCode, coverage: c, duplication: d })
        : []),
    ],
    notProvided: measuresNotProvided,
  };
}

export type ThresholdResult = 'pass' | 'fail' | 'unknown';
/** Unknown measures never pass or fail silently; the caller must handle them. */
export function evaluateThreshold(
  measure: Measure,
  threshold: { min?: number; max?: number },
): ThresholdResult {
  if (measure.state !== 'known') return 'unknown';
  if (threshold.min !== undefined && measure.percent < threshold.min)
    return 'fail';
  if (threshold.max !== undefined && measure.percent > threshold.max)
    return 'fail';
  return 'pass';
}
