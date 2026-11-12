import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';
import type { ScannerAdapter } from './scanner-adapter.js';
import {
  type Ratio,
  compareText,
  exclusionMatcher,
  isCommit,
  isCount,
  isRecord,
  measuresSchemaVersion,
  toRepositoryPath,
} from './measure-common.js';
import { type AdapterFinding, findingFingerprint } from './adapter-envelope.js';
import { externalPins } from './scanner-pins.js';

/** jscpd 5.4.3 (MIT) is the approved duplication engine; see licensing doc. */
export const jscpdPin = Object.freeze({
  id: 'jscpd',
  version: externalPins.jscpd.version,
});
/** Pinned detection configuration, recorded with every duplication result. */
export const jscpdPinnedConfig = Object.freeze({
  mode: 'strict',
  minLines: 5,
  minTokens: 50,
  gitignore: false,
  ignore: Object.freeze([] as string[]),
});
export const jscpdConfigVersion = 'jscpd-strict-5-50';

/**
 * Counting method recorded with every complete result. Duplicated lines come
 * from the clone locations; the denominator is the report's own total line
 * count, accepted only when it is consistent with the snapshot line counts of
 * every file the clones name (clone-free files are not listed by jscpd, so the
 * snapshot alone cannot give the full denominator).
 */
export const duplicationCounting = Object.freeze({
  duplicatedLines: 'distinct-lines-from-clone-locations',
  cloneFileLines: 'committed-snapshot-line-count',
  denominator: 'report-total-lines-cross-checked-against-snapshot',
});

export const duplicationInputLimits = Object.freeze({
  bytes: 8388608,
  clones: 20000,
  files: 5000,
});

/** Report name and directory (relative to the workspace) jscpd writes to. */
export const jscpdReportFile = 'out/jscpd-report.json';
/**
 * Adapter definition for `runAdapter`. Arguments mirror the flags the repo's
 * committed-source scan already passes; callers may only add allowlisted
 * extras. jscpd's JSON reporter writes `jscpd-report.json` into `--output`, so
 * the adapter declares that file (inside the private workspace, bounded) and
 * `runAdapter` hands its content to `parse`. The executable is verified
 * against the pinned SHA-256 unless a test passes its own.
 */
export function jscpdAdapter(
  executable: string,
  executableSha256: string = externalPins.jscpd.sha256,
): ScannerAdapter {
  return {
    engine: { ...jscpdPin },
    rulesetVersion: jscpdConfigVersion,
    configVersion: jscpdConfigVersion,
    executable,
    executableSha256,
    outputFile: {
      path: jscpdReportFile,
      maxBytes: duplicationInputLimits.bytes,
    },
    versionArgs: ['--version'],
    versionOutput: jscpdPin.version,
    fixedArgs: [
      '--reporters',
      'json',
      '--output',
      '../out',
      '--min-lines',
      String(jscpdPinnedConfig.minLines),
      '--min-tokens',
      String(jscpdPinnedConfig.minTokens),
      '--mode',
      jscpdPinnedConfig.mode,
      '--no-gitignore',
      '--no-colors',
      '--no-tips',
      '--silent',
      '--exit-code',
      '42',
      '--',
      '.',
    ],
    allowedArgs: [],
    successExitCodes: [0, 42],
    parse: (report, context) => {
      const detail = parseJscpdReport(report, {
        pathRoot: context.sourceRoot,
        files: undefined,
        lineCount: snapshotLineCounter(context.sourceRoot),
      });
      return detail.state === 'complete'
        ? { findings: jscpdFindings(detail.clones) }
        : undefined;
    },
  };
}

/** Envelope findings (two per clone, one per side) for parsed clones. */
export function jscpdFindings(clones: readonly Clone[]): AdapterFinding[] {
  return clones.flatMap((c, i) =>
    [
      [c.first, c.second],
      [c.second, c.first],
    ].map(([a, b], side) => {
      const base = {
        ruleId: 'jscpd/duplicate',
        nativeSeverity: 'info',
        path: a.path,
        range: {
          startLine: a.startLine,
          startColumn: 1,
          endLine: a.endLine,
          endColumn: 1,
        },
        message: `Duplicate of ${b.path}:${b.startLine}-${b.endLine}`,
      };
      return {
        ...base,
        fingerprint: findingFingerprint(jscpdPin.id, base, i * 2 + side),
      };
    }),
  );
}

export interface CloneSide {
  path: string;
  startLine: number;
  endLine: number;
}
export interface Clone {
  format: string;
  lines: number;
  tokens: number;
  first: CloneSide;
  second: CloneSide;
}
export type DuplicationState =
  'complete' | 'missing' | 'unsupported' | 'invalid' | 'stale' | 'unmatched';
export interface DuplicationContext {
  /** Absolute checkout root relativizing report paths ('/' for none). */
  pathRoot: string;
  /**
   * Line count of a repository path in the committed snapshot the scan used,
   * or `undefined` when it cannot be counted. jscpd's report carries no
   * per-file line counts, so every file it names in a clone is counted here.
   */
  lineCount?: (path: string) => number | undefined;
  /** Exact file set at the commit; `undefined` skips set matching. */
  files: readonly string[] | undefined;
  commitSha?: string;
  reportCommitSha?: string;
  /** Gitignore-style exclusions applied by the caller's analysis scope. */
  exclusions?: readonly string[];
}
export interface DuplicationDetail {
  schemaVersion: 1;
  tool: { id: string; version: string };
  config: typeof jscpdPinnedConfig;
  state: DuplicationState;
  commitSha: string | null;
  reportCommitSha: string | null;
  clones: Clone[];
  /**
   * Files named by clones with their snapshot line counts. jscpd lists no
   * clone-free file, so this is a subset of the analyzed files.
   */
  analyzed: Record<string, number>;
  /** Totals; `covered` is duplicated lines and `total` all analyzed lines. */
  totals: Ratio | null;
  /** How the numbers were obtained, recorded in the measure's provenance. */
  counting: typeof duplicationCounting | null;
  /** Files jscpd analyzed (report-wide `statistics.total.sources`). */
  sourceCount: number;
  cloneCount: number;
  excluded: string[];
  exclusionPatterns: string[];
  /** In-set files jscpd did not analyze (unsupported language, ignored...). */
  notAnalyzed: string[];
  unmatched: string[];
}

/** Parse a recorded jscpd JSON report; never executes anything. */
export function parseJscpdReport(
  raw: unknown,
  ctx: DuplicationContext,
): DuplicationDetail {
  const exclusionPatterns = [...(ctx.exclusions ?? [])];
  const result = (
    state: DuplicationState,
    extra: Partial<DuplicationDetail> = {},
  ): DuplicationDetail => ({
    schemaVersion: measuresSchemaVersion,
    tool: { ...jscpdPin },
    config: jscpdPinnedConfig,
    state,
    commitSha: ctx.commitSha ?? null,
    reportCommitSha: ctx.reportCommitSha ?? null,
    clones: [],
    analyzed: {},
    totals: null,
    counting: null,
    sourceCount: 0,
    cloneCount: 0,
    excluded: [],
    exclusionPatterns,
    notAnalyzed: [],
    unmatched: [],
    ...extra,
  });
  if (raw === undefined || raw === null || raw === '') return result('missing');
  if (
    typeof raw !== 'string' ||
    Buffer.byteLength(raw, 'utf8') > duplicationInputLimits.bytes
  )
    return result('invalid');
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return result('invalid');
  }
  if (
    !isRecord(root) ||
    !isRecord(root.statistics) ||
    !isRecord(root.statistics.formats) ||
    !isRecord(root.statistics.total) ||
    !Array.isArray(root.duplicates)
  )
    return result('unsupported');
  if (ctx.commitSha !== undefined) {
    if (!isCommit(ctx.commitSha) || ctx.reportCommitSha !== ctx.commitSha)
      return result('stale');
  }
  if (root.duplicates.length > duplicationInputLimits.clones)
    return result('invalid');
  const isExcluded = exclusionMatcher(ctx.exclusions ?? []);
  const inSet = ctx.files ? new Set(ctx.files) : undefined;
  const analyzed: Record<string, number> = {};
  const excluded: string[] = [];
  const unmatched: string[] = [];
  const resolve = (key: unknown): string | undefined | null => {
    if (typeof key !== 'string') return null;
    const path = toRepositoryPath(key, ctx.pathRoot);
    if (path === undefined) {
      unmatched.push(key);
      return undefined;
    }
    if (isExcluded(path)) {
      excluded.push(path);
      return undefined;
    }
    if (inSet && !inSet.has(path)) {
      unmatched.push(path);
      return undefined;
    }
    return path;
  };
  // Real jscpd 5.4.3 reports give per-format counts, not per-file lines.
  let formatLines = 0;
  let formatSources = 0;
  for (const format of Object.values(root.statistics.formats)) {
    if (
      !isRecord(format) ||
      !isCount(format.lines) ||
      !isCount(format.sources) ||
      (formatSources += format.sources) > duplicationInputLimits.files
    )
      return result('invalid');
    formatLines += format.lines;
  }
  const reported = root.statistics.total;
  if (
    !isCount(reported.lines) ||
    !isCount(reported.sources) ||
    !isCount(reported.clones) ||
    reported.lines !== formatLines ||
    reported.sources !== formatSources
  )
    return result('invalid');
  const clones: Clone[] = [];
  for (const item of root.duplicates as unknown[]) {
    if (!isRecord(item)) return result('invalid');
    const sides: (CloneSide | undefined | null)[] = [
      item.firstFile,
      item.secondFile,
    ].map((file) => {
      if (!isRecord(file)) return null;
      const startLoc = isRecord(file.startLoc) ? file.startLoc.line : undefined;
      const endLoc = isRecord(file.endLoc) ? file.endLoc.line : undefined;
      const start = startLoc ?? file.start;
      const end = endLoc ?? file.end;
      if (!isCount(start) || !isCount(end) || start < 1 || end < start)
        return null;
      const path = resolve(file.name);
      return path
        ? { path, startLine: start, endLine: end }
        : (path as undefined | null);
    });
    const [first, second] = sides;
    if (first === null || second === null) return result('invalid');
    if (first === undefined || second === undefined) continue;
    if (
      !isCount(item.lines) ||
      !isCount(item.tokens) ||
      typeof item.format !== 'string'
    )
      return result('invalid');
    for (const side of [first, second]) {
      if (!(side.path in analyzed)) {
        const length = ctx.lineCount?.(side.path);
        if (length === undefined || !isCount(length)) return result('invalid');
        analyzed[side.path] = length;
      }
      if (side.endLine > analyzed[side.path]) return result('invalid');
    }
    clones.push({
      format: item.format,
      lines: item.lines,
      tokens: item.tokens,
      first,
      second,
    });
  }
  if (unmatched.length > 0)
    return result('unmatched', {
      unmatched: [...new Set(unmatched)].sort(compareText),
    });
  // jscpd's totals are report-wide, so they cannot be scoped to a subset: a
  // report touching excluded files has no usable denominator.
  if (excluded.length > 0)
    return result('unsupported', {
      excluded: [...new Set(excluded)].sort(compareText),
    });
  // The report must agree with what the snapshot says about the files its
  // clones name; those files can never outnumber or outsize the report.
  const cloneFileLines = Object.values(analyzed).reduce((a, b) => a + b, 0);
  if (
    reported.clones !== clones.length ||
    Object.keys(analyzed).length > reported.sources ||
    cloneFileLines > reported.lines
  )
    return result('invalid');
  const total = reported.lines;
  const dup = duplicatedLineSets(clones);
  let duplicated = 0;
  for (const set of Object.values(dup)) duplicated += set.size;
  if (duplicated > total) return result('invalid');
  const notAnalyzed = inSet
    ? [...inSet]
        .filter((f) => !(f in analyzed) && !isExcluded(f))
        .sort(compareText)
    : [];
  return result('complete', {
    clones,
    analyzed,
    totals: { covered: duplicated, total },
    counting: duplicationCounting,
    sourceCount: reported.sources,
    cloneCount: clones.length,
    notAnalyzed,
  });
}

/** Distinct duplicated line numbers per file, over both sides of each clone. */
export function duplicatedLineSets(
  clones: readonly Clone[],
): Record<string, Set<number>> {
  const sets: Record<string, Set<number>> = {};
  for (const clone of clones)
    for (const side of [clone.first, clone.second]) {
      const set = (sets[side.path] ??= new Set());
      for (let line = side.startLine; line <= side.endLine; line++)
        set.add(line);
    }
  return sets;
}

/**
 * Line counter over an owned committed snapshot directory. Files are read
 * bounded; anything unreadable, oversized or outside the root is `undefined`.
 */
export function snapshotLineCounter(
  root: string,
): (path: string) => number | undefined {
  return (path) => {
    if (path.startsWith('/') || path.split('/').includes('..'))
      return undefined;
    let fd: number | undefined;
    try {
      fd = openSync(join(root, path), 'r');
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > 1048576) return undefined;
      const buffer = Buffer.alloc(stat.size);
      if (readSync(fd, buffer, 0, stat.size, 0) !== stat.size) return undefined;
      let lines = 0;
      for (const byte of buffer) if (byte === 10) lines++;
      return buffer.length > 0 && buffer[buffer.length - 1] !== 10
        ? lines + 1
        : lines;
    } catch {
      return undefined;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  };
}
