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
  /** Analyzed files with their line counts (the denominator, per file). */
  analyzed: Record<string, number>;
  /** Totals; `covered` is duplicated lines and `total` all analyzed lines. */
  totals: Ratio | null;
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
  let fileCount = 0;
  for (const format of Object.values(root.statistics.formats)) {
    if (!isRecord(format) || !isRecord(format.sources))
      return result('invalid');
    for (const [key, stats] of Object.entries(format.sources)) {
      if (++fileCount > duplicationInputLimits.files || !isRecord(stats))
        return result('invalid');
      if (!isCount(stats.lines)) return result('invalid');
      const path = resolve(key);
      if (path === null) return result('invalid');
      if (path !== undefined) analyzed[path] = stats.lines;
    }
  }
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
      typeof item.format !== 'string' ||
      !(first.path in analyzed) ||
      !(second.path in analyzed) ||
      first.endLine > analyzed[first.path] ||
      second.endLine > analyzed[second.path]
    )
      return result('invalid');
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
  const dup = duplicatedLineSets(clones);
  let duplicated = 0;
  for (const set of Object.values(dup)) duplicated += set.size;
  const total = Object.values(analyzed).reduce((a, b) => a + b, 0);
  // The report's own totals must agree with the file-level numbers it lists.
  const reported = root.statistics.total;
  const full =
    excluded.length === 0 && clones.length === root.duplicates.length;
  if (
    full &&
    // jscpd's own `duplicatedLines` sums clone sizes (overlaps double count),
    // so only the denominator and clone count are cross-checked.
    (reported.lines !== total || reported.clones !== clones.length)
  )
    return result('invalid');
  const notAnalyzed = inSet
    ? [...inSet]
        .filter((f) => !(f in analyzed) && !isExcluded(f))
        .sort(compareText)
    : [];
  return result('complete', {
    clones,
    analyzed,
    totals: { covered: duplicated, total },
    cloneCount: clones.length,
    excluded: [...new Set(excluded)].sort(compareText),
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
