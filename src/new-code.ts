import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { isSafeRelativePath } from './adapter-envelope.js';
import { parseCoverageDetail, type CoverageDetail } from './coverage-detail.js';
import {
  duplicationCounting,
  jscpdPin,
  jscpdPinnedConfig,
  type Clone,
  type DuplicationDetail,
} from './duplication.js';
import { isCommit, isRecord, toRepositoryPath } from './measure-common.js';
import {
  newCodeMeasures,
  type ChangedFile,
  type ChangedLinesDiff,
  type Measure,
  type MeasureId,
  type UnknownReason,
} from './quality-measures.js';
import type { EngineResult } from './quality-scan.js';

const exec = promisify(execFile);
const sha = /^[0-9a-f]{40}$/;

export type BaseSource = 'pull-request-base' | 'base-ref' | 'none';
export interface NewCodeOutcome {
  /** Where the comparison base came from. */
  baseSource: BaseSource;
  /** Resolved 40-character base commit, or null when there was none. */
  baseSha: string | null;
  headSha: string;
  /** Always `coverage.lines`, `coverage.branches` and `duplication.lines`. */
  measures: Measure[];
}

/** The pull request's base SHA from the Actions event payload, or null. */
export async function pullRequestBaseSha(
  env: Readonly<Record<string, string | undefined>>,
  readEvent: (path: string) => Promise<string>,
): Promise<string | null | undefined> {
  const name = env.GITHUB_EVENT_NAME ?? '';
  if (name !== 'pull_request' && name !== 'pull_request_target')
    return undefined; // not a pull request
  try {
    const event: unknown = JSON.parse(
      await readEvent(env.GITHUB_EVENT_PATH ?? ''),
    );
    const base =
      isRecord(event) && isRecord(event.pull_request)
        ? event.pull_request.base
        : undefined;
    const value = isRecord(base) ? base.sha : undefined;
    return typeof value === 'string' && sha.test(value) ? value : null;
  } catch {
    return null;
  }
}

/** Resolve a ref to a commit in the local repository; never fetches. */
export async function resolveCommit(
  git: string,
  repo: string,
  ref: string,
): Promise<string | null> {
  if (ref === '' || ref.startsWith('-') || ref.includes('\0')) return null;
  try {
    const { stdout } = await exec(git, [
      '-C',
      repo,
      'rev-parse',
      '--verify',
      '--quiet',
      '--end-of-options',
      `${ref}^{commit}`,
    ]);
    const out = stdout.trim();
    return sha.test(out) ? out : null;
  } catch {
    return null;
  }
}

const unquoted = (path: string): string => {
  // Git quotes unusual paths; refuse them instead of guessing at the escaping.
  if (path.startsWith('"')) throw new Error('quoted path in diff');
  return path;
};

/**
 * Parse `git diff --unified=0` output into head-side added/changed line
 * numbers per file. Throws on anything it cannot read exactly.
 */
export function parseChangedLines(diff: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  let cur: (ChangedFile & { lines: number[] }) | null = null;
  let renameFrom: string | undefined;
  const finish = (): void => {
    if (cur?.path) files.push(cur);
    cur = null;
    renameFrom = undefined;
  };
  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git ')) {
      finish();
      cur = { path: '', status: 'modified', lines: [] };
    } else if (!cur) continue;
    else if (line.startsWith('new file mode')) cur.status = 'added';
    else if (line.startsWith('deleted file mode')) cur.status = 'deleted';
    else if (line.startsWith('rename from ')) {
      renameFrom = unquoted(line.slice(12));
      cur.status = 'renamed';
    } else if (line.startsWith('rename to ')) {
      cur.path = unquoted(line.slice(10));
      if (renameFrom !== undefined) cur.oldPath = renameFrom;
    } else if (line.startsWith('--- ')) {
      const old = line.slice(4);
      if (cur.status === 'deleted' && old !== '/dev/null')
        cur.path = unquoted(old.replace(/^a\//, ''));
    } else if (line.startsWith('+++ ')) {
      const next = line.slice(4);
      if (next !== '/dev/null') cur.path = unquoted(next.replace(/^b\//, ''));
    } else if (line.startsWith('@@ ')) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (!m) throw new Error('unreadable hunk header');
      const start = Number(m[1]);
      const count = m[2] ? Number(m[2]) : 1;
      for (let i = 0; i < count; i++) cur.lines.push(start + i);
    }
  }
  finish();
  for (const f of files)
    if (!isSafeRelativePath(f.path)) throw new Error('unsafe path in diff');
  return files;
}

/** Changed-lines diff between two commits, read from the local repository. */
export async function changedLinesDiff(
  git: string,
  repo: string,
  baseSha: string,
  headSha: string,
): Promise<ChangedLinesDiff | null> {
  try {
    const { stdout } = await exec(
      git,
      [
        '-C',
        repo,
        '-c',
        'core.quotepath=false',
        'diff',
        '--unified=0',
        '--no-color',
        '--no-ext-diff',
        '--no-textconv',
        '--find-renames',
        '--src-prefix=a/',
        '--dst-prefix=b/',
        baseSha,
        headSha,
        '--',
      ],
      { maxBuffer: 64 * 1024 * 1024 },
    );
    return {
      baseCommitSha: baseSha,
      headCommitSha: headSha,
      files: parseChangedLines(stdout),
    };
  } catch {
    return null;
  }
}

/** Source extensions jscpd analyzes; changed files outside it are not counted. */
const analyzedExtension =
  /\.(?:[cm]?[jt]sx?|py|java|kt|kts|swift|go|rb|rs|php|cs|c|h|cc|cpp|hpp|scala|sh|bash|vue|svelte)$/;

async function lineCount(
  git: string,
  repo: string,
  headSha: string,
  path: string,
): Promise<number | undefined> {
  try {
    const { stdout } = await exec(
      git,
      ['-C', repo, 'show', `${headSha}:${path}`],
      { maxBuffer: 1048576 },
    );
    const n = stdout.split('\n').length - 1;
    return stdout.length > 0 && !stdout.endsWith('\n') ? n + 1 : n;
  } catch {
    return undefined;
  }
}

/**
 * Rebuild a duplication detail from the jscpd engine result. Findings come two
 * per clone, one per side (`jscpdFindings`), so each pair is one clone. jscpd
 * lists no clone-free file, so every changed source file jscpd would analyze is
 * added to `analyzed` with its committed line count; otherwise new code with no
 * duplication at all would have no denominator.
 */
export async function duplicationFromEngine(
  result: EngineResult | undefined,
  input: {
    git: string;
    repo: string;
    headSha: string;
    changed: readonly ChangedFile[];
  },
): Promise<DuplicationDetail> {
  const state: DuplicationDetail['state'] =
    result?.status !== 'completed'
      ? 'missing'
      : result.findings.length % 2 !== 0
        ? 'invalid'
        : 'complete';
  const clones: Clone[] = [];
  const analyzed: Record<string, number> = {};
  if (state === 'complete' && result)
    for (let i = 0; i < result.findings.length; i += 2) {
      const [a, b] = [result.findings.at(i), result.findings.at(i + 1)];
      if (!a || !b) continue;
      const side = (f: typeof a) => ({
        path: f.path,
        startLine: f.range.startLine,
        endLine: f.range.endLine,
      });
      clones.push({
        format: 'unknown',
        lines: a.range.endLine - a.range.startLine + 1,
        tokens: 0,
        first: side(a),
        second: side(b),
      });
    }
  if (state === 'complete') {
    const paths = new Set(clones.flatMap((c) => [c.first.path, c.second.path]));
    for (const f of input.changed)
      if (f.status !== 'deleted' && analyzedExtension.test(f.path))
        paths.add(f.path);
    for (const path of paths) {
      const n = await lineCount(input.git, input.repo, input.headSha, path);
      if (n !== undefined) analyzed[path] = n;
    }
  }
  return {
    schemaVersion: 1,
    tool: { ...jscpdPin },
    config: jscpdPinnedConfig,
    state,
    commitSha: input.headSha,
    reportCommitSha: input.headSha,
    clones,
    analyzed,
    totals: null,
    counting: state === 'complete' ? duplicationCounting : null,
    sourceCount: Object.keys(analyzed).length,
    cloneCount: clones.length,
    excluded: [],
    exclusionPatterns: [],
    notAnalyzed: [],
    unmatched: [],
  };
}

/**
 * Parse a caller-supplied Istanbul report (json-summary or coverage-final).
 * The report is never produced here and is unverified: it is assumed to match
 * the scanned commit, and only files it names are in the file set.
 */
export function coverageFromReport(
  raw: string | undefined,
  input: { repo: string; headSha: string; tracked: readonly string[] },
): CoverageDetail | undefined {
  if (raw === undefined) return undefined;
  let named: string[] = [];
  let format: 'json-summary' | 'coverage-final' = 'coverage-final';
  try {
    const root: unknown = JSON.parse(raw);
    if (isRecord(root)) {
      if (Object.hasOwn(root, 'total')) format = 'json-summary';
      named = Object.keys(root)
        .filter((k) => k !== 'total')
        .map((k) => toRepositoryPath(k, input.repo))
        .filter((p): p is string => p !== undefined);
    }
  } catch {
    /* parseCoverageDetail reports the malformed report */
  }
  const reported = new Set(named);
  return parseCoverageDetail(raw, format, {
    commitSha: input.headSha,
    reportCommitSha: input.headSha,
    pathRoot: input.repo.startsWith('/') ? input.repo : `/${input.repo}`,
    files: input.tracked.filter((p) => reported.has(p)),
  });
}

const ids: readonly MeasureId[] = [
  'coverage.lines',
  'coverage.branches',
  'duplication.lines',
];
const unknownMeasure = (id: MeasureId, reason: UnknownReason): Measure => ({
  id,
  scope: 'new-code',
  state: 'unknown',
  reason,
});

/** Read a supplied coverage report; undefined when none was supplied. */
export const readCoverageReport = (path: string | undefined) =>
  path === undefined ? Promise.resolve(undefined) : readFile(path, 'utf8');

/**
 * Compute the three new-code measures. `baseRef` is only used when the event
 * is not a pull request; a pull request always uses its own base SHA. Every
 * failure yields `unknown` with a reason, never a percentage.
 */
export async function computeNewCode(input: {
  git: string;
  repo: string;
  headSha: string;
  env: Readonly<Record<string, string | undefined>>;
  readEvent: (path: string) => Promise<string>;
  baseRef?: string;
  tracked: readonly string[];
  coverageReport?: string;
  jscpd?: EngineResult;
}): Promise<NewCodeOutcome> {
  const pr = await pullRequestBaseSha(input.env, input.readEvent);
  const baseSource: BaseSource =
    pr !== undefined
      ? 'pull-request-base'
      : input.baseRef
        ? 'base-ref'
        : 'none';
  const baseSha =
    pr !== undefined
      ? pr === null
        ? null
        : await resolveCommit(input.git, input.repo, pr)
      : input.baseRef
        ? await resolveCommit(input.git, input.repo, input.baseRef)
        : null;
  const coverage = coverageFromReport(input.coverageReport, input);
  const outcome = (measures: Measure[]): NewCodeOutcome => ({
    baseSource,
    baseSha,
    headSha: input.headSha,
    measures,
  });
  const none = (reason: UnknownReason): NewCodeOutcome =>
    outcome(
      ids.map((id) =>
        unknownMeasure(
          id,
          id !== 'duplication.lines' && !coverage ? 'no-report' : reason,
        ),
      ),
    );
  if (baseSource === 'none') return none('no-base-ref');
  if (!baseSha || !isCommit(input.headSha)) return none('invalid-reference');
  const diff = await changedLinesDiff(
    input.git,
    input.repo,
    baseSha,
    input.headSha,
  );
  if (!diff) return none('diff-mismatch');
  const duplication = await duplicationFromEngine(input.jscpd, {
    git: input.git,
    repo: input.repo,
    headSha: input.headSha,
    changed: diff.files,
  });
  return outcome(
    newCodeMeasures({
      referenceCommitSha: baseSha,
      headCommitSha: input.headSha,
      diff,
      ...(coverage ? { coverage } : {}),
      duplication,
    }),
  );
}
