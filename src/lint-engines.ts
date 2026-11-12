import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  type AdapterFinding,
  type EnvelopeReason,
  envelopeLimits,
  findingFingerprint,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import { type ParsedOutput, type ScannerAdapter } from './scanner-adapter.js';
import { lintPins } from './scanner-pins.js';

const exec = promisify(execFile);

/** Engines whose input is an explicit list of tracked files. */
export type LintEngineId = 'shellcheck' | 'shfmt' | 'actionlint' | 'zizmor';

/** Largest file list one adapter run accepts (adapterLimits.args is 32; `--` takes one). */
export const lintBatchSize = 30;
export const lintArgChars = 256;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const positive = (v: unknown): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : undefined;

/** Draft findings in, sorted/capped/fingerprinted findings out. Shared by all four parsers. */
function finish(
  engine: LintEngineId,
  drafts: Omit<AdapterFinding, 'fingerprint'>[],
  partial: EnvelopeReason | undefined,
): ParsedOutput {
  drafts.sort(
    (a, b) =>
      a.path.localeCompare(b.path, 'en') ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId, 'en'),
  );
  if (drafts.length > envelopeLimits.findings) {
    drafts.length = envelopeLimits.findings;
    partial ??= 'finding-limit';
  }
  const seen = new Map<string, number>();
  const findings = drafts.map((d): AdapterFinding => {
    const key = findingFingerprint(engine, d);
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    return {
      ...d,
      fingerprint: n === 0 ? key : findingFingerprint(engine, d, n),
    };
  });
  return partial ? { findings, partial } : { findings };
}

const cleanPath = (value: unknown): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const rel = value.startsWith('./') ? value.slice(2) : value;
  return isSafeRelativePath(rel) ? rel : undefined;
};
const ruleOk = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const severityOk = /^[A-Za-z0-9._-]{1,32}$/;

/** ShellCheck `--format=json1`: `{ comments: [{ file, line, endLine, column, endColumn, level, code, message }] }`. */
export function parseShellcheckReport(
  stdout: string,
): ParsedOutput | undefined {
  const root: unknown = JSON.parse(stdout);
  const list = isRecord(root) ? root.comments : root;
  if (!Array.isArray(list)) return undefined;
  const drafts: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let partial: EnvelopeReason | undefined;
  for (const item of list as unknown[]) {
    if (!isRecord(item)) return undefined;
    const path = cleanPath(item.file);
    const startLine = positive(item.line);
    const startColumn = positive(item.column) ?? 1;
    const endLine = positive(item.endLine) ?? startLine;
    const endColumn = positive(item.endColumn) ?? startColumn;
    const level = item.level;
    const code =
      typeof item.code === 'number' ? `SC${String(item.code)}` : undefined;
    if (
      path === undefined ||
      startLine === undefined ||
      endLine === undefined ||
      endLine < startLine ||
      typeof level !== 'string' ||
      !severityOk.test(level) ||
      code === undefined ||
      !ruleOk.test(code)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    drafts.push({
      ruleId: code,
      nativeSeverity: level,
      path,
      range: { startLine, startColumn, endLine, endColumn },
      message: redactMessage(item.message),
    });
  }
  return finish('shellcheck', drafts, partial);
}

/**
 * shfmt `-d` unified diff. One finding per hunk, anchored on the old-file line
 * range. The diff text itself is never copied.
 */
export function parseShfmtDiff(stdout: string): ParsedOutput {
  const drafts: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let partial: EnvelopeReason | undefined;
  let path: string | undefined;
  for (const text of stdout.split('\n')) {
    if (text.startsWith('+++ ')) {
      path = cleanPath(text.slice(4).split('\t')[0]);
      continue;
    }
    const hunk = /^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@/.exec(text);
    if (!hunk) continue;
    const startLine = positive(Number(hunk[1]));
    const count = hunk[2] ? Number(hunk[2]) : 1;
    if (path === undefined || startLine === undefined) {
      partial ??= 'invalid-output';
      continue;
    }
    const endLine = Math.max(startLine, startLine + count - 1);
    drafts.push({
      ruleId: 'shfmt/format',
      nativeSeverity: 'format',
      path,
      range: { startLine, startColumn: 1, endLine, endColumn: 1 },
      message: 'File is not formatted as shfmt would write it (shfmt -d)',
    });
  }
  return finish('shfmt', drafts, partial);
}

/** actionlint `-format '{{json .}}'`: array of `{ message, filepath, line, column, kind, end_column }` (or nothing/null). */
export function parseActionlintReport(
  stdout: string,
): ParsedOutput | undefined {
  const text = stdout.trim();
  const root: unknown = text === '' ? [] : JSON.parse(text);
  if (root === null) return finish('actionlint', [], undefined);
  if (!Array.isArray(root)) return undefined;
  const drafts: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let partial: EnvelopeReason | undefined;
  for (const item of root as unknown[]) {
    if (!isRecord(item)) return undefined;
    const path = cleanPath(item.filepath);
    const startLine = positive(item.line);
    const startColumn = positive(item.column) ?? 1;
    const rule =
      typeof item.kind === 'string' ? `actionlint/${item.kind}` : undefined;
    if (
      path === undefined ||
      startLine === undefined ||
      rule === undefined ||
      !ruleOk.test(rule)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    const endColumn = Math.max(startColumn, positive(item.end_column) ?? 0);
    drafts.push({
      ruleId: rule,
      nativeSeverity: 'error',
      path,
      range: { startLine, startColumn, endLine: startLine, endColumn },
      message: redactMessage(item.message),
    });
  }
  return finish('actionlint', drafts, partial);
}

/**
 * zizmor `--format=json`: array of findings with `ident`, `desc`,
 * `determinations.severity` and `locations[]` (0-based rows). Findings that
 * zizmor marks `ignored` are not reported. Severity stays the native label.
 */
export function parseZizmorReport(stdout: string): ParsedOutput | undefined {
  const text = stdout.trim();
  const root: unknown = text === '' ? [] : JSON.parse(text);
  if (!Array.isArray(root)) return undefined;
  const drafts: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let partial: EnvelopeReason | undefined;
  for (const item of root as unknown[]) {
    if (!isRecord(item)) return undefined;
    if (item.ignored === true) continue;
    const locations = Array.isArray(item.locations)
      ? (item.locations as unknown[]).filter(isRecord)
      : [];
    const location =
      locations.find(
        (l) => isRecord(l.symbolic) && l.symbolic.kind === 'Primary',
      ) ?? locations.at(0);
    const symbolic = location?.symbolic;
    const key =
      isRecord(symbolic) && isRecord(symbolic.key) ? symbolic.key : undefined;
    const local = key && isRecord(key.Local) ? key.Local : undefined;
    const concrete = isRecord(location?.concrete)
      ? location.concrete
      : undefined;
    const span =
      concrete && isRecord(concrete.location) ? concrete.location : undefined;
    const start =
      span && isRecord(span.start_point) ? span.start_point : undefined;
    const end = span && isRecord(span.end_point) ? span.end_point : undefined;
    const determinations = isRecord(item.determinations)
      ? item.determinations
      : {};
    const path = cleanPath(local?.verbatim_path ?? local?.given_path);
    const row = (p: Record<string, unknown> | undefined): number | undefined =>
      typeof p?.row === 'number' ? positive(p.row + 1) : undefined;
    const col = (p: Record<string, unknown> | undefined): number =>
      typeof p?.column === 'number' ? (positive(p.column + 1) ?? 1) : 1;
    const startLine = row(start);
    const endLine = row(end) ?? startLine;
    const severity = determinations.severity;
    const rule =
      typeof item.ident === 'string' ? `zizmor/${item.ident}` : undefined;
    if (
      path === undefined ||
      startLine === undefined ||
      endLine === undefined ||
      endLine < startLine ||
      rule === undefined ||
      !ruleOk.test(rule) ||
      typeof severity !== 'string' ||
      !severityOk.test(severity)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    const startColumn = col(start);
    drafts.push({
      ruleId: rule,
      nativeSeverity: severity,
      path,
      range: {
        startLine,
        startColumn,
        endLine,
        endColumn:
          endLine === startLine ? Math.max(startColumn, col(end)) : col(end),
      },
      message: redactMessage(item.desc),
    });
  }
  return finish('zizmor', drafts, partial);
}

/**
 * Run `<executable> <versionArgs>` once under a scrubbed environment and
 * require the pinned version to appear in the output as a whole token. The
 * trimmed output is what the adapter must see again before it scans (the
 * binary itself is already sha256-pinned).
 */
export async function pinnedVersionOutput(
  executable: string,
  versionArgs: readonly string[],
  version: string,
): Promise<string> {
  const { stdout } = await exec(executable, [...versionArgs], {
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
    timeout: 10000,
  });
  const output = stdout.trim();
  const token = new RegExp(
    `(?<![0-9A-Za-z.])v?${version.replace(/\./g, '\\.')}(?![0-9A-Za-z.])`,
  );
  if (!token.test(output)) throw new Error('unexpected engine version');
  return output;
}

export interface LintEngineSpec {
  id: LintEngineId;
  versionArgs: readonly string[];
  /** Tracked paths this engine analyses. */
  matches: (path: string) => boolean;
  /** Fixed, bundled-default arguments; the file list follows `--`. */
  fixedArgs: readonly string[];
  successExitCodes: readonly number[];
  rulesetVersion: string;
  parse: (stdout: string) => ParsedOutput | undefined;
}

const shellFile = /\.(?:sh|bash|ksh)$/;
const workflowFile = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
export const isShellFile = (path: string): boolean => shellFile.test(path);
export const isWorkflowFile = (path: string): boolean =>
  workflowFile.test(path);

/**
 * Bundled defaults only: no repository config is ever passed, and none exists
 * in the private workspace (only the selected files are written there).
 * - shellcheck: `--norc` ignores user/project rc files; default checks, all severities.
 * - shfmt: `-d` prints a diff and never writes; explicit `-i 2 -ci` makes shfmt
 *   ignore EditorConfig so formatting is the same everywhere.
 * - actionlint: no config file is read for explicit file arguments' project.
 * - zizmor: `--offline` makes no GitHub API call and needs no token.
 */
export const lintEngines: Readonly<Record<LintEngineId, LintEngineSpec>> = {
  shellcheck: {
    id: 'shellcheck',
    versionArgs: ['--version'],
    matches: isShellFile,
    fixedArgs: ['--norc', '--format=json1', '--'],
    successExitCodes: [0, 1],
    rulesetVersion: `default-${lintPins.shellcheck.version}`,
    parse: parseShellcheckReport,
  },
  shfmt: {
    id: 'shfmt',
    versionArgs: ['--version'],
    matches: isShellFile,
    fixedArgs: ['-d', '-i', '2', '-ci', '--'],
    successExitCodes: [0, 1],
    rulesetVersion: `i2-ci-${lintPins.shfmt.version}`,
    parse: parseShfmtDiff,
  },
  actionlint: {
    id: 'actionlint',
    versionArgs: ['-version'],
    matches: isWorkflowFile,
    fixedArgs: ['-no-color', '-format', '{{json .}}', '--'],
    successExitCodes: [0, 1],
    rulesetVersion: `default-${lintPins.actionlint.version}`,
    parse: parseActionlintReport,
  },
  zizmor: {
    id: 'zizmor',
    versionArgs: ['--version'],
    matches: isWorkflowFile,
    fixedArgs: ['--offline', '--format=json', '--'],
    // 0 clean; 10..14 mean findings at increasing severity. 1 is an engine error.
    successExitCodes: [0, 10, 11, 12, 13, 14],
    rulesetVersion: `offline-${lintPins.zizmor.version}`,
    parse: parseZizmorReport,
  },
};

/** The adapter for one batch of files (the file list is the only caller input). */
export function lintAdapter(
  spec: LintEngineSpec,
  executable: string,
  versionOutput: string,
  batch: readonly string[],
  /** Override only for a fake executable in tests; defaults to the pin. */
  executableSha256: string = lintPins[spec.id].sha256,
): ScannerAdapter {
  const pin = lintPins[spec.id];
  return {
    engine: { id: spec.id, version: pin.version },
    rulesetVersion: spec.rulesetVersion,
    configVersion: `bundled-${pin.version}`,
    executable,
    executableSha256,
    versionArgs: spec.versionArgs,
    versionOutput,
    fixedArgs: spec.fixedArgs,
    allowedArgs: batch,
    successExitCodes: spec.successExitCodes,
    parse: spec.parse,
  };
}

/** Split into runs of at most {@link lintBatchSize}; paths unusable as an argument are returned apart. */
export function planBatches(paths: readonly string[]): {
  batches: string[][];
  unusable: string[];
} {
  const usable: string[] = [];
  const unusable: string[] = [];
  for (const p of paths)
    (p.length <= lintArgChars && !p.startsWith('-') ? usable : unusable).push(
      p,
    );
  const batches: string[][] = [];
  for (let i = 0; i < usable.length; i += lintBatchSize)
    batches.push(usable.slice(i, i + lintBatchSize));
  return { batches, unusable };
}
