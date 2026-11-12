import { isAbsolute } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeStatus,
  envelopeLimits,
  findingFingerprint,
  isSafeRelativePath,
} from './adapter-envelope.js';
import { externalPins } from './scanner-pins.js';
import type { ParsedOutput, ScannerAdapter } from './scanner-adapter.js';

/** Pinned, approved Gitleaks CLI (MIT). gitleaks-action is never used. */
export const gitleaksVersion = externalPins.gitleaks.version;
export const gitleaksConfigVersion = `reviewed-config-${gitleaksVersion}`;

export type GitleaksMode = 'working-tree' | 'commit-range';
export interface GitleaksOptions {
  /** Trusted absolute path to the pinned gitleaks executable. */
  executable: string;
  /**
   * Trusted, reviewed rule config. Always passed explicitly so a scanned
   * repository can never supply (or broaden) its own `.gitleaks.toml`.
   */
  configPath: string;
  /**
   * SHA-256 the executable must match. Defaults to the pinned
   * `externalPins.gitleaks.sha256`; override only for a fake in tests.
   */
  executableSha256?: string;
  /** Trusted ignore file/dir; passed explicitly so a repo `.gitleaksignore` is not read. */
  ignorePath: string;
  mode: GitleaksMode;
  /** commit-range only: 40-hex base and head commits; head is the scoped commit. */
  range?: { base: string; head: string };
  /** commit-range only: absolute path of a prepared clone to read history from. */
  repoPath?: string;
  /** commit-range only: true when the clone is shallow or history is incomplete. */
  shallow?: boolean;
}
/** Exact scan coverage to store beside the envelope. */
export interface GitleaksScanRecord {
  mode: GitleaksMode;
  engineVersion: string;
  headCommit?: string;
  range?: { base: string; head: string };
  incompleteHistory: boolean;
}
export interface GitleaksAdapterDefinition {
  adapter: ScannerAdapter;
  record: GitleaksScanRecord;
}

const sha = /^[a-f0-9]{40}$/;
const rulePattern = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const fileMax = envelopeLimits.pathChars;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const line = (v: unknown): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : undefined;

/**
 * Convert a Gitleaks JSON report into findings. Only `RuleID`, `File` and the
 * line/column fields are read; `Secret`, `Match` and every other field are
 * never copied. The scan must have run with `--redact`: a `Secret` that is not
 * the redaction placeholder means the engine ignored it, and the whole report
 * is rejected (fail closed). Errors never include report content.
 */
export function parseGitleaksReport(
  stdout: string,
  incompleteHistory = false,
  /** Absolute scan root to strip when the engine reports absolute paths. */
  pathRoot?: string,
): ParsedOutput | undefined {
  const root: unknown = JSON.parse(stdout);
  if (!Array.isArray(root)) return undefined;
  const candidates: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let partial: EnvelopeReason | undefined = incompleteHistory
    ? 'incomplete-history'
    : undefined;
  for (const item of root as unknown[]) {
    if (!isRecord(item)) return undefined;
    const secret = item.Secret;
    if (
      secret !== undefined &&
      secret !== '' &&
      !(typeof secret === 'string' && /^(?:\*+|REDACTED)$/i.test(secret))
    )
      return undefined;
    const file = typeof item.File === 'string' ? item.File : undefined;
    const stripped =
      pathRoot && file?.startsWith(`${pathRoot}/`)
        ? file.slice(pathRoot.length + 1)
        : file;
    const rel = stripped?.startsWith('./') ? stripped.slice(2) : stripped;
    if (
      rel === undefined ||
      rel.length > fileMax ||
      !isSafeRelativePath(rel) ||
      typeof item.RuleID !== 'string' ||
      !rulePattern.test(item.RuleID)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    const startLine = line(item.StartLine);
    const endLine = line(item.EndLine) ?? startLine;
    const startColumn = line(item.StartColumn) ?? 1;
    const endColumn = line(item.EndColumn) ?? startColumn;
    if (
      startLine === undefined ||
      endLine === undefined ||
      endLine < startLine ||
      (endLine === startLine && endColumn < startColumn)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    candidates.push({
      ruleId: item.RuleID,
      nativeSeverity: 'secret',
      path: rel,
      range: { startLine, startColumn, endLine, endColumn },
      message: `Potential secret detected by rule ${item.RuleID}`.slice(
        0,
        envelopeLimits.messageChars,
      ),
    });
  }
  candidates.sort(
    (a, b) =>
      a.path.localeCompare(b.path, 'en') ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId, 'en'),
  );
  if (candidates.length > envelopeLimits.findings) {
    candidates.length = envelopeLimits.findings;
    partial ??= 'finding-limit';
  }
  const seen = new Map<string, number>();
  // Identity is rule + path + location only: no secret-derived value at all.
  const findings = candidates.map((c): AdapterFinding => {
    const key = findingFingerprint('gitleaks', c);
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    return {
      ...c,
      fingerprint: n === 0 ? key : findingFingerprint('gitleaks', c, n),
    };
  });
  return partial ? { findings, partial } : { findings };
}

/**
 * Build the Gitleaks adapter for one explicitly selected scope. Arguments are
 * fixed (nothing caller-controlled, so `allowedArgs` is empty): the report goes
 * to stdout, secrets are redacted by the engine, inline `gitleaks:allow`
 * comments are ignored, and config/ignore files are the trusted ones given.
 * Throws on out-of-contract options; the scan never validates or uses a secret.
 */
export function createGitleaksAdapter(
  options: GitleaksOptions,
): GitleaksAdapterDefinition {
  const abs = (p: unknown): p is string =>
    typeof p === 'string' && isAbsolute(p) && !p.includes('\0');
  if (!abs(options.executable) || !abs(options.configPath))
    throw new TypeError('Invalid gitleaks options');
  if (!abs(options.ignorePath)) throw new TypeError('Invalid gitleaks options');
  const common = [
    '--no-banner',
    '--log-level',
    'error',
    '--redact',
    '--ignore-gitleaks-allow',
    '--config',
    options.configPath,
    '--gitleaks-ignore-path',
    options.ignorePath,
    '--report-format',
    'json',
    '--report-path',
    '-',
    '--exit-code',
    '2',
  ];
  let fixedArgs: string[];
  const record: GitleaksScanRecord = {
    mode: options.mode,
    engineVersion: gitleaksVersion,
    incompleteHistory: false,
  };
  if (options.mode === 'working-tree') {
    if (options.range || options.repoPath || options.shallow)
      throw new TypeError('Invalid gitleaks options');
    fixedArgs = ['dir', '.', ...common];
  } else if (options.mode === 'commit-range') {
    const r = options.range;
    if (!r || !sha.test(r.base) || !sha.test(r.head) || !abs(options.repoPath))
      throw new TypeError('Invalid gitleaks options');
    fixedArgs = [
      'git',
      `--log-opts=--no-merges ${r.base}..${r.head}`,
      ...common,
      options.repoPath,
    ];
    record.range = { base: r.base, head: r.head };
    record.headCommit = r.head;
    record.incompleteHistory = options.shallow === true;
  } else {
    throw new TypeError('Invalid gitleaks options');
  }
  const incomplete = record.incompleteHistory;
  return {
    record,
    adapter: {
      engine: { id: 'gitleaks', version: gitleaksVersion },
      rulesetVersion: `default-${gitleaksVersion}`,
      configVersion: gitleaksConfigVersion,
      executable: options.executable,
      executableSha256:
        options.executableSha256 ?? externalPins.gitleaks.sha256,
      versionArgs: ['version'],
      versionOutput: gitleaksVersion,
      fixedArgs,
      allowedArgs: [],
      // 0 = no leaks, 2 = leaks found; 1 (and anything else) is an engine error.
      successExitCodes: [0, 2],
      parse: (stdout) => parseGitleaksReport(stdout, incomplete),
    },
  };
}

/** A reviewed, time-bounded exception for exactly one finding. */
export interface GitleaksException {
  fingerprint: string;
  ruleId: string;
  path: string;
  reviewedBy: string;
  /** Calendar dates, `YYYY-MM-DD`. */
  reviewedAt: string;
  expiresAt: string;
  reason: string;
}
export const maxExceptionDays = 90;
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const dayMs = 86400000;
const toTime = (d: unknown): number | undefined => {
  if (typeof d !== 'string' || !datePattern.test(d)) return undefined;
  const t = Date.parse(`${d}T00:00:00Z`);
  return Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== d
    ? undefined
    : t;
};

export interface GitleaksClassification {
  scanStatus: EnvelopeStatus;
  scanReason?: EnvelopeReason;
  /** Findings with no valid, unexpired exception. */
  active: AdapterFinding[];
  excepted: { finding: AdapterFinding; expiresAt: string }[];
  counts: {
    active: number;
    new: number;
    existing: number;
    excepted: number;
    expiredExceptions: number;
    rejectedExceptions: number;
    unusedExceptions: number;
  };
}

/**
 * Apply reviewed exceptions and a baseline to a Gitleaks envelope. Exceptions
 * match one exact fingerprint (rule and path must agree too): there are no
 * wildcards, so an allowlist can never widen implicitly. Expired, malformed or
 * over-long (> 90 days) entries are rejected and never applied, and an expired
 * exception makes the finding active again. A failed or skipped scan stays
 * failed: exceptions never turn it into a clean result.
 */
export function classifyGitleaksEnvelope(
  envelope: AdapterEnvelope,
  context: {
    exceptions?: readonly GitleaksException[];
    /** Fingerprints already known from an earlier run. */
    baseline?: ReadonlySet<string>;
    now: Date;
  },
): GitleaksClassification {
  const counts = {
    active: 0,
    new: 0,
    existing: 0,
    excepted: 0,
    expiredExceptions: 0,
    rejectedExceptions: 0,
    unusedExceptions: 0,
  };
  const out: GitleaksClassification = {
    scanStatus: envelope.status,
    active: [],
    excepted: [],
    counts,
  };
  if (envelope.reason) out.scanReason = envelope.reason;
  const today = Date.UTC(
    context.now.getUTCFullYear(),
    context.now.getUTCMonth(),
    context.now.getUTCDate(),
  );
  const valid = new Map<
    string,
    { exception: GitleaksException; end: number }
  >();
  for (const e of context.exceptions ?? []) {
    const start = toTime(e?.reviewedAt);
    const end = toTime(e?.expiresAt);
    if (
      start === undefined ||
      end === undefined ||
      end <= start ||
      (end - start) / dayMs > maxExceptionDays ||
      typeof e.fingerprint !== 'string' ||
      !/^sha256:[a-f0-9]{64}$/.test(e.fingerprint) ||
      typeof e.ruleId !== 'string' ||
      typeof e.path !== 'string' ||
      typeof e.reviewedBy !== 'string' ||
      e.reviewedBy.trim() === '' ||
      typeof e.reason !== 'string' ||
      e.reason.trim() === '' ||
      valid.has(e.fingerprint)
    ) {
      counts.rejectedExceptions++;
      continue;
    }
    valid.set(e.fingerprint, { exception: e, end });
  }
  if (envelope.status === 'failed' || envelope.status === 'skipped') {
    counts.unusedExceptions = valid.size;
    return out;
  }
  const used = new Set<string>();
  for (const f of envelope.findings) {
    const hit = valid.get(f.fingerprint);
    const matches =
      hit !== undefined &&
      hit.exception.ruleId === f.ruleId &&
      hit.exception.path === f.path;
    if (matches) used.add(f.fingerprint);
    if (matches && hit.end > today) {
      counts.excepted++;
      out.excepted.push({ finding: f, expiresAt: hit.exception.expiresAt });
      continue;
    }
    if (matches) counts.expiredExceptions++;
    out.active.push(f);
    counts.active++;
    if (context.baseline?.has(f.fingerprint)) counts.existing++;
    else counts.new++;
  }
  counts.unusedExceptions = valid.size - used.size;
  return out;
}
