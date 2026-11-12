import { isAbsolute } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  envelopeLimits,
  isEnvelopeVersion,
  isSafeRelativePath,
  isValidScope,
  redactMessage,
  validateEnvelope,
} from './adapter-envelope.js';
import { assembleFindings } from './finding-assembly.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';

/**
 * Semgrep CE adapter (RRDSCRUM-133), bounded by docs/scanner-licensing.md:
 * - The engine (LGPL-2.1) is a customer- or operator-installed binary at a
 *   trusted absolute path. This code never downloads, bundles or ships it.
 * - Semgrep-maintained registry rules (Semgrep Rules License v1.0) are for
 *   ReleaseReady's own internal repositories only, never customers. They are
 *   only usable from a pinned local snapshot, and only when the caller marks
 *   the scope `internal`.
 * - ReleaseReady-authored rules live in `rules/semgrep/`.
 * - CodeQL and Sonar analyzers are not used. Results are Semgrep CE findings
 *   from a small starter ruleset; they are not Sonar-equivalent or complete.
 */
export const semgrepVersion = '1.185.0';
export const releaseReadyRulesVersion = '2026.11.1';
export const semgrepConfigVersion = `reviewed-args-${semgrepVersion}`;
export const semgrepCoverageNotice =
  'Semgrep CE findings from the configured ruleset only. This is not a Sonar-equivalent analysis and says nothing about code the rules do not cover.';

/** Approved ruleset sources. Anything else is refused, never substituted. */
export type SemgrepRulesetSource =
  'releaseready-authored' | 'semgrep-maintained-snapshot';
const internalOnlySources: readonly string[] = ['semgrep-maintained-snapshot'];
const approvedSources: readonly string[] = [
  'releaseready-authored',
  'semgrep-maintained-snapshot',
];

export interface SemgrepOptions {
  /** Trusted absolute path to the installed `semgrep` v1.185.0 executable. */
  executable: string;
  ruleset: {
    source: SemgrepRulesetSource;
    /** Absolute path to a local, pinned rules file or directory. */
    path: string;
    version: string;
  };
  /** Must be exactly `internal` to use an internal-only ruleset source. */
  audience?: 'internal' | 'customer';
}
export type SemgrepRefusal =
  | 'internal-only-ruleset'
  | 'registry-config'
  | 'unapproved-ruleset'
  | 'unsupported-language'
  | 'invalid-options';

export type SemgrepFindingKind = 'vulnerability' | 'review-required-hotspot';
export type SemgrepConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export interface SemgrepLocation {
  path: string;
  line: number;
}
/** Locations only: no source text is ever copied. */
export interface SemgrepDataflowSummary {
  source?: SemgrepLocation;
  intermediateCount: number;
  sink?: SemgrepLocation;
}
export interface SemgrepFindingDetail {
  kind: SemgrepFindingKind;
  confidence: SemgrepConfidence;
  cwe: string[];
  dataflow?: SemgrepDataflowSummary;
  remediation?: string;
}
export interface SemgrepParsedOutput extends ParsedOutput {
  /** Keyed by finding fingerprint. */
  details: Record<string, SemgrepFindingDetail>;
}
export interface SemgrepScanResult {
  envelope: AdapterEnvelope;
  details: Record<string, SemgrepFindingDetail>;
  /** Set when the scan was refused before the engine ran. */
  refusal?: SemgrepRefusal;
  /** Files in the request that were not scanned because of their language. */
  unsupportedFiles: string[];
  notice: string;
}

const supportedExtension = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const rulePattern = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const severityPattern = /^[A-Za-z0-9._-]{1,32}$/;
const ownRuleId = /(?:^|\.)(releaseready\.js\.[a-z0-9-]+)$/;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const line = (v: unknown): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : undefined;
const text = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() !== '' ? redactMessage(v) : undefined;

/** Only an absolute local path can be a rules config; registry names cannot. */
export function isLocalRulesPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isAbsolute(value) &&
    !value.includes('\0') &&
    !value.includes('://') &&
    !value.split('/').includes('..') &&
    value.length <= 512
  );
}

function cweIds(metadata: Record<string, unknown>): string[] {
  const raw = Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe];
  const ids = new Set<string>();
  for (const entry of raw)
    if (typeof entry === 'string')
      for (const m of entry.matchAll(/CWE-(\d{1,5})/gi))
        ids.add(`CWE-${m[1] ?? ''}`);
  return [...ids].sort((a, b) => a.localeCompare(b, 'en'));
}

function confidenceOf(metadata: Record<string, unknown>): SemgrepConfidence {
  const c =
    typeof metadata.confidence === 'string'
      ? metadata.confidence.toUpperCase()
      : '';
  return c === 'HIGH' || c === 'MEDIUM' || c === 'LOW' ? c : 'UNKNOWN';
}

/**
 * An explicit `finding-type` in rule metadata wins. Otherwise a finding is only
 * a vulnerability when the rule states HIGH or MEDIUM confidence: anything else
 * needs a human, so it is a review-required hotspot.
 */
function kindOf(
  metadata: Record<string, unknown>,
  confidence: SemgrepConfidence,
): SemgrepFindingKind {
  const t = metadata['finding-type'];
  if (t === 'vulnerability') return 'vulnerability';
  if (t === 'hotspot' || t === 'review-required-hotspot')
    return 'review-required-hotspot';
  return confidence === 'HIGH' || confidence === 'MEDIUM'
    ? 'vulnerability'
    : 'review-required-hotspot';
}

function locationOf(value: unknown): SemgrepLocation | undefined {
  if (Array.isArray(value)) {
    // Semgrep encodes ["CliLoc", [location, content]]; content is ignored.
    const inner: unknown = value[1];
    return locationOf(Array.isArray(inner) ? inner[0] : inner);
  }
  if (!isRecord(value)) return undefined;
  if (isRecord(value.location)) return locationOf(value.location);
  const start = value.start;
  const path = value.path;
  const ln = isRecord(start) ? line(start.line) : undefined;
  if (typeof path !== 'string' || ln === undefined) return undefined;
  const rel = path.startsWith('./') ? path.slice(2) : path;
  return isSafeRelativePath(rel) ? { path: rel, line: ln } : undefined;
}

function dataflowOf(trace: unknown): SemgrepDataflowSummary | undefined {
  if (!isRecord(trace)) return undefined;
  const summary: SemgrepDataflowSummary = {
    intermediateCount: Array.isArray(trace.intermediate_vars)
      ? Math.min(trace.intermediate_vars.length, 1000)
      : 0,
  };
  const source = locationOf(trace.taint_source);
  const sink = locationOf(trace.taint_sink);
  if (source) summary.source = source;
  if (sink) summary.sink = sink;
  return source || sink || summary.intermediateCount > 0 ? summary : undefined;
}

/**
 * Own rules are namespaced by Semgrep with the rules directory path; drop that
 * install-specific prefix so ids and fingerprints are stable across machines.
 * Other rule ids are kept exactly as the engine reported them.
 */
function nativeRuleId(checkId: string): string {
  return ownRuleId.exec(checkId)?.[1] ?? checkId;
}

/**
 * Convert `semgrep --json` output. Reads rule id, path, range, severity and
 * the metadata fields CWE, confidence, finding-type and remediation, plus
 * dataflow *locations*. Matched source (`extra.lines`), `extra.fix` and trace
 * contents are never copied. A non-empty `errors` array marks the run
 * `incomplete`; malformed JSON or a missing `results` array is unusable.
 */
export function parseSemgrepReport(stdout: string): SemgrepParsedOutput {
  const root: unknown = JSON.parse(stdout);
  if (!isRecord(root) || !Array.isArray(root.results))
    throw new TypeError('not a semgrep report');
  let partial: EnvelopeReason | undefined;
  if (root.errors !== undefined && !Array.isArray(root.errors))
    throw new TypeError('not a semgrep report');
  if (Array.isArray(root.errors) && root.errors.length > 0)
    partial = 'engine-error';
  type Candidate = Omit<AdapterFinding, 'fingerprint'> & {
    detail: SemgrepFindingDetail;
  };
  const candidates: Candidate[] = [];
  for (const item of root.results as unknown[]) {
    const extra = isRecord(item) ? item.extra : undefined;
    const start = isRecord(item) ? item.start : undefined;
    const end = isRecord(item) ? item.end : undefined;
    const rel =
      isRecord(item) && typeof item.path === 'string'
        ? item.path.startsWith('./')
          ? item.path.slice(2)
          : item.path
        : undefined;
    const startLine = isRecord(start) ? line(start.line) : undefined;
    const endLine = isRecord(end) ? line(end.line) : undefined;
    const startColumn = (isRecord(start) ? line(start.col) : undefined) ?? 1;
    const endColumn =
      (isRecord(end) ? line(end.col) : undefined) ?? startColumn;
    if (
      !isRecord(item) ||
      !isRecord(extra) ||
      typeof item.check_id !== 'string' ||
      !rulePattern.test(nativeRuleId(item.check_id)) ||
      typeof extra.severity !== 'string' ||
      !severityPattern.test(extra.severity) ||
      rel === undefined ||
      !isSafeRelativePath(rel) ||
      startLine === undefined ||
      endLine === undefined ||
      endLine < startLine ||
      (endLine === startLine && endColumn < startColumn)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    const metadata = isRecord(extra.metadata) ? extra.metadata : {};
    const confidence = confidenceOf(metadata);
    const kind = kindOf(metadata, confidence);
    const cwe = cweIds(metadata);
    const detail: SemgrepFindingDetail = { kind, confidence, cwe };
    const flow = dataflowOf(extra.dataflow_trace);
    if (flow) detail.dataflow = flow;
    const remediation = text(metadata.remediation);
    if (remediation) detail.remediation = remediation;
    const label =
      kind === 'vulnerability' ? 'Vulnerability' : 'Review required';
    const message = redactMessage(
      `${label}: ${text(extra.message) ?? nativeRuleId(item.check_id)}${
        cwe.length > 0 ? ` (${cwe.join(', ')})` : ''
      }`,
    );
    candidates.push({
      ruleId: nativeRuleId(item.check_id),
      nativeSeverity: extra.severity,
      path: rel,
      range: { startLine, startColumn, endLine, endColumn },
      message,
      detail,
    });
  }
  const assembled = assembleFindings('semgrep', candidates, partial);
  const details: Record<string, SemgrepFindingDetail> = {};
  const findings = assembled.findings.map(
    ({ detail, ...f }): AdapterFinding => {
      details[f.fingerprint] = detail;
      return f;
    },
  );
  return assembled.partial
    ? { findings, partial: assembled.partial, details }
    : { findings, details };
}

/** Policy gate evaluated before anything is written or executed. */
export function semgrepRefusal(
  options: SemgrepOptions,
): { refusal: SemgrepRefusal; message: string } | undefined {
  const r = options?.ruleset;
  if (
    !isRecord(options) ||
    !isRecord(r) ||
    typeof options.executable !== 'string' ||
    !isAbsolute(options.executable) ||
    options.executable.includes('\0') ||
    !isEnvelopeVersion(r.version)
  )
    return { refusal: 'invalid-options', message: 'Invalid semgrep options' };
  if (!isLocalRulesPath(r.path))
    return {
      refusal: 'registry-config',
      message:
        'Semgrep --config must be an absolute local pinned rules path; registry names (auto, p/..., r/...) and URLs are rejected',
    };
  if (typeof r.source !== 'string' || !approvedSources.includes(r.source))
    return {
      refusal: 'unapproved-ruleset',
      message:
        'Ruleset source is not approved; no other ruleset is substituted',
    };
  if (internalOnlySources.includes(r.source) && options.audience !== 'internal')
    return {
      refusal: 'internal-only-ruleset',
      message:
        'Semgrep-maintained rules are internal-only (Semgrep Rules License v1.0) and never run for customer scopes',
    };
  return undefined;
}

/**
 * Fixed arguments only; callers pass none. `--metrics=off` and
 * `--disable-version-check` stop telemetry and version pings, `--config` is the
 * local pinned path, and `.` scans the adapter workspace. Semgrep runs no
 * build or install step. It is not network-enforced: see runAdapter.
 */
export function createSemgrepAdapter(options: SemgrepOptions): ScannerAdapter {
  const problem = semgrepRefusal(options);
  if (problem) throw new TypeError(problem.message);
  return {
    engine: { id: 'semgrep', version: semgrepVersion },
    rulesetVersion: `${options.ruleset.source}-${options.ruleset.version}`,
    configVersion: semgrepConfigVersion,
    executable: options.executable,
    // semgrep-core runs `uname`; nothing else is added to the scrubbed environment.
    systemPath: true,
    versionArgs: ['--version'],
    versionOutput: semgrepVersion,
    fixedArgs: [
      'scan',
      '--json',
      '--metrics=off',
      '--disable-version-check',
      '--config',
      options.ruleset.path,
      '.',
    ],
    allowedArgs: [],
    // Semgrep exits 0 with or without findings unless --error is passed.
    successExitCodes: [0],
    parse: (stdout) => parseSemgrepReport(stdout),
  };
}

const reasonFor: Record<SemgrepRefusal, EnvelopeReason> = {
  'internal-only-ruleset': 'customer-config-rejected',
  'registry-config': 'customer-config-rejected',
  'unapproved-ruleset': 'customer-config-rejected',
  'unsupported-language': 'no-supported-files',
  'invalid-options': 'invalid-request',
};

/**
 * Run Semgrep over TS/JS files in a private workspace. Refusals produce a
 * `skipped` envelope with the reason and an explicit `refusal` code before the
 * engine is touched; the engine failing or returning unusable output is
 * `failed`, and engine-reported errors are `incomplete`. Files in other
 * languages are listed in `unsupportedFiles`, never silently scanned or hidden.
 */
export async function runSemgrepScan(
  options: SemgrepOptions,
  request: {
    scope: EnvelopeScope;
    files: Readonly<Record<string, string>>;
    timeoutMs?: number;
    signal?: AbortSignal;
  },
): Promise<SemgrepScanResult> {
  const names = Object.keys(request.files);
  const supported = names.filter((n) => supportedExtension.test(n));
  const unsupportedFiles = names.filter((n) => !supportedExtension.test(n));
  const skipped = (refusal: SemgrepRefusal): SemgrepScanResult => {
    if (!isValidScope(request.scope))
      throw new TypeError('Invalid adapter or scope');
    const draft = {
      schemaVersion: 1,
      provenance: 'adapter-executed',
      ...request.scope,
      engine: { id: 'semgrep', version: semgrepVersion },
      rulesetVersion: isEnvelopeVersion(
        `${options?.ruleset?.source}-${options?.ruleset?.version}`,
      )
        ? `${options.ruleset.source}-${options.ruleset.version}`
        : 'unapproved',
      configVersion: semgrepConfigVersion,
      status: 'skipped',
      reason: reasonFor[refusal],
      findings: [],
    };
    const checked = validateEnvelope(draft, request.scope);
    if (!checked.ok) throw new TypeError('Invalid adapter or scope');
    return {
      envelope: checked.envelope,
      details: {},
      refusal,
      unsupportedFiles,
      notice: semgrepCoverageNotice,
    };
  };
  const refused = semgrepRefusal(options);
  if (refused) return skipped(refused.refusal);
  if (supported.length === 0) return skipped('unsupported-language');
  let details: Record<string, SemgrepFindingDetail> = {};
  const base = createSemgrepAdapter(options);
  const adapter: ScannerAdapter = {
    ...base,
    parse: (stdout, context) => {
      const parsed = base.parse(stdout, context) as SemgrepParsedOutput;
      details = parsed.details;
      return parsed;
    },
  };
  const files = Object.fromEntries(supported.map((n) => [n, request.files[n]]));
  const envelope = await runAdapter(adapter, {
    scope: request.scope,
    files: files,
    timeoutMs: request.timeoutMs,
    signal: request.signal,
  });
  const kept = new Set(envelope.findings.map((f) => f.fingerprint));
  return {
    envelope,
    details: Object.fromEntries(
      Object.entries(details).filter(([fp]) => kept.has(fp)),
    ),
    unsupportedFiles,
    notice: semgrepCoverageNotice,
  };
}
