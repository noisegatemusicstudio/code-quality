import { createHash } from 'node:crypto';

/**
 * Versioned, bounded result envelope emitted by scanner adapters and detailed
 * imports. It carries scope identifiers but proves nothing by itself: the
 * `provenance` says whether the producer was executed by an adapter here or is
 * an unverified import, and no authentication or upload is implied.
 */
export const envelopeSchemaVersion = 1;
export const envelopeLimits = Object.freeze({
  rawBytes: 1048576,
  findings: 5000,
  messageChars: 300,
  pathChars: 512,
  maxLine: 10000000,
});
export const envelopeStatuses = [
  'completed',
  'failed',
  'skipped',
  'incomplete',
] as const;
export type EnvelopeStatus = (typeof envelopeStatuses)[number];
export const envelopeReasons = [
  'finding-limit',
  'path-outside-root',
  'timeout',
  'cancelled',
  'output-limit',
  'engine-error',
  'invalid-output',
  'engine-version-mismatch',
  'invalid-request',
  'unsupported-platform',
  'workspace-error',
  'cleanup-uncertain',
] as const;
export type EnvelopeReason = (typeof envelopeReasons)[number];
export type EnvelopeProvenance = 'imported-unverified' | 'adapter-executed';

export interface EnvelopeScope {
  tenantId: string;
  projectId: string;
  repository: string;
  commitSha: string;
  sourceId: string;
  jobId: string;
  attemptId: string;
}
export interface FindingRange {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}
export interface AdapterFinding {
  /** Engine-native rule identifier, never remapped. */
  ruleId: string;
  /** Engine-native severity label, never normalized. */
  nativeSeverity: string;
  path: string;
  range: FindingRange;
  /** `sha256:` plus 64 lowercase hex; see {@link findingFingerprint}. */
  fingerprint: string;
  /** Redacted, control-free and truncated; never raw source or secrets. */
  message: string;
}
export interface AdapterEnvelope extends EnvelopeScope {
  schemaVersion: 1;
  provenance: EnvelopeProvenance;
  engine: { id: string; version: string };
  rulesetVersion: string;
  configVersion: string;
  status: EnvelopeStatus;
  /** Required unless `completed`; forbidden when `completed`. */
  reason?: EnvelopeReason;
  findings: AdapterFinding[];
}
export type EnvelopeValidation =
  { ok: true; envelope: AdapterEnvelope } | { ok: false; error: string };

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const repositoryPattern =
  /^[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._-]{1,100}){0,2}$/;
const versionPattern = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const fingerprintPattern = /^sha256:[a-f0-9]{64}$/;
const ruleIdPattern = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const severityPattern = /^[A-Za-z0-9._-]{1,32}$/;

export const isEnvelopeId = (value: unknown): value is string =>
  typeof value === 'string' && idPattern.test(value);
export const isEnvelopeVersion = (value: unknown): value is string =>
  typeof value === 'string' && versionPattern.test(value);

const isControlCode = (code: number, c1: boolean): boolean =>
  code < 32 || code === 127 || (c1 && code >= 128 && code <= 159);
/** True when the text holds a C0 control character or DEL. */
export const hasControl = (value: string): boolean =>
  Array.from(value).some((c) => isControlCode(c.codePointAt(0) ?? 0, false));

/** Repository-relative POSIX path with no traversal, control or absolute form. */
export function isSafeRelativePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > envelopeLimits.pathChars ||
    value.startsWith('/') ||
    value.includes('\\') ||
    hasControl(value) ||
    /^[A-Za-z]:/.test(value)
  )
    return false;
  return value.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

const redactions: readonly [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/g, '<redacted>'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '<redacted>'],
  [
    /\b(?:gh[pousr]_|github_pat_|xox[abprs]-|sk-)[A-Za-z0-9_-]{8,}/g,
    '<redacted>',
  ],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer <redacted>'],
  [
    /\b(password|passwd|secret|token|api[_-]?key|authorization)(\s*[:=]\s*)\S+/gi,
    '$1$2<redacted>',
  ],
  [/\b[A-Za-z0-9+/_=-]{32,}\b/g, '<redacted>'],
  [/(?:[A-Za-z]:\\|\/)(?:[^\s/\\'"]+[/\\])+[^\s/\\'"]*/g, '<path>'],
];

/** Best-effort, deterministic redaction. It reduces leakage; it is not proof. */
export function redactMessage(message: unknown): string {
  let text = typeof message === 'string' ? message : '';
  text = Array.from(text, (c) =>
    isControlCode(c.codePointAt(0) ?? 0, true) ? ' ' : c,
  )
    .join('')
    .replace(/ {2,}/g, ' ')
    .trim();
  for (const [pattern, replacement] of redactions)
    text = text.replace(pattern, replacement);
  return text.length > envelopeLimits.messageChars
    ? text.slice(0, envelopeLimits.messageChars - 1) + '…'
    : text;
}

/**
 * Stable fingerprint of engine, native rule, location and redacted message.
 * `occurrence` distinguishes otherwise identical findings, so distinct reported
 * locations or repeats are never collapsed. Line shifts change the value:
 * cross-run correlation belongs to a later comparison layer.
 */
export function findingFingerprint(
  engineId: string,
  finding: Omit<AdapterFinding, 'fingerprint'>,
  occurrence = 0,
): string {
  const hash = createHash('sha256')
    .update(
      JSON.stringify([
        engineId,
        finding.ruleId,
        finding.path,
        finding.range.startLine,
        finding.range.startColumn,
        finding.range.endLine,
        finding.range.endColumn,
        finding.message,
        occurrence,
      ]),
    )
    .digest('hex');
  return `sha256:${hash}`;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const hasExactKeys = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean => {
  const keys = Object.keys(value);
  return (
    required.every((k) => Object.hasOwn(value, k)) &&
    keys.every((k) => required.includes(k) || optional.includes(k))
  );
};
const isLine = (value: unknown): value is number =>
  typeof value === 'number' &&
  Number.isSafeInteger(value) &&
  value >= 1 &&
  value <= envelopeLimits.maxLine;

const scopeKeys = [
  'tenantId',
  'projectId',
  'sourceId',
  'jobId',
  'attemptId',
] as const;

/** Validate the scope fields of a prospective envelope (also used by adapters). */
export function isValidScope(scope: unknown): scope is EnvelopeScope {
  if (!isRecord(scope)) return false;
  return (
    scopeKeys.every((k) => isEnvelopeId(scope[k])) &&
    typeof scope.repository === 'string' &&
    repositoryPattern.test(scope.repository) &&
    typeof scope.commitSha === 'string' &&
    commitPattern.test(scope.commitSha)
  );
}

/**
 * Parse and validate an envelope from JSON text or an object. Unknown keys,
 * oversize input and inconsistent status/reason/findings fail closed. When
 * `expected` is given, every scope field must match exactly: a record for
 * another tenant, project, repository, commit, source, job or attempt is denied.
 */
export function validateEnvelope(
  input: unknown,
  expected?: EnvelopeScope,
): EnvelopeValidation {
  const fail = (error: string): EnvelopeValidation => ({ ok: false, error });
  let root = input;
  if (typeof input === 'string') {
    if (
      input.length > envelopeLimits.rawBytes ||
      Buffer.byteLength(input, 'utf8') > envelopeLimits.rawBytes
    )
      return fail('oversize');
    try {
      root = JSON.parse(input);
    } catch {
      return fail('malformed-json');
    }
  }
  if (
    !isRecord(root) ||
    !hasExactKeys(
      root,
      [
        'schemaVersion',
        'provenance',
        'tenantId',
        'projectId',
        'repository',
        'commitSha',
        'sourceId',
        'jobId',
        'attemptId',
        'engine',
        'rulesetVersion',
        'configVersion',
        'status',
        'findings',
      ],
      ['reason'],
    )
  )
    return fail('shape');
  if (root.schemaVersion !== envelopeSchemaVersion)
    return fail('schema-version');
  if (
    root.provenance !== 'imported-unverified' &&
    root.provenance !== 'adapter-executed'
  )
    return fail('provenance');
  if (!isValidScope(root)) return fail('scope');
  if (expected) {
    if (!isValidScope(expected)) return fail('expected-scope');
    for (const key of [...scopeKeys, 'repository', 'commitSha'] as const)
      if (root[key] !== expected[key]) return fail(`cross-scope:${key}`);
  }
  const engine = root.engine;
  if (
    !isRecord(engine) ||
    !hasExactKeys(engine, ['id', 'version']) ||
    !isEnvelopeId(engine.id) ||
    !isEnvelopeVersion(engine.version)
  )
    return fail('engine');
  if (
    !isEnvelopeVersion(root.rulesetVersion) ||
    !isEnvelopeVersion(root.configVersion)
  )
    return fail('versions');
  const status = root.status;
  if (!envelopeStatuses.some((s) => s === status)) return fail('status');
  const reason = root.reason;
  if (status === 'completed') {
    if (Object.hasOwn(root, 'reason')) return fail('reason-on-completed');
  } else if (!envelopeReasons.some((r) => r === reason)) {
    return fail('reason-required');
  }
  const findings = root.findings;
  if (!Array.isArray(findings) || findings.length > envelopeLimits.findings)
    return fail('findings-limit');
  // Only completed/incomplete runs may carry results; others never imply any.
  if ((status === 'failed' || status === 'skipped') && findings.length > 0)
    return fail('findings-on-non-result-status');
  const seen = new Set<string>();
  const clean: AdapterFinding[] = [];
  for (const item of findings as unknown[]) {
    if (
      !isRecord(item) ||
      !hasExactKeys(item, [
        'ruleId',
        'nativeSeverity',
        'path',
        'range',
        'fingerprint',
        'message',
      ])
    )
      return fail('finding-shape');
    const range = item.range;
    if (
      typeof item.ruleId !== 'string' ||
      !ruleIdPattern.test(item.ruleId) ||
      typeof item.nativeSeverity !== 'string' ||
      !severityPattern.test(item.nativeSeverity) ||
      !isSafeRelativePath(item.path) ||
      typeof item.fingerprint !== 'string' ||
      !fingerprintPattern.test(item.fingerprint) ||
      typeof item.message !== 'string' ||
      item.message.length > envelopeLimits.messageChars ||
      hasControl(item.message) ||
      !isRecord(range) ||
      !hasExactKeys(range, [
        'startLine',
        'startColumn',
        'endLine',
        'endColumn',
      ]) ||
      !isLine(range.startLine) ||
      !isLine(range.startColumn) ||
      !isLine(range.endLine) ||
      !isLine(range.endColumn) ||
      range.endLine < range.startLine ||
      (range.endLine === range.startLine && range.endColumn < range.startColumn)
    )
      return fail('finding-field');
    if (seen.has(item.fingerprint)) return fail('duplicate-fingerprint');
    seen.add(item.fingerprint);
    clean.push({
      ruleId: item.ruleId,
      nativeSeverity: item.nativeSeverity,
      path: item.path,
      range: {
        startLine: range.startLine,
        startColumn: range.startColumn,
        endLine: range.endLine,
        endColumn: range.endColumn,
      },
      fingerprint: item.fingerprint,
      message: item.message,
    });
  }
  const envelope: AdapterEnvelope = {
    schemaVersion: 1,
    provenance: root.provenance,
    tenantId: root.tenantId,
    projectId: root.projectId,
    repository: root.repository,
    commitSha: root.commitSha,
    sourceId: root.sourceId,
    jobId: root.jobId,
    attemptId: root.attemptId,
    engine: { id: engine.id, version: engine.version },
    rulesetVersion: root.rulesetVersion,
    configVersion: root.configVersion,
    status: status as EnvelopeStatus,
    findings: clean,
  };
  if (status !== 'completed') envelope.reason = reason as EnvelopeReason;
  return { ok: true, envelope };
}
