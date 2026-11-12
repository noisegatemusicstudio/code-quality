import { isAbsolute, relative, sep } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  envelopeLimits,
  findingFingerprint,
  isEnvelopeVersion,
  isSafeRelativePath,
  isValidScope,
  redactMessage,
  validateEnvelope,
} from './adapter-envelope.js';

export type EslintImport =
  { status: 'parsed'; findingCount: number } | { status: 'invalid' };
/** Parsing is not producer completion, execution proof, or a quality gate. */
export function parseEslintJson(raw: unknown): EslintImport {
  const invalid: EslintImport = { status: 'invalid' };
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
  const ownCount = (
    item: Record<string, unknown>,
    key: string,
  ): number | null => {
    if (!Object.hasOwn(item, key)) return null;
    const value = item[key];
    return typeof value === 'number' &&
      Number.isSafeInteger(value) &&
      value >= 0
      ? value
      : null;
  };
  if (!Array.isArray(root) || root.length > 1000) return invalid;
  let findingCount = 0;
  let messageCount = 0;
  for (const file of root) {
    if (
      !isRecord(file) ||
      !Object.hasOwn(file, 'messages') ||
      !Object.hasOwn(file, 'suppressedMessages') ||
      !Array.isArray(file.messages) ||
      !Array.isArray(file.suppressedMessages)
    )
      return invalid;
    messageCount += file.messages.length + file.suppressedMessages.length;
    if (messageCount > 10000) return invalid;
    const errors = ownCount(file, 'errorCount');
    const warnings = ownCount(file, 'warningCount');
    const fatals = ownCount(file, 'fatalErrorCount');
    const fixableErrors = ownCount(file, 'fixableErrorCount');
    const fixableWarnings = ownCount(file, 'fixableWarningCount');
    if (
      errors === null ||
      warnings === null ||
      fatals === null ||
      fixableErrors === null ||
      fixableWarnings === null ||
      fixableErrors > errors ||
      fixableWarnings > warnings
    )
      return invalid;
    let derivedErrors = 0;
    let derivedWarnings = 0;
    let derivedFatals = 0;
    for (const message of file.messages) {
      if (
        !isRecord(message) ||
        !Object.hasOwn(message, 'severity') ||
        (message.severity !== 1 && message.severity !== 2)
      )
        return invalid;
      if (Object.hasOwn(message, 'fatal')) {
        if (
          typeof message.fatal !== 'boolean' ||
          (message.fatal && message.severity !== 2)
        )
          return invalid;
        if (message.fatal) derivedFatals++;
      }
      if (message.severity === 2) derivedErrors++;
      else derivedWarnings++;
    }
    if (
      errors !== derivedErrors ||
      warnings !== derivedWarnings ||
      fatals !== derivedFatals
    )
      return invalid;
    findingCount += file.messages.length;
  }
  return { status: 'parsed', findingCount };
}

export interface EslintEnvelopeContext extends EnvelopeScope {
  /** ESLint version that produced the report, as declared by the caller. */
  engineVersion: string;
  rulesetVersion: string;
  configVersion: string;
  /** Absolute directory the report's file paths are relative to. */
  pathRoot: string;
}
export type EslintFindingsImport =
  { status: 'parsed'; envelope: AdapterEnvelope } | { status: 'invalid' };

const positive = (value: unknown): number | undefined =>
  typeof value === 'number' &&
  Number.isSafeInteger(value) &&
  value >= 1 &&
  value <= envelopeLimits.maxLine
    ? value
    : undefined;

/**
 * Detailed ESLint import in the shared adapter envelope. The report is first
 * validated by {@link parseEslintJson}, so counts stay consistent. Provenance is
 * always `imported-unverified`. Findings that cannot be represented safely
 * (path outside the root, unreadable location) are dropped and the envelope is
 * `incomplete` with a reason rather than silently `completed`. Suppressed
 * messages, source text and fixes are discarded; messages are redacted.
 */
export function parseEslintFindings(
  raw: unknown,
  context: EslintEnvelopeContext,
): EslintFindingsImport {
  const invalid: EslintFindingsImport = { status: 'invalid' };
  if (
    !isValidScope(context) ||
    !isEnvelopeVersion(context.engineVersion) ||
    !isEnvelopeVersion(context.rulesetVersion) ||
    !isEnvelopeVersion(context.configVersion) ||
    typeof context.pathRoot !== 'string' ||
    !isAbsolute(context.pathRoot) ||
    parseEslintJson(raw).status !== 'parsed'
  )
    return invalid;
  const files = JSON.parse(raw as string) as Record<string, unknown>[];
  const candidates: Omit<AdapterFinding, 'fingerprint'>[] = [];
  let dropped: EnvelopeReason | undefined;
  for (const file of files) {
    const filePath = Object.hasOwn(file, 'filePath')
      ? file.filePath
      : undefined;
    const rel =
      typeof filePath === 'string' && isAbsolute(filePath)
        ? relative(context.pathRoot, filePath).split(sep).join('/')
        : undefined;
    const messages = file.messages as Record<string, unknown>[];
    if (rel === undefined || rel.startsWith('..') || !isSafeRelativePath(rel)) {
      if (messages.length > 0) dropped ??= 'path-outside-root';
      continue;
    }
    for (const message of messages) {
      const startLine = positive(message.line);
      const startColumn = positive(message.column);
      const endLine = positive(message.endLine) ?? startLine;
      const endColumn = positive(message.endColumn) ?? startColumn;
      const ruleId =
        typeof message.ruleId === 'string' &&
        /^[A-Za-z0-9@/._:()-]{1,200}$/.test(message.ruleId)
          ? message.ruleId
          : message.ruleId === null || message.ruleId === undefined
            ? '(no-rule)'
            : undefined;
      if (
        startLine === undefined ||
        startColumn === undefined ||
        endLine === undefined ||
        endColumn === undefined ||
        ruleId === undefined ||
        endLine < startLine ||
        (endLine === startLine && endColumn < startColumn)
      ) {
        dropped ??= 'invalid-output';
        continue;
      }
      candidates.push({
        ruleId,
        nativeSeverity:
          message.fatal === true
            ? 'fatal'
            : message.severity === 2
              ? 'error'
              : 'warn',
        path: rel,
        range: { startLine, startColumn, endLine, endColumn },
        message: redactMessage(message.message),
      });
    }
  }
  candidates.sort(
    (a, b) =>
      a.path.localeCompare(b.path, 'en') ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId, 'en') ||
      a.message.localeCompare(b.message, 'en'),
  );
  if (candidates.length > envelopeLimits.findings) {
    candidates.length = envelopeLimits.findings;
    dropped ??= 'finding-limit';
  }
  const seen = new Map<string, number>();
  const findings = candidates.map((candidate): AdapterFinding => {
    const key = findingFingerprint('eslint', candidate);
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    return {
      ...candidate,
      fingerprint:
        occurrence === 0
          ? key
          : findingFingerprint('eslint', candidate, occurrence),
    };
  });
  const envelope: AdapterEnvelope = {
    schemaVersion: 1,
    provenance: 'imported-unverified',
    tenantId: context.tenantId,
    projectId: context.projectId,
    repository: context.repository,
    commitSha: context.commitSha,
    sourceId: context.sourceId,
    jobId: context.jobId,
    attemptId: context.attemptId,
    engine: { id: 'eslint', version: context.engineVersion },
    rulesetVersion: context.rulesetVersion,
    configVersion: context.configVersion,
    status: dropped ? 'incomplete' : 'completed',
    findings,
  };
  if (dropped) envelope.reason = dropped;
  const checked = validateEnvelope(envelope, context);
  return checked.ok
    ? { status: 'parsed', envelope: checked.envelope }
    : invalid;
}
