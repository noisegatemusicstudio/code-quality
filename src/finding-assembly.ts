import {
  type AdapterFinding,
  type EnvelopeReason,
  envelopeLimits,
  findingFingerprint,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import { relativeSourcePath } from './source-paths.js';

type Candidate = Omit<AdapterFinding, 'fingerprint'>;

/**
 * Shared last step of every report parser: order candidates deterministically,
 * apply the envelope finding limit (marking the run incomplete) and assign
 * stable fingerprints, adding an occurrence index to exact repeats.
 */
export function assembleFindings<T extends Candidate>(
  engine: string,
  candidates: T[],
  partial?: EnvelopeReason,
): { findings: (T & { fingerprint: string })[]; partial?: EnvelopeReason } {
  const sorted = [...candidates].sort(
    (a, b) =>
      a.path.localeCompare(b.path, 'en') ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId, 'en'),
  );
  let reason = partial;
  if (sorted.length > envelopeLimits.findings) {
    sorted.length = envelopeLimits.findings;
    reason ??= 'finding-limit';
  }
  const seen = new Map<string, number>();
  const findings = sorted.map((c) => {
    const key = findingFingerprint(engine, c);
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    return {
      ...c,
      fingerprint: n === 0 ? key : findingFingerprint(engine, c, n),
    };
  });
  return reason ? { findings, partial: reason } : { findings };
}

const position = (v: unknown): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : undefined;
const ruleOk = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const levelOk = /^[A-Za-z0-9._-]{1,32}$/;

/** One raw, unvalidated report entry as a parser read it. */
export interface Draft {
  ruleId: unknown;
  severity: unknown;
  path: unknown;
  line: unknown;
  column: unknown;
  endLine?: unknown;
  endColumn?: unknown;
  message: unknown;
}

/** Validate one raw entry; `undefined` means unusable (the run becomes incomplete). */
function toCandidate(
  d: Draft,
  sourceRoot: string | undefined,
): Candidate | undefined {
  const path =
    typeof d.path === 'string'
      ? relativeSourcePath(
          d.path.startsWith('file://') ? d.path.slice(7) : d.path,
          sourceRoot,
        )
      : undefined;
  const startLine = position(d.line);
  const startColumn = position(d.column) ?? 1;
  const endLine = position(d.endLine) ?? startLine;
  const endColumn = position(d.endColumn) ?? startColumn;
  if (
    typeof d.ruleId !== 'string' ||
    !ruleOk.test(d.ruleId) ||
    typeof d.severity !== 'string' ||
    !levelOk.test(d.severity) ||
    !isSafeRelativePath(path) ||
    startLine === undefined ||
    endLine === undefined ||
    endLine < startLine
  )
    return undefined;
  return {
    ruleId: d.ruleId,
    nativeSeverity: d.severity,
    path,
    range: { startLine, startColumn, endLine, endColumn },
    message: redactMessage(d.message) || d.ruleId,
  };
}

/**
 * Validate raw entries and assemble them. An unusable entry, or `invalid`
 * (a malformed container the parser already skipped), marks the run
 * `incomplete` with `invalid-output`; it is never dropped silently.
 */
export function assembleDrafts(
  engine: string,
  drafts: readonly Draft[],
  sourceRoot: string | undefined,
  invalid: boolean,
): ReturnType<typeof assembleFindings> {
  let partial: EnvelopeReason | undefined = invalid
    ? 'invalid-output'
    : undefined;
  const candidates: Candidate[] = [];
  for (const draft of drafts) {
    const candidate = toCandidate(draft, sourceRoot);
    if (candidate) candidates.push(candidate);
    else partial ??= 'invalid-output';
  }
  return assembleFindings(engine, candidates, partial);
}
