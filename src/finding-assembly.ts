import {
  type AdapterFinding,
  type EnvelopeReason,
  envelopeLimits,
  findingFingerprint,
} from './adapter-envelope.js';

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
