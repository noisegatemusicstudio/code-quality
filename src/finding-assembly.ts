import { realpathSync } from 'node:fs';
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

/**
 * Report path to repository-relative path: strips a `file://` scheme, the
 * workspace root (raw and realpath forms) and a leading `./`.
 */
export function relativeToRoot(path: string, sourceRoot?: string): string {
  const prefixes: string[] = [];
  if (sourceRoot) {
    prefixes.push(sourceRoot);
    try {
      prefixes.push(realpathSync(sourceRoot));
    } catch {
      /* the workspace is gone; the raw root still applies */
    }
  }
  let relative = path.startsWith('file://') ? path.slice(7) : path;
  for (const prefix of prefixes)
    if (relative.startsWith(`${prefix}/`))
      relative = relative.slice(prefix.length + 1);
  return relative.startsWith('./') ? relative.slice(2) : relative;
}
