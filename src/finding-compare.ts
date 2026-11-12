import { createHash } from 'node:crypto';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type FindingRange,
  validateEnvelope,
} from './adapter-envelope.js';

const snippetChars = 200;

/** Source text of a range with whitespace collapsed, bounded and never stored. */
export function normalisedSnippet(source: string, range: FindingRange): string {
  const lines = source.split(/\r\n|\r|\n/);
  const start = range.startLine - 1;
  const end = range.endLine - 1;
  let text = '';
  if (start >= 0 && end < lines.length) {
    if (start === end)
      text = lines[start].slice(range.startColumn - 1, range.endColumn - 1);
    else
      text = [
        lines[start].slice(range.startColumn - 1),
        ...lines.slice(start + 1, end),
        lines[end].slice(0, range.endColumn - 1),
      ].join('\n');
  }
  text = text.replace(/\s+/g, ' ').trim();
  // Zero-width or unreadable ranges fall back to the whole starting line.
  if (text === '') text = (lines[start] ?? '').replace(/\s+/g, ' ').trim();
  return text.slice(0, snippetChars);
}

/**
 * Fingerprint from engine, rule, path and the normalised snippet hash, so it
 * survives unrelated line shifts. Line numbers and messages are excluded.
 * `occurrence` separates identical snippets in one file (in source order).
 */
export function stableFingerprint(
  engineId: string,
  ruleId: string,
  path: string,
  snippet: string,
  occurrence = 0,
): string {
  const snippetHash = createHash('sha256').update(snippet).digest('hex');
  const hash = createHash('sha256')
    .update(
      JSON.stringify([
        'stable-v1',
        engineId,
        ruleId,
        path,
        snippetHash,
        occurrence,
      ]),
    )
    .digest('hex');
  return `sha256:${hash}`;
}

export type Comparison =
  | {
      status: 'not-comparable';
      reason:
        | 'invalid-envelope'
        | 'scope-mismatch'
        | 'version-mismatch'
        | 'provenance';
      new: [];
      existing: [];
      resolved: [];
      unclassified: [];
    }
  | {
      status: 'compared';
      /** New and unclassified need a completed baseline. */
      baselineComplete: boolean;
      /** Resolved needs a completed current run; otherwise it is empty. */
      currentComplete: boolean;
      new: AdapterFinding[];
      existing: AdapterFinding[];
      resolved: AdapterFinding[];
      /** Current findings that cannot be called new: baseline was incomplete. */
      unclassified: AdapterFinding[];
    };

const notComparable = (
  reason: Extract<Comparison, { status: 'not-comparable' }>['reason'],
): Comparison => ({
  status: 'not-comparable',
  reason,
  new: [],
  existing: [],
  resolved: [],
  unclassified: [],
});

/**
 * Pure comparison of two adapter-executed runs of the same project, engine,
 * ruleset and configuration. A finding is resolved only when the current run
 * `completed`; failed, skipped or incomplete runs never resolve anything, and
 * an incomplete baseline never makes a finding "new".
 */
export function compareFindings(
  baseline: AdapterEnvelope,
  current: AdapterEnvelope,
): Comparison {
  const a = validateEnvelope(baseline);
  const b = validateEnvelope(current);
  if (!a.ok || !b.ok) return notComparable('invalid-envelope');
  const [base, cur] = [a.envelope, b.envelope];
  if (
    base.provenance !== 'adapter-executed' ||
    cur.provenance !== 'adapter-executed'
  )
    return notComparable('provenance');
  if (
    base.tenantId !== cur.tenantId ||
    base.projectId !== cur.projectId ||
    base.repository !== cur.repository ||
    base.sourceId !== cur.sourceId
  )
    return notComparable('scope-mismatch');
  if (
    base.engine.id !== cur.engine.id ||
    base.engine.version !== cur.engine.version ||
    base.rulesetVersion !== cur.rulesetVersion ||
    base.configVersion !== cur.configVersion
  )
    return notComparable('version-mismatch');
  const baselineComplete = base.status === 'completed';
  const currentComplete = cur.status === 'completed';
  const known = new Set(base.findings.map((f) => f.fingerprint));
  const present = new Set(cur.findings.map((f) => f.fingerprint));
  const result: Extract<Comparison, { status: 'compared' }> = {
    status: 'compared',
    baselineComplete,
    currentComplete,
    new: [],
    existing: [],
    resolved: [],
    unclassified: [],
  };
  for (const f of cur.findings) {
    if (known.has(f.fingerprint)) result.existing.push(f);
    else if (baselineComplete) result.new.push(f);
    else result.unclassified.push(f);
  }
  if (currentComplete)
    result.resolved = base.findings.filter((f) => !present.has(f.fingerprint));
  return result;
}
