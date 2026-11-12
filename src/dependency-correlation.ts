import type { DependencyFinding } from './osv-adapter.js';

/** One finding as seen by one scanner. */
export interface CorrelatedOccurrence {
  source: string;
  fingerprint: string;
  artefactPath: string;
  advisoryId: string;
}
/** One real-world issue, however many scanners and paths reported it. */
export interface CorrelatedDependencyIssue {
  package: { name: string; version: string; ecosystem: string };
  /** Every identifier any source used for this issue. */
  advisoryIds: string[];
  /** Distinct sources that reported it, sorted. */
  sources: string[];
  /** Every original finding: nothing is dropped, only grouped. */
  occurrences: CorrelatedOccurrence[];
  fixedVersions: string[];
}
export interface DependencyCorrelation {
  issues: CorrelatedDependencyIssue[];
  /** Distinct issues: the number to count, not the sum of the sources. */
  total: number;
  /** Raw per-source counts before correlation. */
  bySource: Record<string, number>;
}

const byText = (a: string, b: string): number => a.localeCompare(b);

/** Ecosystem key: case-insensitive, without OSV's `:release` suffix. */
const ecosystemKey = (e: string): string =>
  (e.split(':')[0] ?? e).toLowerCase();

/**
 * Correlate dependency findings from several scanners (for example OSV and
 * Trivy). Findings are the same issue when package name, version and ecosystem
 * match and their advisory ids or aliases share at least one identifier
 * (transitively). Both sources stay visible in `occurrences`; `total` counts
 * each issue once. Ids that never overlap are never merged.
 */
export function correlateDependencyFindings(
  inputs: readonly { source: string; findings: readonly DependencyFinding[] }[],
): DependencyCorrelation {
  interface Item {
    source: string;
    finding: DependencyFinding;
    ids: string[];
  }
  const bySource: Record<string, number> = {};
  const groups = new Map<string, Item[]>();
  for (const { source, findings } of inputs) {
    bySource[source] = (bySource[source] ?? 0) + findings.length;
    for (const finding of findings) {
      const key = JSON.stringify([
        finding.package.name.toLowerCase(),
        finding.package.version,
        ecosystemKey(finding.package.ecosystem),
      ]);
      const item: Item = {
        source,
        finding,
        ids: [finding.advisory.id, ...finding.advisory.aliases],
      };
      groups.set(key, [...(groups.get(key) ?? []), item]);
    }
  }
  const issues: CorrelatedDependencyIssue[] = [];
  for (const items of groups.values()) {
    const clusters: Item[][] = [];
    for (const item of items) {
      const hits = clusters.filter((c) =>
        c.some((o) => o.ids.some((i) => item.ids.includes(i))),
      );
      for (const h of hits) clusters.splice(clusters.indexOf(h), 1);
      clusters.push([item, ...hits.flat()]);
    }
    for (const cluster of clusters) {
      // Every cluster is created with at least one item.
      const first = cluster[0].finding;
      issues.push({
        package: { ...first.package },
        advisoryIds: [...new Set(cluster.flatMap((c) => c.ids))].sort(byText),
        sources: [...new Set(cluster.map((c) => c.source))].sort(byText),
        occurrences: cluster
          .map((c) => ({
            source: c.source,
            fingerprint: c.finding.fingerprint,
            artefactPath: c.finding.artefactPath,
            advisoryId: c.finding.advisory.id,
          }))
          .sort((a, b) =>
            (a.source + a.fingerprint).localeCompare(b.source + b.fingerprint),
          ),
        fixedVersions: [
          ...new Set(cluster.flatMap((c) => c.finding.fixedVersions)),
        ].sort(byText),
      });
    }
  }
  issues.sort((a, b) =>
    JSON.stringify([a.package, a.advisoryIds]).localeCompare(
      JSON.stringify([b.package, b.advisoryIds]),
    ),
  );
  return { issues, total: issues.length, bySource };
}
