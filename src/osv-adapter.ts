import { basename } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeScope,
  findingFingerprint,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';

/** Pinned OSV-Scanner release; see docs/scanner-licensing.md (Apache-2.0). */
export const osvAdapterEngine = Object.freeze({
  id: 'osv-scanner',
  version: '2.7.1',
});
export const osvLockfileNames: readonly string[] = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'poetry.lock',
  'Pipfile.lock',
  'Gemfile.lock',
  'Cargo.lock',
  'go.mod',
  'composer.lock',
  'pom.xml',
];
const sbomPattern = /\.(?:cdx|spdx)\.json$/;

export type OsvArtefactKind = 'lockfile' | 'sbom';
/** Kind of a supported artefact path, or `undefined` when unsupported. */
export function osvArtefactKind(path: string): OsvArtefactKind | undefined {
  if (!isSafeRelativePath(path) || path.startsWith('-')) return undefined;
  const name = basename(path);
  if (osvLockfileNames.includes(name)) return 'lockfile';
  return sbomPattern.test(name) ? 'sbom' : undefined;
}

export interface OsvAffectedRange {
  /** OSV range type, for example SEMVER, ECOSYSTEM or GIT. */
  type: string;
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}
/**
 * One vulnerable package at one artefact path. Aliases of the same advisory
 * are merged; different versions or paths are never merged. Fields are
 * explicit so other scanners (for example Trivy) can emit the same shape.
 */
export interface DependencyFinding {
  /** Repository-relative lockfile or SBOM path. */
  artefactPath: string;
  artefactKind: OsvArtefactKind;
  package: { name: string; version: string; ecosystem: string };
  advisory: {
    /** Primary identifier (GHSA preferred, then CVE, then the rest). */
    id: string;
    /** Every other identifier seen for this package/version/path. */
    aliases: string[];
    summary?: string;
  };
  affectedRanges: OsvAffectedRange[];
  /** Fix versions from the advisory; empty means no fix is known. */
  fixedVersions: string[];
  /** The envelope finding this record corresponds to (same fingerprint). */
  fingerprint: string;
}

export type OsvOutcome =
  | 'scanned'
  | 'engine-failed'
  | 'unsupported-artefact'
  | 'network-denied'
  | 'stale-database'
  | 'database-timestamp-missing'
  | 'invalid-request';
export interface OsvDisclosure {
  mode: 'online' | 'offline';
  /** What leaves the machine; offline sends nothing. */
  transmitted: string;
  /** Offline mode only: when the local database was produced. */
  databaseTimestamp?: string;
  maxDatabaseAgeDays?: number;
  supportedArtefacts: string;
  /** More specific than the envelope reason, which uses the shared enum. */
  outcome: OsvOutcome;
  notice: string;
}
export interface OsvScanResult {
  envelope: AdapterEnvelope;
  disclosure: OsvDisclosure;
  findings: DependencyFinding[];
}

export interface OsvAdapterOptions {
  /** Trusted absolute path to the pinned osv-scanner binary. */
  executable: string;
  /** Exact trimmed `--version` output of the reviewed binary. */
  versionOutput: string;
  /** Default `online`: the customer runs it with online OSV data. */
  mode?: 'online' | 'offline';
  /** Offline only (opt-in): ISO-8601 time the local database was built. */
  databaseTimestamp?: string;
  /** Offline only: older databases are refused. Default 7. */
  maxDatabaseAgeDays?: number;
  /** Online only: false means the caller knows the network is denied. */
  networkAvailable?: boolean;
  now?: Date;
}
export interface OsvScanRequest {
  scope: EnvelopeScope;
  /** Repository-relative lockfile or SBOM path. */
  artefactPath: string;
  artefactContent: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const notice =
  'A clean result does not guarantee the absence of unknown vulnerabilities: ' +
  'it only means no known advisory in the consulted data matched.';
const supported = `Lockfiles (${osvLockfileNames.join(', ')}) and CycloneDX/SPDX JSON SBOMs (*.cdx.json, *.spdx.json); ecosystems are those OSV-Scanner supports for the artefact`;
const dayMs = 86400000;

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string => {
  if (typeof v !== 'string' || v.length === 0 || v.length > 200)
    throw new TypeError('bad string');
  return v;
};
const safeId = /^[A-Za-z0-9._:-]{1,100}$/;
const idRank = (id: string): number =>
  id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 1 : 2;

interface RawVuln {
  ids: string[];
  summary?: string;
  severity: string;
  ranges: OsvAffectedRange[];
  fixed: string[];
}
function rangesFor(
  vuln: Rec,
  name: string,
  ecosystem: string,
): Pick<RawVuln, 'ranges' | 'fixed'> {
  const ranges: OsvAffectedRange[] = [];
  const fixed: string[] = [];
  for (const a of Array.isArray(vuln.affected) ? vuln.affected : []) {
    if (!isRec(a) || !isRec(a.package)) continue;
    if (a.package.name !== name || a.package.ecosystem !== ecosystem) continue;
    for (const r of Array.isArray(a.ranges) ? a.ranges : []) {
      if (!isRec(r) || !Array.isArray(r.events)) continue;
      let current: OsvAffectedRange | undefined;
      for (const e of r.events) {
        if (!isRec(e)) continue;
        if (typeof e.introduced === 'string') {
          current = { type: str(r.type), introduced: str(e.introduced) };
          ranges.push(current);
        } else if (typeof e.fixed === 'string') {
          const v = str(e.fixed);
          if (current && current.fixed === undefined) current.fixed = v;
          else ranges.push({ type: str(r.type), fixed: v });
          fixed.push(v);
        } else if (typeof e.last_affected === 'string') {
          const v = str(e.last_affected);
          if (current && current.lastAffected === undefined)
            current.lastAffected = v;
          else ranges.push({ type: str(r.type), lastAffected: v });
        }
      }
    }
  }
  return { ranges, fixed };
}

/**
 * Parse OSV-Scanner JSON (`results[].packages[].vulnerabilities[]`). Returns
 * `undefined` for malformed output; throws nothing. Findings are keyed by
 * artefact path + package name + version + ecosystem: vulnerabilities whose
 * ids/aliases overlap there are one advisory, anything else stays separate.
 */
export function parseOsvReport(
  stdout: string,
  artefactPath: string,
  engineId: string = osvAdapterEngine.id,
): { findings: DependencyFinding[]; envelope: AdapterFinding[] } | undefined {
  const kind = osvArtefactKind(artefactPath);
  if (!kind) return undefined;
  try {
    const root: unknown = JSON.parse(stdout);
    if (!isRec(root) || !Array.isArray(root.results)) return undefined;
    // key -> vulnerabilities for one package/version/ecosystem/path.
    const groups = new Map<
      string,
      { pkg: DependencyFinding['package']; vulns: RawVuln[] }
    >();
    for (const result of root.results) {
      if (
        !isRec(result) ||
        !isRec(result.source) ||
        !Array.isArray(result.packages)
      )
        return undefined;
      const source = str(result.source.path).replaceAll('\\', '/');
      // The scan targets exactly one artefact; any other path is not ours.
      if (source !== artefactPath && !source.endsWith(`/${artefactPath}`))
        return undefined;
      for (const entry of result.packages) {
        if (!isRec(entry) || !isRec(entry.package)) return undefined;
        const pkg = {
          name: str(entry.package.name),
          version: str(entry.package.version),
          ecosystem: str(entry.package.ecosystem),
        };
        const vulns = entry.vulnerabilities;
        if (vulns === undefined) continue;
        if (!Array.isArray(vulns)) return undefined;
        const key = JSON.stringify([
          artefactPath,
          pkg.name,
          pkg.version,
          pkg.ecosystem,
        ]);
        const group = groups.get(key) ?? { pkg, vulns: [] };
        groups.set(key, group);
        for (const v of vulns) {
          if (!isRec(v)) return undefined;
          const aliases = v.aliases === undefined ? [] : v.aliases;
          if (!Array.isArray(aliases)) return undefined;
          const ids = [str(v.id), ...aliases.map(str)];
          if (!ids.every((i) => safeId.test(i))) return undefined;
          const db = isRec(v.database_specific) ? v.database_specific : {};
          const sev =
            typeof db.severity === 'string' &&
            /^[A-Za-z0-9._-]{1,32}$/.test(db.severity)
              ? db.severity
              : 'UNKNOWN';
          group.vulns.push({
            ids,
            summary: typeof v.summary === 'string' ? v.summary : undefined,
            severity: sev,
            ...rangesFor(v, pkg.name, pkg.ecosystem),
          });
        }
      }
    }
    const findings: DependencyFinding[] = [];
    const envelope: AdapterFinding[] = [];
    for (const { pkg, vulns } of groups.values()) {
      // Union vulnerabilities that share any identifier.
      const clusters: RawVuln[][] = [];
      for (const v of vulns) {
        const hits = clusters.filter((c) =>
          c.some((o) => o.ids.some((i) => v.ids.includes(i))),
        );
        const merged = [v, ...hits.flat()];
        for (const h of hits) clusters.splice(clusters.indexOf(h), 1);
        clusters.push(merged);
      }
      for (const cluster of clusters) {
        const ids = [...new Set(cluster.flatMap((c) => c.ids))].sort(
          (a, b) => idRank(a) - idRank(b) || (a < b ? -1 : 1),
        );
        const id = ids[0] as string;
        const ranges: OsvAffectedRange[] = [];
        for (const r of cluster.flatMap((c) => c.ranges))
          if (!ranges.some((o) => JSON.stringify(o) === JSON.stringify(r)))
            ranges.push(r);
        const fixedVersions = [...new Set(cluster.flatMap((c) => c.fixed))];
        const summary = cluster.find((c) => c.summary)?.summary;
        const base = {
          ruleId: id,
          nativeSeverity: cluster[0]?.severity ?? 'UNKNOWN',
          path: artefactPath,
          range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
          message: redactMessage(
            `${pkg.name}@${pkg.version} (${pkg.ecosystem}) affected by ${id}` +
              (fixedVersions.length
                ? `; fixed in ${fixedVersions.join(', ')}`
                : '; no fix known'),
          ),
        };
        const fingerprint = findingFingerprint(engineId, base);
        envelope.push({ ...base, fingerprint });
        findings.push({
          artefactPath,
          artefactKind: kind,
          package: pkg,
          advisory: {
            id,
            aliases: ids.slice(1),
            ...(summary ? { summary: redactMessage(summary) } : {}),
          },
          affectedRanges: ranges,
          fixedVersions,
          fingerprint,
        });
      }
    }
    return { findings, envelope };
  } catch {
    return undefined;
  }
}

/**
 * Run the pinned OSV-Scanner on one lockfile or SBOM. Only `scan source` with
 * a single allowlisted artefact argument is ever executed: no installs, no
 * lifecycle scripts, no source resolution. Unsupported artefacts, a known
 * denied network, and missing or stale offline databases are returned as
 * `skipped` without running (reason `invalid-request`; the precise cause is
 * in `disclosure.outcome`). Network use is NOT enforced here.
 */
export async function runOsvScan(
  options: OsvAdapterOptions,
  request: OsvScanRequest,
): Promise<OsvScanResult> {
  const mode = options.mode ?? 'online';
  const now = options.now ?? new Date();
  const maxAge = options.maxDatabaseAgeDays ?? 7;
  const disclosure: OsvDisclosure = {
    mode,
    transmitted:
      mode === 'online'
        ? 'Package names, versions and ecosystems from the artefact are sent to the OSV API'
        : 'Nothing: advisories come from a local database',
    supportedArtefacts: supported,
    outcome: 'scanned',
    notice,
  };
  let stamp: number | undefined;
  if (mode === 'offline') {
    disclosure.maxDatabaseAgeDays = maxAge;
    stamp = options.databaseTimestamp
      ? Date.parse(options.databaseTimestamp)
      : Number.NaN;
    if (!Number.isNaN(stamp))
      disclosure.databaseTimestamp = new Date(stamp).toISOString();
  }
  const kind = osvArtefactKind(request.artefactPath);
  const datePart = disclosure.databaseTimestamp
    ?.slice(0, 10)
    .replaceAll('-', '');
  const pinned: ScannerAdapter = {
    engine: { ...osvAdapterEngine },
    rulesetVersion: datePart ? `osv-db-${datePart}` : `osv-${mode}`,
    configVersion: `osv-${mode}-v1`,
    executable: options.executable,
    versionArgs: ['--version'],
    versionOutput: options.versionOutput,
    fixedArgs: [
      'scan',
      'source',
      '--format',
      'json',
      ...(mode === 'offline' ? ['--offline'] : []),
    ],
    allowedArgs: kind
      ? [kind === 'sbom' ? '--sbom' : '-L', request.artefactPath]
      : [],
    // 0 = clean, 1 = vulnerabilities found; 127/128 are errors/no packages.
    successExitCodes: [0, 1],
    parse: () => undefined,
  };
  let details: DependencyFinding[] = [];
  pinned.parse = (stdout): ParsedOutput | undefined => {
    const parsed = parseOsvReport(stdout, request.artefactPath);
    if (!parsed) return undefined;
    details = parsed.findings;
    return { findings: parsed.envelope };
  };
  const skip = async (outcome: OsvOutcome): Promise<OsvScanResult> => {
    // Zero files and no args: runAdapter's own validation yields `skipped`.
    const envelope = await runAdapter(pinned, {
      scope: request.scope,
      files: {},
      args: ['--not-allowed'],
    });
    return { envelope, disclosure: { ...disclosure, outcome }, findings: [] };
  };
  if (!kind) return skip('unsupported-artefact');
  if (mode === 'online' && options.networkAvailable === false)
    return skip('network-denied');
  if (mode === 'offline') {
    if (stamp === undefined || Number.isNaN(stamp))
      return skip('database-timestamp-missing');
    if (stamp > now.getTime() || now.getTime() - stamp > maxAge * dayMs)
      return skip('stale-database');
  }
  const envelope = await runAdapter(pinned, {
    scope: request.scope,
    files: { [request.artefactPath]: request.artefactContent },
    args: [kind === 'sbom' ? '--sbom' : '-L', request.artefactPath],
    timeoutMs: request.timeoutMs,
    signal: request.signal,
  });
  const ok =
    envelope.status === 'completed' || envelope.status === 'incomplete';
  return {
    envelope,
    disclosure: {
      ...disclosure,
      outcome:
        envelope.status === 'skipped'
          ? 'invalid-request'
          : ok
            ? 'scanned'
            : 'engine-failed',
    },
    findings: ok ? details : [],
  };
}
