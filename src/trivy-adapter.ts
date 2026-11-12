import { isAbsolute } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  findingFingerprint,
  hasControl,
  isSafeRelativePath,
  redactMessage,
  validateEnvelope,
} from './adapter-envelope.js';
import type { DependencyFinding } from './osv-adapter.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';

/** Pinned Trivy release; see docs/scanner-licensing.md (engine Apache-2.0). */
export const trivyAdapterEngine = Object.freeze({
  id: 'trivy',
  version: '0.76.2',
});

/** A Trivy package vulnerability in the shared dependency shape. */
export interface TrivyVulnerability extends DependencyFinding {
  artefactKind: 'image';
  severity: { label: string; source?: string };
}
export interface TrivyMisconfiguration {
  /** Scanned file path, repository-relative. */
  path: string;
  /** Resource inside the file (for example `aws_s3_bucket.logs`). */
  resource?: string;
  ruleId: string;
  severity: string;
  /** Redacted remediation text from the rule, when Trivy gave one. */
  remediation?: string;
  startLine: number;
  endLine: number;
  fingerprint: string;
}
export interface TrivyParsed {
  vulnerabilities: TrivyVulnerability[];
  misconfigurations: TrivyMisconfiguration[];
  envelope: AdapterFinding[];
}

export type TrivyTarget =
  /** Registry image pinned by digest: `registry/name@sha256:<64 hex>`. */
  | { kind: 'image-digest'; reference: string }
  /** Absolute path of a local image archive (`.tar`, `.tar.gz`, `.tgz`). */
  | { kind: 'image-tarball'; path: string }
  /** IaC files (repository-relative path to UTF-8 content). */
  | { kind: 'iac'; files: Readonly<Record<string, string>> };

export type TrivyOutcome =
  | 'scanned'
  | 'incomplete'
  | 'cancelled'
  | 'engine-failed'
  | 'unsupported-target'
  | 'no-supported-files'
  | 'registry-denied'
  | 'stale-database'
  | 'database-info-missing'
  | 'invalid-request';
export interface TrivyDisclosure {
  mode: 'online' | 'offline';
  transmitted: string;
  /** Image scans only: vulnerability database facts supplied by the caller. */
  database?: {
    version?: string;
    updatedAt?: string;
    maxAgeDays?: number;
  };
  /** IaC files that were not written to the workspace, with the reason. */
  droppedFiles: string[];
  outcome: TrivyOutcome;
  notice: string;
}
export interface TrivyScanResult {
  envelope: AdapterEnvelope;
  disclosure: TrivyDisclosure;
  vulnerabilities: TrivyVulnerability[];
  misconfigurations: TrivyMisconfiguration[];
}
export interface TrivyAdapterOptions {
  /** Trusted absolute path to the pinned trivy binary. */
  executable: string;
  /** Exact trimmed `--version` output of the reviewed binary. */
  versionOutput: string;
  /** Default `online`: customer-run with the online vulnerability DB. */
  mode?: 'online' | 'offline';
  /** Vulnerability DB version, reported by `trivy version`; disclosed only. */
  databaseVersion?: string;
  /** ISO-8601 `UpdatedAt` of the DB. Required for offline image scans. */
  databaseUpdatedAt?: string;
  /** Offline only: older databases are refused. Default 7. */
  maxDatabaseAgeDays?: number;
  /** False means the caller knows the registry cannot be reached. */
  registryAccess?: boolean;
  now?: Date;
}
export interface TrivyScanRequest {
  scope: EnvelopeScope;
  target: TrivyTarget;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const notice =
  'A clean result does not guarantee the absence of vulnerabilities or ' +
  'misconfigurations: only known advisories and rules in the consulted data ' +
  'and checks were applied.';
const dayMs = 86400000;
const digestRef = /^[a-z0-9][a-z0-9._/:-]{0,180}@sha256:[a-f0-9]{64}$/;
const tarball = /\.(?:tar|tar\.gz|tgz)$/;
const iacFile =
  /(?:\.(?:tf|tfvars|tf\.json|ya?ml|json|toml)|(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[A-Za-z0-9_-]+)?)$/;
/** Files Trivy reads implicitly from its working directory: never workspace input. */
const trivyControlFiles = new Set([
  'trivy.yaml',
  'trivy.yml',
  '.trivyignore',
  '.trivyignore.yaml',
  '.trivyignore.yml',
  'trivy-secret.yaml',
]);
const baseName = (p: string): string => p.slice(p.lastIndexOf('/') + 1);

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 200): string => {
  if (typeof v !== 'string' || v.length === 0 || v.length > max)
    throw new TypeError('bad string');
  return v;
};
const optText = (v: unknown, max = 2000): string | undefined =>
  typeof v === 'string' && v.length > 0 ? v.slice(0, max) : undefined;
const ruleIdOk = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const labelOk = /^[A-Za-z0-9._-]{1,32}$/;
const sevLabel = (v: unknown): string =>
  typeof v === 'string' && labelOk.test(v) ? v : 'UNKNOWN';
const ecosystems: Record<string, string> = {
  npm: 'npm',
  yarn: 'npm',
  pnpm: 'npm',
  'node-pkg': 'npm',
  pip: 'PyPI',
  pipenv: 'PyPI',
  poetry: 'PyPI',
  'python-pkg': 'PyPI',
  gomod: 'Go',
  gobinary: 'Go',
  cargo: 'crates.io',
  'rust-binary': 'crates.io',
  bundler: 'RubyGems',
  gemspec: 'RubyGems',
  composer: 'Packagist',
  jar: 'Maven',
  pom: 'Maven',
  gradle: 'Maven',
  nuget: 'NuGet',
  'dotnet-core': 'NuGet',
};
/** Envelope paths must be safe relative paths; image layers get a stand-in. */
function safePath(target: string): string {
  const t = target.replaceAll('\\', '/').replace(/^\/+/, '');
  return isSafeRelativePath(t) ? t : 'image';
}

/**
 * Parse Trivy `--format json` (SchemaVersion 2). Returns `undefined` for
 * malformed output. Only `Vulnerabilities` and `Misconfigurations` are read:
 * secret findings, code snippets and licence data are never copied, and every
 * free-text field is redacted.
 */
export function parseTrivyReport(
  stdout: string,
  engineId: string = trivyAdapterEngine.id,
): TrivyParsed | undefined {
  try {
    const root: unknown = JSON.parse(stdout);
    if (!isRec(root) || root.SchemaVersion !== 2) return undefined;
    text(root.ArtifactName, 512);
    const results = root.Results ?? [];
    if (!Array.isArray(results)) return undefined;
    const vulnerabilities: TrivyVulnerability[] = [];
    const misconfigurations: TrivyMisconfiguration[] = [];
    const envelope: AdapterFinding[] = [];
    const seen = new Map<string, TrivyVulnerability>();
    for (const result of results) {
      if (!isRec(result)) return undefined;
      const target = text(result.Target, 512);
      const type = typeof result.Type === 'string' ? result.Type : 'unknown';
      const vulns = result.Vulnerabilities ?? [];
      const misconfs = result.Misconfigurations ?? [];
      if (!Array.isArray(vulns) || !Array.isArray(misconfs)) return undefined;
      const path = safePath(target);
      for (const v of vulns) {
        if (!isRec(v)) return undefined;
        const id = text(v.VulnerabilityID, 100);
        if (!ruleIdOk.test(id)) return undefined;
        const pkg = {
          name: text(v.PkgName),
          version: text(v.InstalledVersion),
          ecosystem: ecosystems[type.toLowerCase()] ?? type,
        };
        const key = JSON.stringify([path, pkg.name, pkg.version, id]);
        const fixedRaw = optText(v.FixedVersion, 500);
        const fixedVersions = (fixedRaw?.split(',') ?? [])
          .map((s) => s.trim())
          .filter((s) => s.length > 0 && s.length <= 100);
        const existing = seen.get(key);
        if (existing) {
          for (const f of fixedVersions)
            if (!existing.fixedVersions.includes(f))
              existing.fixedVersions.push(f);
          continue;
        }
        const severity = {
          label: sevLabel(v.Severity),
          ...(typeof v.SeveritySource === 'string' &&
          labelOk.test(v.SeveritySource)
            ? { source: v.SeveritySource }
            : {}),
        };
        const vendorIds = (
          Array.isArray(v.VendorIDs) ? v.VendorIDs : []
        ).filter((x): x is string => typeof x === 'string' && ruleIdOk.test(x));
        const summary = optText(v.Title, 300);
        const base = {
          ruleId: id,
          nativeSeverity: severity.label,
          path,
          range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
          message: redactMessage(
            `${pkg.name}@${pkg.version} (${pkg.ecosystem}) affected by ${id}; ` +
              `severity ${severity.label}` +
              (severity.source ? ` per ${severity.source}` : '') +
              (fixedVersions.length
                ? `; fixed in ${fixedVersions.join(', ')}`
                : '; no fix known'),
          ),
        };
        const fingerprint = findingFingerprint(engineId, base);
        const finding: TrivyVulnerability = {
          artefactPath: path,
          artefactKind: 'image',
          package: pkg,
          advisory: {
            id,
            aliases: vendorIds.filter((x) => x !== id),
            ...(summary ? { summary: redactMessage(summary) } : {}),
          },
          affectedRanges: [],
          fixedVersions,
          fingerprint,
          severity,
        };
        seen.set(key, finding);
        vulnerabilities.push(finding);
        envelope.push({ ...base, fingerprint });
      }
      for (const m of misconfs) {
        if (!isRec(m)) return undefined;
        // Passed checks and exceptions are not findings.
        if (m.Status !== undefined && m.Status !== 'FAIL') continue;
        if (!isSafeRelativePath(target)) return undefined;
        const ruleId = text(m.ID, 200);
        if (!ruleIdOk.test(ruleId)) return undefined;
        const cause = isRec(m.CauseMetadata) ? m.CauseMetadata : {};
        const line = (x: unknown, d: number): number =>
          typeof x === 'number' && Number.isSafeInteger(x) && x >= 1 ? x : d;
        const startLine = line(cause.StartLine, 1);
        const endLine = Math.max(startLine, line(cause.EndLine, startLine));
        const resource = optText(cause.Resource, 200);
        const severity = sevLabel(m.Severity);
        const resolution = optText(m.Resolution, 500);
        const remediation = resolution ? redactMessage(resolution) : undefined;
        const base = {
          ruleId,
          nativeSeverity: severity,
          path: target,
          range: { startLine, startColumn: 1, endLine, endColumn: 1 },
          message: redactMessage(
            `${optText(m.Message, 400) ?? optText(m.Title, 400) ?? ruleId}` +
              (resource ? ` [${resource}]` : '') +
              (resolution ? ` Remediation: ${resolution}` : ''),
          ),
        };
        const fingerprint = findingFingerprint(engineId, base);
        misconfigurations.push({
          path: target,
          ...(resource ? { resource: redactMessage(resource) } : {}),
          ruleId,
          severity,
          ...(remediation ? { remediation } : {}),
          startLine,
          endLine,
          fingerprint,
        });
        envelope.push({ ...base, fingerprint });
      }
    }
    return { vulnerabilities, misconfigurations, envelope };
  } catch {
    return undefined;
  }
}

const emptyDetails = (): Pick<
  TrivyScanResult,
  'vulnerabilities' | 'misconfigurations'
> => ({ vulnerabilities: [], misconfigurations: [] });

/**
 * Run the pinned Trivy on one explicit target. Image scans enable only the
 * `vuln` scanner and read the image from a registry digest (`--image-src
 * remote`, never the Docker/containerd/podman sockets) or a local archive
 * (`--input`). IaC scans use `trivy config` (misconfiguration only) on files
 * written to a private workspace. Images are never started, infrastructure is
 * never applied and customer scripts are never executed. The scrubbed
 * environment carries no registry or cloud credentials; private registries
 * therefore surface as an engine failure or, when the caller knows, as
 * `registryAccess: false` (`skipped`). Network use is NOT enforced here.
 */
export async function runTrivyScan(
  options: TrivyAdapterOptions,
  request: TrivyScanRequest,
): Promise<TrivyScanResult> {
  const mode = options.mode ?? 'online';
  const now = options.now ?? new Date();
  const maxAge = options.maxDatabaseAgeDays ?? 7;
  const target = request.target;
  const isImage = target.kind !== 'iac';
  const disclosure: TrivyDisclosure = {
    mode,
    transmitted: !isImage
      ? 'Nothing is sent for IaC checks; Terraform remote modules, if referenced, may be fetched by the engine'
      : mode === 'online'
        ? 'Image layer metadata may be requested from the registry and the vulnerability DB is downloaded from its public source'
        : 'Nothing beyond reading the target: the vulnerability DB is local',
    droppedFiles: [],
    outcome: 'scanned',
    notice,
  };
  let stamp: number | undefined;
  if (isImage) {
    disclosure.database = {};
    if (
      options.databaseVersion &&
      /^[0-9A-Za-z._-]{1,32}$/.test(options.databaseVersion)
    )
      disclosure.database.version = options.databaseVersion;
    if (options.databaseUpdatedAt)
      stamp = Date.parse(options.databaseUpdatedAt);
    if (stamp !== undefined && !Number.isNaN(stamp))
      disclosure.database.updatedAt = new Date(stamp).toISOString();
    if (mode === 'offline') disclosure.database.maxAgeDays = maxAge;
  }
  const datePart = disclosure.database?.updatedAt
    ?.slice(0, 10)
    .replaceAll('-', '');

  // Files written to the workspace (IaC only), minus anything Trivy would
  // read as configuration or that is not a supported IaC format.
  const files: Record<string, string> = {};
  if (target.kind === 'iac') {
    for (const [name, content] of Object.entries(target.files)) {
      if (!trivyControlFiles.has(baseName(name)) && iacFile.test(name))
        files[name] = content;
      else disclosure.droppedFiles.push(name);
    }
  }
  const common = [
    '--format',
    'json',
    '--quiet',
    '--no-progress',
    '--skip-version-check',
  ];
  const offline =
    mode === 'offline' ? ['--skip-db-update', '--offline-scan'] : [];
  let fixedArgs: string[];
  let args: string[];
  if (target.kind === 'image-digest') {
    fixedArgs = [
      'image',
      ...common,
      '--scanners',
      'vuln',
      ...offline,
      '--image-src',
      'remote',
    ];
    args = [target.reference];
  } else if (target.kind === 'image-tarball') {
    fixedArgs = [
      'image',
      ...common,
      '--scanners',
      'vuln',
      ...offline,
      '--input',
    ];
    args = [target.path];
  } else {
    fixedArgs = ['config', ...common];
    args = ['.'];
  }
  const pinned: ScannerAdapter = {
    engine: { ...trivyAdapterEngine },
    rulesetVersion: isImage
      ? datePart
        ? `trivy-db-${datePart}`
        : `trivy-db-${mode}`
      : 'trivy-checks-bundled',
    configVersion: `trivy-${isImage ? 'image' : 'config'}-${mode}-v1`,
    executable: options.executable,
    versionArgs: ['--version'],
    versionOutput: options.versionOutput,
    fixedArgs,
    allowedArgs: args,
    successExitCodes: [0],
    parse: () => undefined,
  };
  let details: TrivyParsed | undefined;
  pinned.parse = (stdout): ParsedOutput | undefined => {
    details = parseTrivyReport(stdout);
    return details ? { findings: details.envelope } : undefined;
  };
  const skip = async (
    outcome: TrivyOutcome,
    reason: EnvelopeReason = 'invalid-request',
  ): Promise<TrivyScanResult> => {
    // Zero files and a non-allowlisted argument: runAdapter yields `skipped`.
    const base = await runAdapter(pinned, {
      scope: request.scope,
      files: {},
      args: ['--not-allowed'],
    });
    const candidate = { ...base, reason };
    const checked = validateEnvelope(candidate, request.scope);
    return {
      envelope: checked.ok ? checked.envelope : base,
      disclosure: { ...disclosure, outcome },
      ...emptyDetails(),
    };
  };

  if (target.kind === 'image-digest' && !digestRef.test(target.reference))
    return skip('unsupported-target');
  if (
    target.kind === 'image-tarball' &&
    (!isAbsolute(target.path) ||
      hasControl(target.path) ||
      target.path.split('/').includes('..') ||
      !tarball.test(target.path))
  )
    return skip('unsupported-target');
  if (target.kind === 'iac' && Object.keys(files).length === 0)
    return skip('no-supported-files', 'no-supported-files');
  if (target.kind === 'image-digest' && options.registryAccess === false)
    return skip('registry-denied');
  if (isImage && mode === 'offline') {
    if (stamp === undefined || Number.isNaN(stamp))
      return skip('database-info-missing');
    if (stamp > now.getTime() || now.getTime() - stamp > maxAge * dayMs)
      return skip('stale-database');
  }

  const envelope = await runAdapter(pinned, {
    scope: request.scope,
    files,
    args,
    timeoutMs: request.timeoutMs,
    signal: request.signal,
  });
  const ok =
    envelope.status === 'completed' || envelope.status === 'incomplete';
  const outcome: TrivyOutcome =
    envelope.reason === 'cancelled'
      ? 'cancelled'
      : envelope.status === 'skipped'
        ? 'invalid-request'
        : envelope.status === 'incomplete'
          ? 'incomplete'
          : ok
            ? 'scanned'
            : 'engine-failed';
  // Keep details aligned with a possibly truncated envelope.
  const kept = new Set(envelope.findings.map((f) => f.fingerprint));
  const parsed = ok ? details : undefined;
  return {
    envelope,
    disclosure: { ...disclosure, outcome },
    vulnerabilities: (parsed?.vulnerabilities ?? []).filter((v) =>
      kept.has(v.fingerprint),
    ),
    misconfigurations: (parsed?.misconfigurations ?? []).filter((m) =>
      kept.has(m.fingerprint),
    ),
  };
}
