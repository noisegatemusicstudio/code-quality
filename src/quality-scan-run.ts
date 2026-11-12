import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { lookup } from './lookup.js';
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  rm,
  writeFile,
  mkdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import {
  type AdapterEnvelope,
  type EnvelopeScope,
  isValidScope,
  validateEnvelope,
} from './adapter-envelope.js';
import { scanCommittedSource, type ExecutionSlot } from './customer-scan.js';
import { runEslintScan } from './eslint-adapter.js';
import {
  type PrettierScanReport,
  approvedPrettierVersion as prettierVersion,
  isPrettierInput,
  runPrettierScan,
} from './prettier-adapter.js';
import {
  type EngineId,
  type EngineResult,
  type OsvMode,
  engineIds,
  detectApplicability,
} from './quality-scan.js';
import {
  type GitleaksException,
  classifyGitleaksEnvelope,
} from './gitleaks-adapter.js';
import {
  checkstyleVersion,
  isJavaFile,
  pmdVersion,
  pmdVersionOutput,
  runCheckstyleScan,
  runPmdScan,
} from './java-adapters.js';
import {
  createDetektAdapter,
  createKtlintAdapter,
  javaSkipReason,
  kotlinFile,
  runKotlinScan,
} from './kotlin-adapter.js';
import { ruffVersion, runRuffScan } from './ruff-adapter.js';
import {
  runSwiftlintScan,
  swiftFile,
  swiftConfigPath,
  swiftWorkspace,
  swiftlintUnrunnableReason,
  swiftlintVersion,
} from './swift-adapter.js';
import { installZipTree, treeMatches } from './tree-install.js';
import {
  type LintEngineId,
  lintAdapter,
  lintEngines,
  pinnedVersionOutput,
  planBatches,
} from './lint-engines.js';
import { osvLockfileNames, runOsvScan } from './osv-adapter.js';
import {
  hadolintAdapter,
  isDockerfile,
  isMarkdownFile,
  isTerraformFile,
  isYamlFile,
  markdownlintAdapter,
  markdownlintSupportFiles,
  tflintAdapter,
  yamllintAdapter,
} from './lint-adapters.js';
import { adapterLimits, runAdapter } from './scanner-adapter.js';
import {
  externalPins,
  hadolintPin,
  markdownlintPin,
  lintPins,
  osvPin,
  detektPin,
  ktlintPin,
  swiftlintPin,
  mypyPin,
  swiftlintAnalyzePin,
  pmdPin,
  releaseTrees,
  spotbugsPin,
  releaseAssets,
  tflintPin,
  trivyPin,
  yamllintPin,
} from './scanner-pins.js';
import {
  releaseReadyRulesVersion,
  runSemgrepScan,
  semgrepVersion,
} from './semgrep-adapter.js';
import {
  isIacCandidate,
  runTrivyScan,
  trivyAdapterEngine,
} from './trivy-adapter.js';

const exec = promisify(execFile);
const projectEslintConfig =
  /^(?:eslint\.config\.[cm]?[jt]s|\.eslintrc(?:\.[a-z]+)?|\.eslintignore)$/;
const baseName = (path: string): string =>
  path.slice(path.lastIndexOf('/') + 1);
const sha256 = (bytes: Uint8Array): string =>
  createHash('sha256').update(bytes).digest('hex');

export type Downloader = (url: string) => Promise<Uint8Array>;
const maxAssetBytes = 300 * 1024 * 1024;
export const defaultDownloader: Downloader = async (url) => {
  if (!url.startsWith('https://')) throw new Error('https only');
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok)
    throw new Error(`download failed: ${String(response.status)}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maxAssetBytes) throw new Error('asset too large');
  return bytes;
};

export type InstallableEngine =
  | 'gitleaks'
  | 'trivy'
  | 'osv'
  | 'jscpd'
  | 'ruff'
  | 'pmd'
  | 'checkstyle'
  | 'detekt'
  | 'ktlint'
  | 'swiftlint'
  | 'hadolint'
  | 'tflint'
  | LintEngineId;
/**
 * Engines whose download is large enough to matter: `quality-scan-cli install`
 * fetches them only when the repository has tracked files they scan, so a
 * repository without Swift pays nothing for SwiftLint.
 */
export const installOnDemand: Partial<
  Record<InstallableEngine, (path: string) => boolean>
> = { swiftlint: (path) => swiftFile.test(path) };
export const installableEngines: readonly InstallableEngine[] = [
  'gitleaks',
  'trivy',
  'osv',
  'jscpd',
  'ruff',
  'pmd',
  'checkstyle',
  'detekt',
  'ktlint',
  'swiftlint',
  'shellcheck',
  'shfmt',
  'actionlint',
  'zizmor',
  'hadolint',
  'tflint',
];

/**
 * Download one official release asset, verify its sha256 and (for archives)
 * the extracted executable's sha256 against the pin, then place it in
 * `directory`. Anything unexpected throws before a file becomes executable.
 */
export async function installEngine(
  id: InstallableEngine,
  directory: string,
  download: Downloader = defaultDownloader,
): Promise<string> {
  if (id === 'pmd') {
    const tree = releaseTrees.pmd;
    const archive = await download(tree.url);
    if (sha256(archive) !== tree.assetSha256)
      throw new Error('pmd: asset sha256 mismatch');
    return installZipTree({
      bytes: archive,
      member: tree.member,
      treeSha256: tree.treeSha256,
      target: join(directory, 'pmd'),
    });
  }
  const asset = releaseAssets[id];
  const bytes = await download(asset.url);
  if (sha256(bytes) !== asset.assetSha256)
    throw new Error(`${id}: asset sha256 mismatch`);
  const work = await mkdtemp(join(tmpdir(), 'quality-install-'));
  try {
    let binary: Uint8Array = bytes;
    if (asset.member !== null) {
      const zip = asset.url.endsWith('.zip');
      const archive = join(work, zip ? 'asset.zip' : 'asset.tgz');
      await writeFile(archive, bytes, { flag: 'wx' });
      if (zip) await exec('unzip', ['-q', archive, asset.member, '-d', work]);
      else await exec('tar', ['-xf', archive, '-C', work, asset.member]);
      const extracted = join(work, asset.member);
      const info = await lstat(extracted);
      if (!info.isFile() || info.size > maxAssetBytes)
        throw new Error(`${id}: unexpected archive member`);
      binary = new Uint8Array(await readFileNoFollow(extracted));
    }
    if (sha256(binary) !== asset.binarySha256)
      throw new Error(`${id}: binary sha256 mismatch`);
    await mkdir(directory, { recursive: true });
    const target = join(directory, id);
    await writeFile(target, binary, { mode: 0o700 });
    await chmod(target, 0o700);
    return target;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

async function readFileNoFollow(path: string): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

/** True only when the file at `path` hashes to `expected`. */
export async function executableMatches(
  path: string,
  expected: string,
): Promise<boolean> {
  try {
    return sha256(await readFileNoFollow(resolve(path))) === expected;
  } catch {
    return false;
  }
}

/** Committed (tracked) paths of a checkout, sorted for deterministic bounding. */
export async function trackedPaths(repo: string): Promise<string[]> {
  const { stdout } = await exec('git', ['-C', repo, 'ls-files', '-z'], {
    maxBuffer: 64 * 1024 * 1024,
    encoding: 'buffer',
  });
  return stdout
    .toString('utf8')
    .split('\0')
    .filter((p) => p !== '')
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export interface BoundedFiles {
  files: Record<string, string>;
  /** Matching files that could not be passed to the engine, with no content kept. */
  omitted: number;
  /** Why files were omitted, by cause (counts only; no paths or content). */
  causes: Partial<Record<OmissionCause, number>>;
}
export type OmissionCause =
  | 'file-count-limit'
  | 'file-too-large'
  | 'total-size-limit'
  | 'not-regular-file'
  | 'not-utf8'
  | 'unreadable';
/**
 * Read matching tracked files within the adapter's input limits. Symlinks,
 * non-UTF-8 files and anything over a limit are counted in `omitted`, so the
 * caller can mark the engine incomplete instead of reporting a false clean.
 */
export async function readBoundedFiles(
  repo: string,
  paths: readonly string[],
  match: (path: string) => boolean,
): Promise<BoundedFiles> {
  const files: Record<string, string> = {};
  const causes: BoundedFiles['causes'] = {};
  let omitted = 0;
  let total = 0;
  const omit = (cause: OmissionCause): void => {
    omitted += 1;
    causes[cause] = (causes[cause] ?? 0) + 1;
  };
  let kept = 0;
  for (const path of paths.filter(match)) {
    if (kept >= adapterLimits.files) {
      omit('file-count-limit');
      continue;
    }
    try {
      const full = join(repo, path);
      const info = await lstat(full);
      if (!info.isFile()) {
        omit('not-regular-file');
        continue;
      }
      if (info.size > adapterLimits.fileBytes) {
        omit('file-too-large');
        continue;
      }
      if (total + info.size > adapterLimits.totalBytes) {
        omit('total-size-limit');
        continue;
      }
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(
          await readFileNoFollow(full),
        );
      } catch (error) {
        omit(error instanceof TypeError ? 'not-utf8' : 'unreadable');
        continue;
      }
      total += info.size;
      files[path] = text;
      kept += 1;
    } catch {
      omit('unreadable');
    }
  }
  return { files, omitted, causes };
}

const idSafe = (value: string, fallback: string): string => {
  const cleaned = value.replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 128);
  return /^[A-Za-z0-9]/.test(cleaned) ? cleaned : fallback;
};
/** Envelope scope from the GitHub Actions environment, with safe fallbacks. */
export function scopeFromEnvironment(
  environment: Record<string, string | undefined>,
  commitSha: string,
): EnvelopeScope {
  const repository = environment.GITHUB_REPOSITORY ?? '';
  const scope: EnvelopeScope = {
    tenantId: 'github-actions',
    projectId: idSafe(repository.split('/')[1] ?? '', 'project'),
    repository: /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(
      repository,
    )
      ? repository
      : 'local/repository',
    commitSha,
    sourceId: 'github-actions',
    jobId: idSafe(environment.GITHUB_RUN_ID ?? '', 'local'),
    attemptId: idSafe(environment.GITHUB_RUN_ATTEMPT ?? '', '1'),
  };
  if (!isValidScope(scope)) throw new Error('invalid envelope scope');
  return scope;
}

const skipped = (
  engine: EngineId,
  skipKind: NonNullable<EngineResult['skipKind']>,
  reason: string,
): EngineResult => ({
  engine,
  status: 'skipped',
  skipKind,
  reason,
  findings: [],
});
const failed = (engine: EngineId, reason: string): EngineResult => ({
  engine,
  status: 'failed',
  reason,
  findings: [],
});

/**
 * The adapter wants the exact trimmed `--version` output. Trivy appends its
 * embedded check-bundle digest after the version line, so read it once under
 * the same scrubbed environment and insist the first line is the pinned
 * version (the binary itself is already sha256-pinned).
 */
export async function trivyVersionOutput(executable: string): Promise<string> {
  const { stdout } = await exec(executable, ['--version'], {
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
    timeout: 10000,
  });
  const output = stdout.trim();
  if (output.split('\n')[0] !== `Version: ${trivyAdapterEngine.version}`)
    throw new Error('unexpected trivy version');
  return output;
}

/**
 * Read `--version` once under the scrubbed environment and insist it names the
 * pinned version (the binary or wheel is already hash-pinned).
 */
export async function lintVersionOutput(
  executable: string,
  expectedVersion: string,
): Promise<string> {
  const { stdout } = await exec(executable, ['--version'], {
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
    timeout: 10000,
  });
  const output = stdout.trim();
  if (!output.includes(expectedVersion))
    throw new Error('unexpected engine version');
  return output;
}

/** Name the files ESLint could not parse so an incomplete result is actionable. */
export function withParseFailures(
  result: EngineResult,
  report: { parseFailures: readonly string[]; truncated: boolean },
): EngineResult {
  if (report.parseFailures.length === 0 || result.status === 'failed')
    return result;
  const shown = report.parseFailures.slice(0, 20).join(', ');
  const more =
    report.parseFailures.length > 20 || report.truncated ? ', and more' : '';
  return {
    ...result,
    reason: `parse-failure: ${String(report.parseFailures.length)} file(s) the bundled parser cannot parse and were not linted: ${shown}${more}`,
  };
}

/**
 * Say why a Prettier run is not a plain pass: files it could not parse, and
 * config it would not honour (JS/TS config, plugins, custom parsers), which
 * means the repository's own settings were replaced by Prettier defaults.
 */
export function withPrettierNotes(
  result: EngineResult,
  report: PrettierScanReport,
): EngineResult {
  if (result.status === 'failed') return result;
  const parts: string[] = [];
  if (report.parseFailures.length > 0)
    parts.push(
      `parse-failure: ${String(report.parseFailures.length)} file(s) Prettier cannot parse and were not checked: ${report.parseFailures.slice(0, 20).join(', ')}${report.parseFailures.length > 20 || report.truncated ? ', and more' : ''}`,
    );
  if (report.configRejected.length > 0)
    parts.push(
      `customer-config-rejected: Prettier config that needs repository code was not loaded (${report.configRejected.slice(0, 20).join(', ')}); Prettier defaults were used for the affected files, so formatting findings may differ from the project's own settings`,
    );
  return parts.length > 0 ? { ...result, reason: parts.join('; ') } : result;
}

/** Map a bounded-input shortfall onto an engine result, never to a clean one. */
export function applyOmitted(
  result: EngineResult,
  omitted: number,
  causes: BoundedFiles['causes'] = {},
): EngineResult {
  if (omitted === 0 || result.status !== 'completed') return result;
  const detail = Object.entries(causes)
    .map(([cause, count]) => `${cause}: ${String(count)}`)
    .join(', ');
  return {
    ...result,
    status: 'incomplete',
    reason: `${String(omitted)} file(s) exceeded adapter input limits, were unreadable or not UTF-8 and were not scanned${detail ? ` (${detail})` : ''}`,
  };
}

const fromEnvelope = (
  engine: EngineId,
  envelope: AdapterEnvelope,
  version: string,
): EngineResult => ({
  engine,
  status: envelope.status,
  reason: envelope.reason,
  version,
  findings: envelope.findings,
  envelope,
  ...(envelope.status === 'skipped'
    ? { skipKind: 'unavailable' as const }
    : {}),
});

/** Map a customer-scan slot (gitleaks/jscpd) onto an engine result. */
export function fromSlot(
  engine: 'gitleaks' | 'jscpd',
  slot: ExecutionSlot,
  sourceError: string | undefined,
  scope: EnvelopeScope,
): EngineResult {
  const version = externalPins[engine].version;
  if (sourceError)
    return {
      ...failed(engine, `committed snapshot unavailable: ${sourceError}`),
      version,
    };
  const status =
    slot.state === 'completed' && slot.evidence === 'executed'
      ? 'completed'
      : slot.state === 'limited'
        ? 'incomplete'
        : 'failed';
  const findings = status === 'completed' ? (slot.findings ?? []) : [];
  const result: EngineResult = {
    engine,
    status,
    version,
    findings,
    ...(status === 'completed'
      ? {}
      : { reason: slot.reason ?? `engine state ${slot.state}` }),
  };
  if (status === 'completed') {
    const checked = validateEnvelope(
      {
        schemaVersion: 1,
        provenance: 'adapter-executed',
        ...scope,
        engine: { id: engine, version },
        rulesetVersion: slot.coverage,
        configVersion: slot.config ?? 'bundled-v1',
        status: 'completed',
        findings,
      },
      scope,
    );
    result.envelope = checked.ok ? checked.envelope : null;
  }
  return result;
}

export interface RunOptions {
  repo: string;
  scope: EnvelopeScope;
  selected: readonly EngineId[];
  /** Absolute path of each installed engine binary, if installation worked. */
  tools: Partial<
    Record<
      InstallableEngine | 'semgrep' | 'yamllint' | 'markdownlint' | 'java',
      string
    >
  >;
  /** Install failure reasons, so a missing engine is reported as failed. */
  installErrors: Partial<Record<EngineId, string>>;
  gitExecutable: string;
  rulesDirectory: string;
  /** `online` (default) sends package metadata to the OSV API; see the summary. */
  osvMode?: OsvMode;
}

/** `--version` of a verified jar under the scrubbed environment; it must name the pinned version. */
export async function jarVersionOutput(
  java: string,
  jar: string,
  expectedVersion: string,
): Promise<string> {
  const { stdout } = await exec(java, ['-jar', jar, '--version'], {
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
    timeout: 20000,
  });
  const output = stdout.trim();
  if (!output.includes(expectedVersion))
    throw new Error('unexpected engine version');
  return output;
}

const maxLockfiles = 20;
const envelopeStatusRank = {
  completed: 0,
  skipped: 1,
  incomplete: 2,
  failed: 3,
};
/** Combine per-lockfile OSV envelopes: the worst status wins, findings concatenate. */
export function mergeEnvelopes(
  envelopes: readonly AdapterEnvelope[],
): AdapterEnvelope {
  const first = envelopes.at(0);
  const rest = envelopes.slice(1);
  if (!first) throw new Error('no envelopes to merge');
  if (!rest.length) return first;
  const worst = envelopes.reduce((a, b) =>
    envelopeStatusRank[b.status] > envelopeStatusRank[a.status] ? b : a,
  );
  const mixed = envelopes.some((e) => e.status !== worst.status);
  // A skipped lockfile next to a scanned one means partial coverage.
  const status =
    worst.status === 'skipped' && mixed ? 'incomplete' : worst.status;
  const merged: AdapterEnvelope = {
    ...first,
    status,
    findings: envelopes.flatMap((e) => e.findings),
  };
  delete merged.reason;
  if (status !== 'completed')
    merged.reason = worst.reason ?? 'incomplete-history';
  return merged;
}

/**
 * Apply reviewed gitleaks exceptions to a result. Only findings matching an
 * exception's exact fingerprint, rule and path, unexpired and within the 90-day
 * cap, are removed from `findings`; the envelope keeps every finding.
 */
export function applyGitleaksExceptions(
  result: EngineResult,
  exceptions: readonly GitleaksException[],
  now: Date,
): EngineResult {
  if (result.engine !== 'gitleaks' || !result.envelope || !exceptions.length)
    return result;
  const classified = classifyGitleaksEnvelope(result.envelope, {
    exceptions,
    now,
  });
  if (!classified.counts.excepted) return result;
  return {
    ...result,
    findings: classified.active,
    excepted: classified.counts.excepted,
  };
}

/** Parse `{ "gitleaks": [...] }`; throws on anything else rather than guessing. */
export function parseExceptions(text: string): GitleaksException[] {
  const parsed: unknown = JSON.parse(text);
  const list =
    typeof parsed === 'object' && parsed !== null
      ? (parsed as { gitleaks?: unknown }).gitleaks
      : undefined;
  if (!Array.isArray(list))
    throw new Error('exceptions file needs a gitleaks array');
  return list as GitleaksException[];
}

export interface ExceptionLoad {
  /** Exceptions that may suppress findings in this run. */
  exceptions: GitleaksException[];
  /** Where they came from; pull requests never use their own file. */
  source: 'base-commit' | 'scanned-commit';
  baseSha?: string;
  /** Added or changed by the scanned commit but not yet in force (PR only). */
  pending: GitleaksException[];
  /** Set when the PR's own exceptions file could not be read for the pending list. */
  pendingError?: string;
}
export class ExceptionSourceError extends Error {}

const sorted = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(sorted)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.entries(value as Record<string, unknown>)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
            .map(([k, v]) => [k, sorted(v)]),
        )
      : value;
const canonical = (e: GitleaksException): string => JSON.stringify(sorted(e));

/**
 * Choose and read the reviewed exceptions. A `quality-exceptions.json` read
 * from the scanned commit would let a pull request exempt its own findings, so
 * for pull_request events only the BASE commit counts: a new exception takes
 * effect after it is merged. Entries the PR adds or changes are returned as
 * `pending`. Any other event reads the scanned (pushed) commit. A pull request
 * whose base commit cannot be determined or read fails closed (throws).
 * `readHead` reads the scanned commit's file; `readBase(sha)` reads the file at
 * a commit. Both return `undefined` when the file does not exist.
 */
export async function loadExceptions(input: {
  environment: Readonly<Record<string, string | undefined>>;
  readHead: () => Promise<string | undefined>;
  readBase: (baseSha: string) => Promise<string | undefined>;
  readEvent: (path: string) => Promise<string>;
}): Promise<ExceptionLoad> {
  const { environment: env } = input;
  const parse = (text: string | undefined) =>
    text === undefined ? [] : parseExceptions(text);
  const eventName = env.GITHUB_EVENT_NAME ?? '';
  if (eventName !== 'pull_request' && eventName !== 'pull_request_target')
    return {
      exceptions: parse(await input.readHead()),
      source: 'scanned-commit',
      pending: [],
    };
  let baseSha: unknown;
  try {
    const event: unknown = JSON.parse(
      await input.readEvent(env.GITHUB_EVENT_PATH ?? ''),
    );
    const pr = (event as { pull_request?: { base?: { sha?: unknown } } })
      .pull_request;
    baseSha = pr?.base?.sha;
  } catch {
    baseSha = undefined;
  }
  if (typeof baseSha !== 'string' || !/^[0-9a-f]{40}$/.test(baseSha))
    throw new ExceptionSourceError(
      'pull request base commit could not be determined',
    );
  let exceptions: GitleaksException[];
  try {
    exceptions = parse(await input.readBase(baseSha));
  } catch {
    throw new ExceptionSourceError(
      'exceptions file at the pull request base commit could not be read',
    );
  }
  const inForce = new Set(exceptions.map(canonical));
  let pending: GitleaksException[] = [];
  let pendingError: string | undefined;
  try {
    pending = parse(await input.readHead()).filter(
      (e) => !inForce.has(canonical(e)),
    );
  } catch {
    pendingError = 'exceptions file in this pull request is malformed';
  }
  return {
    exceptions,
    source: 'base-commit',
    baseSha,
    pending,
    ...(pendingError ? { pendingError } : {}),
  };
}

/**
 * Run one file-list lint engine (ShellCheck, shfmt, actionlint, zizmor) in
 * batches the adapter's argument limit allows. Files that cannot be passed
 * (unreadable, over limits, unusable name) make the result incomplete.
 */
async function runLintEngine(
  id: LintEngineId,
  options: RunOptions,
  paths: readonly string[],
): Promise<EngineResult> {
  const spec = lintEngines[id];
  const executable = options.tools[id];
  if (
    !executable ||
    !(await executableMatches(executable, lintPins[id].sha256))
  )
    return failed(
      id,
      options.installErrors[id] ?? `${id} missing or sha256 mismatch`,
    );
  const { files, omitted, causes } = await readBoundedFiles(
    options.repo,
    paths,
    spec.matches,
  );
  const { batches, unusable } = planBatches(Object.keys(files));
  const versionOutput = await pinnedVersionOutput(
    executable,
    spec.versionArgs,
    lintPins[id].version,
  );
  const envelopes: AdapterEnvelope[] = [];
  for (const batch of batches)
    envelopes.push(
      await runAdapter(lintAdapter(spec, executable, versionOutput, batch), {
        scope: options.scope,
        files: Object.fromEntries(batch.map((p) => [p, files[p] ?? ''])),
        args: batch,
      }),
    );
  if (!envelopes.length && !unusable.length && !omitted)
    return failed(id, 'no files to scan');
  const base = envelopes.length
    ? fromEnvelope(id, mergeEnvelopes(envelopes), lintPins[id].version)
    : failed(id, 'no file could be passed to the engine');
  return applyOmitted(base, omitted + unusable.length, causes);
}

/** Run every selected engine against the checked-out commit. Never throws. */
export async function runEngines(options: RunOptions): Promise<EngineResult[]> {
  const paths = await trackedPaths(options.repo);
  const applicability = detectApplicability(paths);
  const out = new Map<EngineId, EngineResult>();
  const todo = (engine: EngineId): boolean => {
    if (!options.selected.includes(engine)) {
      out.set(engine, skipped(engine, 'not-selected', 'not in scanners list'));
      return false;
    }
    const a = applicability[engine];
    if (!a.applicable) {
      out.set(engine, skipped(engine, 'not-applicable', a.reason ?? 'n/a'));
      return false;
    }
    return true;
  };
  const guard = async (
    engine: EngineId,
    run: () => Promise<EngineResult>,
  ): Promise<void> => {
    if (!todo(engine)) return;
    try {
      out.set(engine, await run());
    } catch {
      out.set(engine, failed(engine, 'engine runner threw unexpectedly'));
    }
  };

  await guard('eslint', async () => {
    // The adapter refuses project ESLint configs; leave them out so the bundled
    // ReleaseReady rules run instead (the project's own rules are not applied).
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      (p) =>
        /\.(?:[cm]?[jt]s|[jt]sx)$/.test(p) &&
        !projectEslintConfig.test(baseName(p)),
    );
    const { envelope, report } = await runEslintScan({
      scope: options.scope,
      files,
    });
    return applyOmitted(
      withParseFailures(fromEnvelope('eslint', envelope, 'bundled'), report),
      omitted,
      causes,
    );
  });

  await guard('prettier', async () => {
    // Only tracked files are read. Config candidates travel as plain text and
    // are never executed; the runner decides which ones it may honour.
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      isPrettierInput,
    );
    let scanned: Awaited<ReturnType<typeof runPrettierScan>>;
    try {
      scanned = await runPrettierScan({ scope: options.scope, files });
    } catch {
      return failed(
        'prettier',
        'installed Prettier is not the approved version',
      );
    }
    return applyOmitted(
      withPrettierNotes(
        fromEnvelope('prettier', scanned.envelope, prettierVersion),
        scanned.report,
      ),
      omitted,
      causes,
    );
  });

  await guard('semgrep', async () => {
    const executable = options.tools.semgrep;
    if (!executable)
      return failed(
        'semgrep',
        options.installErrors.semgrep ?? 'semgrep is not installed',
      );
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      (p) => /\.(?:[cm]?[jt]s|[jt]sx)$/.test(p),
    );
    const result = await runSemgrepScan(
      {
        executable,
        ruleset: {
          source: 'releaseready-authored',
          path: options.rulesDirectory,
          version: releaseReadyRulesVersion,
        },
        audience: 'customer',
      },
      { scope: options.scope, files },
    );
    const base = fromEnvelope('semgrep', result.envelope, semgrepVersion);
    return applyOmitted(
      result.refusal ? { ...base, reason: result.refusal } : base,
      omitted,
      causes,
    );
  });

  await guard('ruff', async () => {
    const executable = options.tools.ruff;
    if (!executable)
      return failed(
        'ruff',
        options.installErrors.ruff ?? 'ruff is not installed',
      );
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      (p) => /\.pyi?$/.test(p),
    );
    const result = await runRuffScan({
      executable,
      scope: options.scope,
      files,
    });
    return applyOmitted(
      fromEnvelope('ruff', result, ruffVersion),
      omitted,
      causes,
    );
  });

  // Java: PMD and Checkstyle run source-only on the workflow's JDK. A missing
  // JDK or engine is a failed engine, never a clean one.
  const scanJava = async (
    id: 'pmd' | 'checkstyle',
    version: string,
    scan: (files: Record<string, string>) => Promise<AdapterEnvelope>,
  ): Promise<EngineResult> => {
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      isJavaFile,
    );
    return applyOmitted(
      fromEnvelope(id, await scan(files), version),
      omitted,
      causes,
    );
  };
  await guard('pmd', async () => {
    const java = options.tools.java;
    const pmdDirectory = options.tools.pmd;
    if (
      !java ||
      !pmdDirectory ||
      !(await treeMatches(pmdDirectory, pmdPin.treeSha256))
    )
      return failed(
        'pmd',
        options.installErrors.pmd ??
          'pmd or java missing, or pmd tree sha256 mismatch',
      );
    const versionOutput = await pmdVersionOutput(java, pmdDirectory);
    return scanJava('pmd', pmdVersion, (files) =>
      runPmdScan({
        java,
        pmdDirectory,
        versionOutput,
        scope: options.scope,
        files,
      }),
    );
  });
  await guard('checkstyle', async () => {
    const java = options.tools.java;
    const jar = options.tools.checkstyle;
    if (!java || !jar)
      return failed(
        'checkstyle',
        options.installErrors.checkstyle ?? 'checkstyle or java missing',
      );
    return scanJava('checkstyle', checkstyleVersion, (files) =>
      runCheckstyleScan({ java, jar, scope: options.scope, files }),
    );
  });
  await guard('spotbugs', () =>
    Promise.resolve({
      ...skipped('spotbugs', 'unavailable', spotbugsPin.skipReason),
      version: spotbugsPin.version,
    }),
  );

  const kotlinEngine = (
    id: 'detekt' | 'ktlint',
    pin: typeof detektPin | typeof ktlintPin,
    createAdapter: typeof createDetektAdapter,
  ) =>
    guard(id, async () => {
      const java = options.tools.java;
      if (!java)
        return {
          ...skipped(id, 'unavailable', javaSkipReason),
          version: pin.version,
        };
      const executable = options.tools[id];
      if (!executable || !(await executableMatches(executable, pin.sha256)))
        return failed(
          id,
          options.installErrors[id] ?? `${id} missing or sha256 mismatch`,
        );
      const { files, omitted, causes } = await readBoundedFiles(
        options.repo,
        paths,
        (p) => kotlinFile.test(p),
      );
      const adapter = createAdapter(
        java,
        executable,
        await jarVersionOutput(java, executable, pin.version),
      );
      const result = await runKotlinScan({
        adapter,
        scope: options.scope,
        files,
      });
      return applyOmitted(
        fromEnvelope(id, result, pin.version),
        omitted,
        causes,
      );
    });
  await kotlinEngine('detekt', detektPin, createDetektAdapter);
  await kotlinEngine('ktlint', ktlintPin, createKtlintAdapter);

  await guard('swiftlint', async () => {
    const executable = options.tools.swiftlint;
    if (
      !executable ||
      !(await executableMatches(executable, swiftlintPin.sha256))
    )
      return failed(
        'swiftlint',
        options.installErrors.swiftlint ??
          'swiftlint missing or sha256 mismatch',
      );
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      (p) => swiftFile.test(p),
    );
    const config = await readBoundedFiles(
      options.repo,
      paths,
      (p) => p === swiftConfigPath,
    );
    const workspace = swiftWorkspace(
      files,
      config.omitted ? undefined : config.files[swiftConfigPath],
    );
    const configProblem =
      workspace.configRejected ??
      (config.omitted ? 'unreadable or over the input limits' : undefined);
    const result = await runSwiftlintScan({
      executable,
      scope: options.scope,
      files: workspace.files,
    });
    const base = fromEnvelope('swiftlint', result, swiftlintVersion);
    // A binary that cannot start on this host fails the version check; say so
    // plainly (for example a glibc mismatch) instead of a bare envelope reason.
    const unrunnable =
      base.status === 'failed' && result.reason === 'engine-version-mismatch'
        ? { ...base, reason: swiftlintUnrunnableReason }
        : base;
    const counted = applyOmitted(unrunnable, omitted, causes);
    return configProblem !== undefined && counted.status === 'completed'
      ? {
          ...counted,
          status: 'incomplete',
          reason: `repository ${swiftConfigPath} was not used (${configProblem}); the bundled default configuration ran instead`,
        }
      : counted;
  });
  await guard('swiftlint-analyze', () =>
    Promise.resolve({
      ...skipped(
        'swiftlint-analyze',
        'unavailable',
        swiftlintAnalyzePin.skipReason,
      ),
      version: swiftlintAnalyzePin.version,
    }),
  );

  await guard('mypy', () =>
    Promise.resolve({
      ...skipped('mypy', 'unavailable', mypyPin.skipReason),
      version: mypyPin.version,
    }),
  );

  await guard('trivy', async () => {
    const executable = options.tools.trivy;
    if (!executable || !(await executableMatches(executable, trivyPin.sha256)))
      return failed(
        'trivy',
        options.installErrors.trivy ?? 'trivy missing or sha256 mismatch',
      );
    const { files, omitted, causes } = await readBoundedFiles(
      options.repo,
      paths,
      isIacCandidate,
    );
    const result = await runTrivyScan(
      {
        executable,
        versionOutput: await trivyVersionOutput(executable),
        mode: 'online',
      },
      { scope: options.scope, target: { kind: 'iac', files } },
    );
    return applyOmitted(
      fromEnvelope('trivy', result.envelope, trivyPin.version),
      omitted,
      causes,
    );
  });

  const lintFiles = async (match: (p: string) => boolean) =>
    readBoundedFiles(options.repo, paths, match);
  const lintResult = async (
    engine: EngineId,
    version: string,
    adapter: Parameters<typeof runAdapter>[0],
    files: Record<string, string>,
    args: readonly string[],
  ): Promise<EngineResult> =>
    fromEnvelope(
      engine,
      await runAdapter(adapter, { scope: options.scope, files, args }),
      version,
    );

  await guard('hadolint', async () => {
    const executable = options.tools.hadolint;
    if (
      !executable ||
      !(await executableMatches(executable, hadolintPin.sha256))
    )
      return failed(
        'hadolint',
        options.installErrors.hadolint ?? 'hadolint missing or sha256 mismatch',
      );
    const { files, omitted, causes } = await lintFiles(isDockerfile);
    const versionOutput = await lintVersionOutput(
      executable,
      hadolintPin.version,
    );
    const names = Object.keys(files);
    const envelopes: AdapterEnvelope[] = [];
    // The adapter allows at most 32 arguments per run.
    for (let i = 0; i < names.length; i += 30) {
      const chunk = names.slice(i, i + 30);
      const adapter = hadolintAdapter({
        executable,
        versionOutput,
        files: new Set(chunk),
      });
      envelopes.push(
        await runAdapter(adapter, {
          scope: options.scope,
          files: Object.fromEntries(chunk.map((n) => [n, files[n] ?? ''])),
          args: chunk,
        }),
      );
    }
    if (!envelopes.length)
      return skipped('hadolint', 'not-applicable', 'no readable Dockerfile');
    return applyOmitted(
      fromEnvelope('hadolint', mergeEnvelopes(envelopes), hadolintPin.version),
      omitted,
      causes,
    );
  });

  await guard('tflint', async () => {
    const executable = options.tools.tflint;
    if (!executable || !(await executableMatches(executable, tflintPin.sha256)))
      return failed(
        'tflint',
        options.installErrors.tflint ?? 'tflint missing or sha256 mismatch',
      );
    const { files, omitted, causes } = await lintFiles(isTerraformFile);
    const adapter = tflintAdapter({
      executable,
      versionOutput: await lintVersionOutput(executable, tflintPin.version),
      files: new Set(Object.keys(files)),
    });
    return applyOmitted(
      await lintResult('tflint', tflintPin.version, adapter, files, []),
      omitted,
      causes,
    );
  });

  await guard('yamllint', async () => {
    const executable = options.tools.yamllint;
    if (!executable)
      return failed(
        'yamllint',
        options.installErrors.yamllint ?? 'yamllint is not installed',
      );
    const { files, omitted, causes } = await lintFiles(isYamlFile);
    const adapter = yamllintAdapter({
      executable,
      versionOutput: await lintVersionOutput(executable, yamllintPin.version),
      files: new Set(Object.keys(files)),
    });
    return applyOmitted(
      await lintResult('yamllint', yamllintPin.version, adapter, files, []),
      omitted,
      causes,
    );
  });

  await guard('markdownlint', async () => {
    const script = options.tools.markdownlint;
    if (!script || !(await executableMatches(script, markdownlintPin.sha256)))
      return failed(
        'markdownlint',
        options.installErrors.markdownlint ??
          'markdownlint-cli2 missing or sha256 mismatch',
      );
    const { files, omitted, causes } = await lintFiles(isMarkdownFile);
    const adapter = markdownlintAdapter({
      node: process.execPath,
      script,
      packageJson: join(dirname(script), 'package.json'),
      files: new Set(Object.keys(files)),
    });
    return applyOmitted(
      await lintResult(
        'markdownlint',
        markdownlintPin.version,
        adapter,
        { ...files, ...markdownlintSupportFiles },
        [],
      ),
      omitted,
      causes,
    );
  });

  await guard('osv', async () => {
    const mode = options.osvMode ?? 'online';
    if (mode === 'off')
      return skipped('osv', 'not-selected', 'osv-mode is off');
    if (mode === 'offline')
      return skipped(
        'osv',
        'unavailable',
        `osv-mode is offline, but the offline-only adapter needs a caller-supplied advisory database and none is provisioned (OSV data redistribution is deferred in docs/scanner-licensing.md); osv-scanner ${osvPin.version} not run`,
      );
    const executable = options.tools.osv;
    if (!executable || !(await executableMatches(executable, osvPin.sha256)))
      return failed(
        'osv',
        options.installErrors.osv ?? 'osv-scanner missing or sha256 mismatch',
      );
    const lockfiles = paths.filter((p) =>
      osvLockfileNames.includes(baseName(p)),
    );
    if (!lockfiles.length)
      return skipped(
        'osv',
        'unavailable',
        'no lockfile the OSV adapter accepts',
      );
    const versionOutput = (
      await exec(executable, ['--version'], {
        env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
        timeout: 10000,
      })
    ).stdout.trim();
    const envelopes: AdapterEnvelope[] = [];
    let omitted = Math.max(0, lockfiles.length - maxLockfiles);
    let disclosure = '';
    for (const lockfile of lockfiles.slice(0, maxLockfiles)) {
      const { files, omitted: skippedFiles } = await readBoundedFiles(
        options.repo,
        paths,
        (p) => p === lockfile,
      );
      omitted += skippedFiles;
      const content = lookup(files, lockfile);
      if (content === undefined) continue;
      const scan = await runOsvScan(
        { executable, versionOutput, mode: 'online' },
        {
          scope: options.scope,
          artefactPath: lockfile,
          artefactContent: content,
        },
      );
      envelopes.push(scan.envelope);
      if (scan.envelope.status !== 'skipped')
        disclosure = `online mode: ${scan.disclosure.transmitted}`;
    }
    if (!envelopes.length)
      return failed('osv', 'no lockfile could be read within adapter limits');
    const result = applyOmitted(
      fromEnvelope('osv', mergeEnvelopes(envelopes), osvPin.version),
      omitted,
    );
    return disclosure ? { ...result, disclosure } : result;
  });

  for (const id of Object.keys(lintEngines) as LintEngineId[])
    await guard(id, () => runLintEngine(id, options, paths));

  // gitleaks and jscpd run through the committed-snapshot API.
  const snapshotEngines = (['gitleaks', 'jscpd'] as const).filter(todo);
  if (snapshotEngines.length) {
    try {
      const { stdout } = await exec('git', [
        '-C',
        options.repo,
        'rev-parse',
        '--git-dir',
      ]);
      const gitDirectory = resolve(options.repo, stdout.trim());
      const tools: { gitleaks?: string; jscpd?: string } = {};
      for (const id of snapshotEngines) {
        const path = options.tools[id];
        if (path && (await executableMatches(path, externalPins[id].sha256)))
          tools[id] = path;
      }
      const report = await scanCommittedSource({
        gitExecutable: options.gitExecutable,
        gitDirectory,
        commitSha: options.scope.commitSha,
        tools,
        detailedFindings: true,
      });
      for (const id of snapshotEngines) {
        const slot = report.scanners.find((s) => s.id === id);
        if (!tools[id])
          out.set(
            id,
            failed(id, options.installErrors[id] ?? 'engine not installed'),
          );
        else if (!slot) out.set(id, failed(id, 'no result from scan'));
        else
          out.set(
            id,
            fromSlot(
              id,
              slot,
              report.sourceError && report.sourceDetail
                ? `${report.sourceError} (${report.sourceDetail})`
                : report.sourceError,
              options.scope,
            ),
          );
      }
    } catch {
      for (const id of snapshotEngines)
        out.set(id, failed(id, 'committed-snapshot scan threw unexpectedly'));
    }
  }
  return engineIds.map((id) => out.get(id) ?? failed(id, 'no result'));
}
