import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  type EnvelopeStatus,
  envelopeLimits,
  isEnvelopeVersion,
  isSafeRelativePath,
  isValidScope,
  validateEnvelope,
} from './adapter-envelope.js';
import { readBoundedRegular } from './external-scanners.js';
import { runScannerProcess } from './scanner-process.js';

/** Package managers and installers are never adapter executables. */
const forbiddenExecutables = new Set([
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'corepack',
  'pip',
  'pip3',
  'node-gyp',
  'curl',
  'wget',
  'sh',
  'bash',
]);
export const adapterLimits = Object.freeze({
  timeoutMs: 120000,
  stdoutBytes: 4194304,
  files: 1000,
  fileBytes: 1048576,
  totalBytes: 16777216,
  executableBytes: 67108864,
  /** Ceiling for an adapter's own `executableMaxBytes` (self-contained JVM jars). */
  executableBytesCeiling: 134217728,
  args: 32,
  argChars: 256,
});

/** What an engine adapter must declare. All of it is data reviewed up front. */
export interface ScannerAdapter {
  engine: { id: string; version: string };
  rulesetVersion: string;
  configVersion: string;
  /** Trusted absolute path to the pinned engine executable. */
  executable: string;
  /**
   * Optional lowercase hex SHA-256 of the executable. When set, the file is
   * read once, hashed, and a private copy of exactly those bytes is what runs;
   * a mismatch is refused before anything executes. Adapters for pinned
   * engines take this from `externalPins`/`osvPin`.
   */
  executableSha256?: string;
  /** Size cap for the executable read; defaults to `adapterLimits.executableBytes`, at most the ceiling. */
  executableMaxBytes?: number;
  /**
   * Engines whose report reporter writes a file (for example jscpd) declare
   * it here. `path` is relative to the private workspace (the engine runs in
   * `<workspace>/source`, so arguments reach it as `../<dir>`); the directory
   * is created first, the file is read with a bounded, no-symlink read after a
   * successful exit, and `parse` receives its content instead of stdout.
   */
  outputFile?: { path: string; maxBytes: number };
  /**
   * JVM engines: the process that actually runs is `runtime.executable` (the
   * JDK's `java`) with `runtime.args` first, and `executable` is the pinned
   * artifact those arguments point at. The literal argument `{engine}` is
   * replaced by the verified private copy of `executable` (a jar), or by
   * `executable` itself when it has no `executableSha256` (an installed
   * distribution whose tree the caller verified).
   */
  runtime?: { executable: string; args: readonly string[] };
  /** Engine needs base tools (for example `uname`): run with a fixed system PATH. */
  systemPath?: boolean;
  /** Engine needs a `HOME` to start: give it the scan's private workspace, never the real home. */
  privateHome?: boolean;
  /** Run before the scan; its trimmed stdout must equal `versionOutput`. */
  versionArgs: readonly string[];
  versionOutput: string;
  /** Always passed first, never caller-controlled. */
  fixedArgs: readonly string[];
  /** Exact-match caller arguments permitted after the fixed ones. */
  allowedArgs: readonly string[];
  /** Exit codes that mean the engine ran (for example ESLint uses 0 and 1). */
  successExitCodes: readonly number[];
  /**
   * Parse stdout (or the declared `outputFile` content) into findings. `partial` marks results the engine reported as
   * incomplete. Throw or return `undefined` for unusable output.
   */
  parse(
    stdout: string,
    context: { sourceRoot: string },
  ): ParsedOutput | undefined;
}
export interface ParsedOutput {
  findings: AdapterFinding[];
  partial?: EnvelopeReason;
}
export interface AdapterRequest {
  scope: EnvelopeScope;
  /** Repository-relative path to UTF-8 content, written into the workspace. */
  files: Readonly<Record<string, string>>;
  args?: readonly string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Check the adapter declaration itself; a bad adapter never executes. */
function adapterProblem(adapter: ScannerAdapter): string | undefined {
  if (
    ![adapter.executable, adapter.runtime?.executable].every(
      (path) =>
        path === undefined ||
        (isAbsolute(path) &&
          !path.includes('\0') &&
          !forbiddenExecutables.has(basename(path))),
    )
  )
    return 'executable';
  if (
    !isEnvelopeVersion(adapter.engine.version) ||
    !isEnvelopeVersion(adapter.rulesetVersion) ||
    !isEnvelopeVersion(adapter.configVersion) ||
    adapter.versionOutput.length === 0 ||
    (adapter.executableSha256 !== undefined &&
      !/^[a-f0-9]{64}$/.test(adapter.executableSha256)) ||
    (adapter.executableMaxBytes !== undefined &&
      (!Number.isSafeInteger(adapter.executableMaxBytes) ||
        adapter.executableMaxBytes < 1 ||
        adapter.executableMaxBytes > adapterLimits.executableBytesCeiling)) ||
    (adapter.outputFile !== undefined &&
      (!isSafeRelativePath(adapter.outputFile.path) ||
        adapter.outputFile.path.split('/').length < 2 ||
        !Number.isSafeInteger(adapter.outputFile.maxBytes) ||
        adapter.outputFile.maxBytes < 1 ||
        adapter.outputFile.maxBytes > adapterLimits.totalBytes ||
        adapter.outputFile.path.startsWith('source/')))
  )
    return 'pin';
  return undefined;
}

/**
 * Exact allowlist: every caller argument must equal a declared entry. Flags,
 * install/run verbs and anything else are rejected, so lifecycle scripts and
 * network switches cannot be requested.
 */
export function allowedArguments(
  adapter: ScannerAdapter,
  args: readonly string[],
): boolean {
  return (
    args.length <= adapterLimits.args &&
    args.every(
      (a) =>
        a.length <= adapterLimits.argChars &&
        !a.includes('\0') &&
        adapter.allowedArgs.includes(a),
    )
  );
}

function validFiles(files: AdapterRequest['files']): boolean {
  const names = Object.keys(files);
  if (names.length > adapterLimits.files) return false;
  let total = 0;
  for (const name of names) {
    const content = files[name];
    if (!isSafeRelativePath(name) || typeof content !== 'string') return false;
    const size = Buffer.byteLength(content, 'utf8');
    total += size;
    if (size > adapterLimits.fileBytes || total > adapterLimits.totalBytes)
      return false;
  }
  return true;
}

/**
 * Run one pinned adapter in a private temporary workspace and return a
 * validated envelope. The result never claims more than happened: failures and
 * skips carry no findings; cancellation, timeouts and truncation are
 * `incomplete` with a reason and with unusable output discarded.
 *
 * This is not a hostile-code sandbox or a network-enforced boundary. The engine
 * must be trusted; the process gets a scrubbed environment (no credentials or
 * proxy settings), no stdin, fixed arguments and resource limits, and this code
 * never invokes package managers or lifecycle scripts.
 */
export async function runAdapter(
  adapter: ScannerAdapter,
  request: AdapterRequest,
): Promise<AdapterEnvelope> {
  const scope: EnvelopeScope = { ...request.scope };
  const build = (
    status: EnvelopeStatus,
    reason?: EnvelopeReason,
    findings: AdapterFinding[] = [],
  ): AdapterEnvelope => {
    const envelope: AdapterEnvelope = {
      schemaVersion: 1,
      provenance: 'adapter-executed',
      tenantId: scope.tenantId,
      projectId: scope.projectId,
      repository: scope.repository,
      commitSha: scope.commitSha,
      sourceId: scope.sourceId,
      jobId: scope.jobId,
      attemptId: scope.attemptId,
      engine: { ...adapter.engine },
      rulesetVersion: adapter.rulesetVersion,
      configVersion: adapter.configVersion,
      status,
      findings,
    };
    if (reason) envelope.reason = reason;
    return envelope;
  };
  // Out-of-contract requests cannot produce a trustworthy scope: refuse.
  if (!isValidScope(scope) || adapterProblem(adapter) !== undefined)
    throw new TypeError('Invalid adapter or scope');
  const args = request.args ?? [];
  const timeoutMs = request.timeoutMs ?? 30000;
  if (
    !allowedArguments(adapter, args) ||
    !validFiles(request.files) ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > adapterLimits.timeoutMs
  )
    return build('skipped', 'invalid-request');
  if (request.signal?.aborted) return build('skipped', 'cancelled');
  if (process.platform !== 'linux')
    return build('skipped', 'unsupported-platform');

  let workspace: string | undefined;
  try {
    workspace = await mkdtemp(join(tmpdir(), 'adapter-'));
    const source = join(workspace, 'source');
    await mkdir(source, { mode: 0o700 });
    for (const [name, content] of Object.entries(request.files)) {
      const target = join(source, name);
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, content, { mode: 0o600, flag: 'wx' });
    }
    let executable = adapter.executable;
    if (adapter.executableSha256 !== undefined) {
      let bytes: Buffer;
      try {
        bytes = await readBoundedRegular(
          adapter.executable,
          adapter.executableMaxBytes ?? adapterLimits.executableBytes,
        );
      } catch {
        return build('failed', 'engine-version-mismatch');
      }
      if (
        createHash('sha256').update(bytes).digest('hex') !==
        adapter.executableSha256
      )
        return build('failed', 'engine-version-mismatch');
      // Run the verified bytes, not a path that could change after the check.
      executable = join(workspace, 'engine');
      await writeFile(executable, bytes, { mode: 0o700, flag: 'wx' });
    }
    if (adapter.outputFile)
      await mkdir(dirname(join(workspace, adapter.outputFile.path)), {
        recursive: true,
        mode: 0o700,
      });
    // JVM engines run `java <runtime args> <engine args>`; others run the engine.
    const launch = (args: readonly string[]) =>
      adapter.runtime
        ? {
            executable: adapter.runtime.executable,
            args: [
              ...adapter.runtime.args.map((a) =>
                a === '{engine}' ? executable : a,
              ),
              ...args,
            ],
          }
        : { executable, args };
    const version = await runScannerProcess({
      ...launch(adapter.versionArgs),
      cwd: workspace,
      timeoutMs: Math.min(timeoutMs, 10000),
      outputLimit: 4096,
      signal: request.signal,
      systemPath: adapter.systemPath,
      // No `home` here: the version probe needs none, and some engines print
      // extra lines about loaded plugins once they can find a home.
    });
    if (version.state === 'cancelled') return build('incomplete', 'cancelled');
    if (
      version.state !== 'exited' ||
      version.code !== 0 ||
      version.stdout.toString('utf8').trim() !== adapter.versionOutput
    )
      return build('failed', 'engine-version-mismatch');
    const run = await runScannerProcess({
      ...launch([...adapter.fixedArgs, ...args]),
      cwd: source,
      timeoutMs,
      outputLimit: adapterLimits.stdoutBytes,
      signal: request.signal,
      systemPath: adapter.systemPath,
      home: adapter.privateHome ? workspace : undefined,
    });
    switch (run.state) {
      case 'cancelled':
        return build('incomplete', 'cancelled');
      case 'timed-out':
        return build('incomplete', 'timeout');
      case 'output-limit':
        return build('incomplete', 'output-limit');
      case 'cleanup-uncertain':
        return build('failed', 'cleanup-uncertain');
      case 'unsupported':
        return build('skipped', 'unsupported-platform');
      case 'failed':
        return build('failed', 'engine-error');
      case 'exited':
        break;
    }
    if (!adapter.successExitCodes.includes(run.code))
      return build('failed', 'engine-error');
    let output = run.stdout.toString('utf8');
    if (adapter.outputFile) {
      try {
        output = (
          await readBoundedRegular(
            join(workspace, adapter.outputFile.path),
            adapter.outputFile.maxBytes,
          )
        ).toString('utf8');
      } catch {
        return build('failed', 'invalid-output');
      }
    }
    let parsed: ParsedOutput | undefined;
    try {
      parsed = adapter.parse(output, {
        sourceRoot: source,
      });
    } catch {
      parsed = undefined;
    }
    if (!parsed) return build('failed', 'invalid-output');
    let findings = parsed.findings;
    let partial = parsed.partial;
    if (findings.length > envelopeLimits.findings) {
      findings = findings.slice(0, envelopeLimits.findings);
      partial ??= 'finding-limit';
    }
    const envelope = partial
      ? build('incomplete', partial, findings)
      : build('completed', undefined, findings);
    // Adapter output is untrusted until the shared validator accepts it.
    const checked = validateEnvelope(envelope, scope);
    return checked.ok ? checked.envelope : build('failed', 'invalid-output');
  } catch {
    return build('failed', 'workspace-error');
  } finally {
    if (workspace) await rm(workspace, { recursive: true, force: true });
  }
}
