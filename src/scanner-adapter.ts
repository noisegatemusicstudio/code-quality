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
   * Parse stdout into findings. `partial` marks results the engine reported as
   * incomplete. Throw or return `undefined` for unusable output.
   */
  parse(stdout: string): ParsedOutput | undefined;
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
    !isAbsolute(adapter.executable) ||
    adapter.executable.includes('\0') ||
    forbiddenExecutables.has(basename(adapter.executable))
  )
    return 'executable';
  if (
    !isEnvelopeVersion(adapter.engine.version) ||
    !isEnvelopeVersion(adapter.rulesetVersion) ||
    !isEnvelopeVersion(adapter.configVersion) ||
    adapter.versionOutput.length === 0
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
    const version = await runScannerProcess({
      executable: adapter.executable,
      args: adapter.versionArgs,
      cwd: workspace,
      timeoutMs: Math.min(timeoutMs, 10000),
      outputLimit: 4096,
      signal: request.signal,
    });
    if (version.state === 'cancelled') return build('incomplete', 'cancelled');
    if (
      version.state !== 'exited' ||
      version.code !== 0 ||
      version.stdout.toString('utf8').trim() !== adapter.versionOutput
    )
      return build('failed', 'engine-version-mismatch');
    const run = await runScannerProcess({
      executable: adapter.executable,
      args: [...adapter.fixedArgs, ...args],
      cwd: source,
      timeoutMs,
      outputLimit: adapterLimits.stdoutBytes,
      signal: request.signal,
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
    let parsed: ParsedOutput | undefined;
    try {
      parsed = adapter.parse(run.stdout.toString('utf8'));
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
