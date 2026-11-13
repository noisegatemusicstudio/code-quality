import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  open,
  realpath,
  mkdtemp,
  writeFile,
  lstat,
  rm,
  readdir,
} from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type { AdapterFinding } from './adapter-envelope.js';
import { parseGitleaksReport } from './gitleaks-adapter.js';
import {
  jscpdFindings,
  parseJscpdReport,
  snapshotLineCounter,
} from './duplication.js';
import { runScannerProcess } from './scanner-process.js';
import { externalPins } from './scanner-pins.js';

export { externalPins };
export type ExternalId = keyof typeof externalPins;
export interface ExternalResult {
  id: ExternalId;
  state: 'completed' | 'failed' | 'timed-out' | 'missing' | 'limited';
  evidence: 'executed' | 'none';
  reason?:
    | 'unsupported-platform'
    | 'unavailable-or-untrusted-tool'
    | 'source-suppression-file'
    | 'source-suppression-directive'
    | 'execution-or-report-failed'
    | 'suppression-scan-limit'
    | 'tool-output-limit'
    | 'tool-failed'
    | 'tool-exit-unexpected'
    | 'report-too-large'
    | 'report-invalid'
    | 'timeout'
    | 'cleanup-uncertain';
  findingCount?: number;
  /** Detailed envelope findings; only present when requested. */
  findings?: AdapterFinding[];
  coveredFileCount?: number;
  toolVersion: string;
  binarySha256: string;
  config: string;
}

/** Thrown by `readBoundedRegular` when the file exceeds the byte limit. */
export class BoundedReadTooLargeError extends Error {}

export async function readBoundedRegular(
  path: string,
  limit: number,
): Promise<Buffer> {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error();
    if (stat.size > limit) throw new BoundedReadTooLargeError();
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!read.bytesRead) throw new Error();
      offset += read.bytesRead;
    }
    if ((await handle.stat()).size !== stat.size) throw new Error();
    return bytes;
  } finally {
    await handle.close();
  }
}
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Pure extraction on top of the shared adapter parsers (one parser per report
 * format): counts for the legacy output plus the detailed envelope findings.
 * NEVER execution proof on its own. `pathRoot` is the absolute scan root the
 * engine reported paths under.
 */
export function parseExternalReport(
  id: ExternalId,
  raw: Buffer,
  pathRoot?: string,
): {
  findingCount: number;
  coveredFileCount?: number;
  findings: AdapterFinding[];
} | null {
  if (raw.length > 1048576) return null;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    return null;
  }
  try {
    if (id === 'gitleaks') {
      const parsed = parseGitleaksReport(text, false, pathRoot);
      // Any skipped or truncated entry means the report is not trustworthy.
      if (!parsed || parsed.partial || parsed.findings.length > 10000)
        return null;
      return {
        findingCount: parsed.findings.length,
        findings: parsed.findings,
      };
    }
    const detail = parseJscpdReport(text, {
      pathRoot: pathRoot ?? '/',
      files: undefined,
      ...(pathRoot ? { lineCount: snapshotLineCounter(pathRoot) } : {}),
    });
    const covered = detail.sourceCount;
    if (detail.state !== 'complete' || covered === 0) return null;
    return {
      findingCount: detail.cloneCount,
      coveredFileCount: covered,
      findings: jscpdFindings(detail.clones),
    };
  } catch {
    return null;
  }
}

export function acceptExternalReport(
  id: ExternalId,
  exitCode: number,
  raw: Buffer,
  pathRoot?: string,
) {
  if (exitCode !== 0 && exitCode !== 42) return null;
  const parsed = parseExternalReport(id, raw, pathRoot);
  return parsed !== null && (exitCode === 0) === (parsed.findingCount === 0)
    ? parsed
    : null;
}

/** Internal snapshot adapter. sourceDirectory MUST be the owned committed
 * snapshot, never an arbitrary checkout. No downloads, installation, shell,
 * project config discovery, network mode or PATH lookup is provided here.
 */
async function runExternalScannerInner(
  id: ExternalId,
  sourceDirectory: string,
  executable?: string,
  detailed = false,
): Promise<ExternalResult> {
  const pin = externalPins[id];
  const result: ExternalResult = {
    id,
    state: 'missing',
    evidence: 'none',
    toolVersion: pin.version,
    binarySha256: pin.sha256,
    config: 'bundled-v1-default-rules-no-project-config',
  };
  if (executable === undefined) return result;
  if (process.platform !== 'linux' || process.arch !== 'x64')
    return { ...result, state: 'failed', reason: 'unsupported-platform' };
  let binary: Buffer;
  try {
    if (
      !isAbsolute(executable) ||
      (await realpath(executable)) !== resolve(executable)
    )
      throw new Error();
    binary = await readBoundedRegular(executable, 67108864);
    if (createHash('sha256').update(binary).digest('hex') !== pin.sha256)
      throw new Error();
  } catch {
    return {
      ...result,
      state: 'failed',
      reason: 'unavailable-or-untrusted-tool',
    };
  }
  if (id === 'gitleaks') {
    try {
      await lstat(join(sourceDirectory, '.gitleaksignore'));
      return { ...result, state: 'limited', reason: 'source-suppression-file' };
    } catch (error) {
      if (!record(error) || error.code !== 'ENOENT')
        return {
          ...result,
          state: 'failed',
          reason: 'execution-or-report-failed',
        };
    }
  }
  if (id === 'jscpd') {
    const suppression = await findJscpdSuppression(sourceDirectory);
    if (suppression === 'found')
      return {
        ...result,
        state: 'limited',
        reason: 'source-suppression-directive',
      };
    if (suppression !== 'none')
      return { ...result, state: 'failed', reason: 'suppression-scan-limit' };
  }
  const directory = await mkdtemp(join(tmpdir(), 'code-quality-external-'));
  let uncertain = false;
  let inFlight = false;
  try {
    const tool = join(directory, 'scanner');
    await writeFile(tool, binary, { flag: 'wx', mode: 0o700 });
    const config = join(
      directory,
      id === 'gitleaks' ? 'rules.toml' : 'rules.json',
    );
    await writeFile(
      config,
      id === 'gitleaks' ? '[extend]\nuseDefault = true\n' : '{}',
      { mode: 0o600 },
    );
    await writeFile(join(directory, 'ignore'), '');
    const report = join(directory, 'report.json');
    const args =
      id === 'gitleaks'
        ? [
            'dir',
            sourceDirectory,
            '--config',
            config,
            '--gitleaks-ignore-path',
            join(directory, 'ignore'),
            '--ignore-gitleaks-allow',
            '--redact=100',
            '--exit-code=42',
            '--no-banner',
            '--log-level=error',
            '--max-decode-depth=0',
            '--max-archive-depth=0',
            '--report-format=json',
            '--report-path',
            report,
          ]
        : [
            '--config',
            config,
            '--reporters',
            'json',
            '--output',
            directory,
            '--report-name',
            'report',
            '--min-lines',
            '5',
            '--min-tokens',
            '50',
            '--mode',
            'strict',
            '--no-gitignore',
            '--no-colors',
            '--no-tips',
            '--silent',
            '--exit-code',
            '42',
            '--fail-on-empty',
            '--',
            sourceDirectory,
          ];
    inFlight = true;
    const execution = await runScannerProcess({
      executable: '/usr/bin/prlimit',
      args: [
        '--as=8589934592:8589934592',
        `--fsize=${String(reportBytesCap)}:${String(reportBytesCap)}`,
        '--cpu=30:30',
        '--',
        tool,
        ...args,
      ],
      cwd: directory,
      timeoutMs: 30000,
      outputLimit: 262144,
    });
    inFlight = false;
    if (execution.state === 'cleanup-uncertain') uncertain = true;
    result.state = execution.state === 'timed-out' ? 'timed-out' : 'failed';
    result.reason = executionFailureReason(execution);
    // `prlimit --fsize` kills the tool (SIGXFSZ) once its report reaches the cap,
    // which looks like a plain tool failure; the truncated file names the cause.
    if (
      execution.state === 'failed' &&
      (await reportReachedSizeCap(report, reportBytesCap))
    )
      result.reason = 'report-too-large';
    if (
      execution.state !== 'exited' ||
      (execution.code !== 0 && execution.code !== 42)
    )
      return result;
    let reportBytes: Buffer;
    try {
      reportBytes = await readBoundedRegular(report, reportBytesCap);
    } catch (error) {
      return {
        ...result,
        reason:
          error instanceof BoundedReadTooLargeError
            ? 'report-too-large'
            : 'report-invalid',
      };
    }
    const parsed = acceptExternalReport(
      id,
      execution.code,
      reportBytes,
      sourceDirectory,
    );
    if (parsed === null) return { ...result, reason: 'report-invalid' };
    return {
      ...result,
      state: 'completed',
      evidence: 'executed',
      reason: undefined,
      findingCount: parsed.findingCount,
      coveredFileCount: parsed.coveredFileCount,
      ...(detailed ? { findings: parsed.findings } : {}),
    };
  } catch {
    if (inFlight) uncertain = true;
    return {
      ...result,
      state: 'failed',
      reason: uncertain ? 'cleanup-uncertain' : 'execution-or-report-failed',
    };
  } finally {
    if (!uncertain) await rm(directory, { recursive: true, force: true });
  }
}

/** Bounds of the pre-scan for in-source `jscpd:ignore` directives. */
export const suppressionScanBounds = Object.freeze({
  files: 1000,
  directories: 2000,
  fileBytes: 1048576,
  totalBytes: 16777216,
});

/**
 * Look for a jscpd suppression directive in the snapshot before running the
 * engine. `limit` means the tree exceeded a bound (or held an unexpected entry
 * type) so the absence of a directive could not be proven; the caller must not
 * run jscpd then, and reports it with a reason that names this guard.
 */
export async function findJscpdSuppression(
  sourceDirectory: string,
  bounds: Record<
    keyof typeof suppressionScanBounds,
    number
  > = suppressionScanBounds,
): Promise<'found' | 'none' | 'limit'> {
  let files = 0;
  let bytes = 0;
  let directories = 0;
  const walk = async (path: string): Promise<boolean> => {
    if (++directories > bounds.directories) throw new Error();
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const target = join(path, entry.name);
      if (entry.isDirectory()) {
        if (await walk(target)) return true;
      } else if (entry.isFile()) {
        if (++files > bounds.files) throw new Error();
        const data = await readBoundedRegular(target, bounds.fileBytes);
        if ((bytes += data.length) > bounds.totalBytes) throw new Error();
        if (/jscpd\s*:\s*ignore/i.test(data.toString('utf8'))) return true;
      } else throw new Error();
    }
    return false;
  };
  try {
    return (await walk(sourceDirectory)) ? 'found' : 'none';
  } catch {
    return 'limit';
  }
}

/** Largest report a scanner may write and this module will read. */
export const reportBytesCap = 1048576;

/** True when the report exists and is at or above the cap (a truncated write). */
export async function reportReachedSizeCap(
  report: string,
  cap: number,
): Promise<boolean> {
  try {
    return (await lstat(report)).size >= cap;
  } catch {
    return false;
  }
}

/** Name the reason a scanner process did not produce a usable exit. */
export function executionFailureReason(execution: {
  state: string;
  code?: number;
}): NonNullable<ExternalResult['reason']> {
  switch (execution.state) {
    case 'cleanup-uncertain':
      return 'cleanup-uncertain';
    case 'timed-out':
      return 'timeout';
    case 'output-limit':
      return 'tool-output-limit';
    case 'exited':
      return execution.code === 0 || execution.code === 42
        ? 'execution-or-report-failed'
        : 'tool-exit-unexpected';
    default:
      return 'tool-failed';
  }
}

export async function runExternalScanner(
  id: ExternalId,
  sourceDirectory: string,
  executable?: string,
  detailed = false,
): Promise<ExternalResult> {
  try {
    return await runExternalScannerInner(
      id,
      sourceDirectory,
      executable,
      detailed,
    );
  } catch {
    const pin = externalPins[id];
    return {
      id,
      state: 'failed',
      evidence: 'none',
      reason: 'cleanup-uncertain',
      toolVersion: pin.version,
      binarySha256: pin.sha256,
      config: 'bundled-v1-default-rules-no-project-config',
    };
  }
}
