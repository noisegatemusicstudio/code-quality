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
import { jscpdFindings, parseJscpdReport } from './duplication.js';
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
    | 'cleanup-uncertain';
  findingCount?: number;
  /** Detailed envelope findings; only present when requested. */
  findings?: AdapterFinding[];
  coveredFileCount?: number;
  toolVersion: string;
  binarySha256: string;
  config: string;
}

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
    if (!stat.isFile() || stat.size > limit) throw new Error();
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
    });
    const covered = Object.keys(detail.analyzed).length;
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
    let files = 0;
    let bytes = 0;
    let directories = 0;
    const containsSuppression = async (path: string): Promise<boolean> => {
      if (++directories > 2000) throw new Error();
      for (const entry of await readdir(path, { withFileTypes: true })) {
        const target = join(path, entry.name);
        if (entry.isDirectory()) {
          if (await containsSuppression(target)) return true;
        } else if (entry.isFile()) {
          if (++files > 1000) throw new Error();
          const data = await readBoundedRegular(target, 1048576);
          if ((bytes += data.length) > 16777216) throw new Error();
          if (/jscpd\s*:\s*ignore/i.test(data.toString('utf8'))) return true;
        } else throw new Error();
      }
      return false;
    };
    try {
      if (await containsSuppression(sourceDirectory))
        return {
          ...result,
          state: 'limited',
          reason: 'source-suppression-directive',
        };
    } catch {
      return {
        ...result,
        state: 'failed',
        reason: 'execution-or-report-failed',
      };
    }
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
        '--fsize=1048576:1048576',
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
    result.reason =
      execution.state === 'cleanup-uncertain'
        ? 'cleanup-uncertain'
        : 'execution-or-report-failed';
    if (
      execution.state !== 'exited' ||
      (execution.code !== 0 && execution.code !== 42)
    )
      return result;
    const parsed = acceptExternalReport(
      id,
      execution.code,
      await readBoundedRegular(report, 1048576),
      sourceDirectory,
    );
    if (parsed === null) return result;
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
