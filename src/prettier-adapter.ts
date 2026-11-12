import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  isSafeRelativePath,
} from './adapter-envelope.js';
import { assembleFindings } from './finding-assembly.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';
import type { RunnerFile, RunnerOutput } from './prettier-runner.js';

/**
 * Prettier format-check adapter. It reports files whose bytes differ from what
 * Prettier would write, one finding per file, and never fixes anything.
 * Prettier is the version this package depends on, started from this tool's
 * checkout by `prettier-runner.js` (see its header for what is never loaded).
 */
export const approvedPrettierVersion = '3.9.10';
export const prettierRuleId = 'prettier/format';
export const prettierConfigVersion = 'json-yaml-config-1';
const listLimit = 100;

const formattable = /\.(?:[cm]?[jt]sx?|json|ya?ml|md|markdown|css)$/;
const excluded =
  /(?:(?:^|\/)(?:node_modules|dist|build|coverage|vendor)\/|\.min\.(?:js|css)$|(?:^|\/)(?:package-lock|npm-shrinkwrap)\.json$|(?:^|\/)pnpm-lock\.yaml$)/;
const configName =
  /^(?:\.prettierrc(?:\.[a-z0-9]+)?|prettier\.config\.[cm]?[jt]s)$/;
const baseName = (path: string): string =>
  path.slice(path.lastIndexOf('/') + 1);

/** Files Prettier checks: TS/JS, JSON, YAML, Markdown and CSS outside generated or vendored trees. */
export const isPrettierFile = (path: string): boolean =>
  formattable.test(path) && !excluded.test(path);
/** Files the runner needs beside the sources: Prettier config candidates and the root ignore file. */
export const isPrettierSupportFile = (path: string): boolean =>
  !excluded.test(path) &&
  (configName.test(baseName(path)) || path === '.prettierignore');
export const isPrettierInput = (path: string): boolean =>
  isPrettierFile(path) || isPrettierSupportFile(path);

export interface PrettierScanReport {
  checkedFiles: number;
  ignoredFiles: number;
  /** Files Prettier could not parse or format; not findings and not clean. */
  parseFailures: string[];
  /** JSON or YAML config files that were read. */
  configUsed: string[];
  /** Config files or options that were not honoured, so defaults applied. */
  configRejected: string[];
  truncated: boolean;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const strings = (v: unknown): string[] | undefined =>
  Array.isArray(v) &&
  v.every((s): s is string => typeof s === 'string' && s.length < 600)
    ? v
    : undefined;
const count = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : undefined;

/** Strict reader for the runner's JSON; anything else is `invalid-output`. */
export function readRunnerOutput(stdout: string): RunnerOutput | undefined {
  const raw: unknown = JSON.parse(stdout);
  if (!isRecord(raw) || !Array.isArray(raw.files)) return undefined;
  const checked = count(raw.checked);
  const ignored = count(raw.ignored);
  const configUsed = strings(raw.configUsed);
  const configRejected = strings(raw.configRejected);
  const files: RunnerFile[] = [];
  for (const f of raw.files as unknown[]) {
    if (
      !isRecord(f) ||
      !isSafeRelativePath(f.path) ||
      (f.state !== 'unformatted' && f.state !== 'error')
    )
      return undefined;
    files.push({ path: f.path, state: f.state });
  }
  return checked === undefined ||
    ignored === undefined ||
    !configUsed ||
    !configRejected
    ? undefined
    : { checked, ignored, files, configUsed, configRejected };
}

/**
 * Turn runner output into findings. A file that failed to parse is never a
 * finding and never clean: it marks the run `parse-failure`. Config that could
 * not be honoured marks it `customer-config-rejected` (defaults were used).
 */
export function parsePrettierReport(
  stdout: string,
  collected?: PrettierScanReport,
): ParsedOutput | undefined {
  const output = readRunnerOutput(stdout);
  if (!output) return undefined;
  const failures = output.files
    .filter((f) => f.state === 'error')
    .map((f) => f.path);
  if (collected) {
    collected.checkedFiles = output.checked;
    collected.ignoredFiles = output.ignored;
    collected.parseFailures = failures.slice(0, listLimit);
    collected.configUsed = output.configUsed.slice(0, listLimit);
    collected.configRejected = output.configRejected.slice(0, listLimit);
    collected.truncated =
      failures.length > listLimit ||
      output.configUsed.length > listLimit ||
      output.configRejected.length > listLimit;
  }
  const candidates: Omit<AdapterFinding, 'fingerprint'>[] = output.files
    .filter((f) => f.state === 'unformatted')
    .map((f) => ({
      ruleId: prettierRuleId,
      nativeSeverity: 'format',
      path: f.path,
      range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
      message:
        'File is not formatted the way Prettier would write it. Run prettier --write on it.',
    }));
  let partial: EnvelopeReason | undefined;
  if (output.configRejected.length > 0) partial = 'customer-config-rejected';
  if (failures.length > 0) partial = 'parse-failure';
  return assembleFindings('prettier', candidates, partial);
}

/** Throws if the installed Prettier is not the approved version. */
export function createPrettierAdapter(collected?: PrettierScanReport): {
  adapter: ScannerAdapter;
  version: string;
} {
  const require = createRequire(import.meta.url);
  const manifest = require('prettier/package.json') as { version: string };
  if (manifest.version !== approvedPrettierVersion)
    throw new Error('engine-version-mismatch');
  const bin = join(
    dirname(require.resolve('prettier/package.json')),
    'bin',
    'prettier.cjs',
  );
  const runner = join(
    dirname(fileURLToPath(import.meta.url)),
    'prettier-runner.js',
  );
  return {
    version: manifest.version,
    adapter: {
      engine: { id: 'prettier', version: manifest.version },
      rulesetVersion: `prettier-${manifest.version}`,
      configVersion: prettierConfigVersion,
      executable: process.execPath,
      versionArgs: [bin, '--version'],
      versionOutput: manifest.version,
      // No flags and no way to pass any: the runner only reads, never writes.
      fixedArgs: [runner],
      allowedArgs: [],
      successExitCodes: [0],
      parse: (stdout) => parsePrettierReport(stdout, collected),
    },
  };
}

export interface PrettierScanResult {
  envelope: AdapterEnvelope;
  report: PrettierScanReport;
}

/**
 * Check formatting of the supplied files (sources plus config candidates and
 * `.prettierignore`). A failure to start, a parse error or a rejected config
 * is `failed`/`incomplete` with a reason, never a clean `completed`.
 */
export async function runPrettierScan(request: {
  scope: EnvelopeScope;
  files: Readonly<Record<string, string>>;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<PrettierScanResult> {
  const report: PrettierScanReport = {
    checkedFiles: 0,
    ignoredFiles: 0,
    parseFailures: [],
    configUsed: [],
    configRejected: [],
    truncated: false,
  };
  const { adapter } = createPrettierAdapter(report);
  const envelope = await runAdapter(adapter, {
    scope: request.scope,
    files: request.files,
    timeoutMs: request.timeoutMs ?? 110000,
    signal: request.signal,
  });
  return { envelope, report };
}
