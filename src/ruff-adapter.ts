import { realpathSync } from 'node:fs';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  envelopeLimits,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import { assembleFindings } from './finding-assembly.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';
import { ruffPin } from './scanner-pins.js';

/**
 * Ruff adapter (RRDSCRUM-187). The rule set is fixed here and passed inline
 * with `--isolated`, so a project's pyproject.toml, ruff.toml, .ruff.toml and
 * `extend` chains are never read. Ruff only reads the copied source files; it
 * installs nothing and runs no project code. Ruff has no severity of its own,
 * so each finding is labelled by rule family (`error`, `security`, `bug`,
 * `convention`) and mapped to the gate's scale by `normaliseSeverity`.
 */
export const ruffVersion = ruffPin.version;
export const ruffRulesetVersion = 'ruff-E-F-W-I-B-UP-S-C4-SIM-PL-2026.11.1';
export const ruffConfigVersion = `bundled-isolated-${ruffVersion}`;
export const ruffSelect = [
  'E',
  'F',
  'W',
  'I',
  'B',
  'UP',
  'S',
  'C4',
  'SIM',
  'PL',
] as const;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const position = (v: unknown): { row: number; column: number } | undefined => {
  if (!isRecord(v)) return undefined;
  const { row, column } = v;
  const ok = (n: unknown): n is number =>
    typeof n === 'number' &&
    Number.isSafeInteger(n) &&
    n >= 1 &&
    n <= envelopeLimits.maxLine;
  return ok(row) && ok(column) ? { row, column } : undefined;
};

/** Rule family label used as the finding's native severity. */
export function ruffFamily(code: string | null): string {
  if (code === null || code.startsWith('E9')) return 'error';
  if (/^S\d/.test(code)) return 'security';
  if (/^(?:F|B|PLE)\d/.test(code)) return 'bug';
  return 'convention';
}

/**
 * Convert `ruff check --output-format json`. Source text and fix suggestions
 * are never copied. A syntax error has a null code and becomes `invalid-syntax`
 * with the `error` family. Unusable entries mark the run `incomplete`; output
 * that is not a JSON array is unusable.
 */
export function parseRuffReport(
  stdout: string,
  sourceRoot?: string,
): ParsedOutput {
  const root: unknown = JSON.parse(stdout);
  if (!Array.isArray(root)) throw new TypeError('not a ruff report');
  const prefixes: string[] = [];
  if (sourceRoot) {
    prefixes.push(sourceRoot);
    try {
      prefixes.push(realpathSync(sourceRoot));
    } catch {
      /* the workspace is gone; the raw root still applies */
    }
  }
  let partial: EnvelopeReason | undefined;
  const candidates: Omit<AdapterFinding, 'fingerprint'>[] = [];
  for (const item of root as unknown[]) {
    const start = isRecord(item) ? position(item.location) : undefined;
    const end = isRecord(item) ? position(item.end_location) : undefined;
    let path: unknown = isRecord(item) ? item.filename : undefined;
    if (typeof path === 'string') {
      let relative: string = path;
      for (const prefix of prefixes)
        if (relative.startsWith(`${prefix}/`))
          relative = relative.slice(prefix.length + 1);
      path = relative.startsWith('./') ? relative.slice(2) : relative;
    }
    const code = isRecord(item) ? item.code : undefined;
    if (
      !isRecord(item) ||
      (code !== null && typeof code !== 'string') ||
      (typeof code === 'string' && !/^[A-Z]{1,5}\d{1,4}$/.test(code)) ||
      typeof item.message !== 'string' ||
      !isSafeRelativePath(path) ||
      !start ||
      !end ||
      end.row < start.row ||
      (end.row === start.row && end.column < start.column)
    ) {
      partial ??= 'invalid-output';
      continue;
    }
    candidates.push({
      ruleId: code ?? 'invalid-syntax',
      nativeSeverity: ruffFamily(code),
      path,
      range: {
        startLine: start.row,
        startColumn: start.column,
        endLine: end.row,
        endColumn: end.column,
      },
      message: redactMessage(item.message) || (code ?? 'invalid-syntax'),
    });
  }
  return assembleFindings('ruff', candidates, partial);
}

/**
 * Fixed arguments only; callers pass none. `--isolated` ignores every
 * configuration file, `--no-cache` writes nothing, and no `--fix` flag means
 * source is never modified. Exit 0 (clean) and 1 (findings) mean Ruff ran;
 * exit 2 is an internal error.
 */
export function createRuffAdapter(
  executable: string,
  executableSha256: string = ruffPin.sha256,
): ScannerAdapter {
  return {
    engine: { id: 'ruff', version: ruffVersion },
    rulesetVersion: ruffRulesetVersion,
    configVersion: ruffConfigVersion,
    executable,
    executableSha256,
    versionArgs: ['--version'],
    versionOutput: `ruff ${ruffVersion}`,
    fixedArgs: [
      'check',
      '--isolated',
      '--no-cache',
      '--output-format',
      'json',
      '--config',
      `lint.select=[${ruffSelect.map((r) => `"${r}"`).join(',')}]`,
      '--config',
      'target-version="py312"',
      '.',
    ],
    allowedArgs: [],
    successExitCodes: [0, 1],
    parse: (stdout, context) => parseRuffReport(stdout, context.sourceRoot),
  };
}

/** Lint `.py`/`.pyi` files in a private workspace; see `runAdapter` for the status contract. */
export function runRuffScan(request: {
  executable: string;
  scope: EnvelopeScope;
  files: Readonly<Record<string, string>>;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<AdapterEnvelope> {
  return runAdapter(createRuffAdapter(request.executable), {
    scope: request.scope,
    files: request.files,
    timeoutMs: request.timeoutMs,
    signal: request.signal,
  });
}
