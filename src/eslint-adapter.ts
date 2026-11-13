import { createRequire } from 'node:module';
import { basename, dirname, extname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  redactMessage,
} from './adapter-envelope.js';
import { parseEslintJson } from './eslint-import.js';
import { unresolvedModuleRuleId } from './eslint-unresolved-module.js';
import { normalisedSnippet, stableFingerprint } from './finding-compare.js';
import {
  type AdapterRequest,
  type ParsedOutput,
  type ScannerAdapter,
  adapterLimits,
  runAdapter,
} from './scanner-adapter.js';

/** Versions approved in docs/scanner-licensing.md; anything else is refused. */
export const approvedVersions = Object.freeze({
  eslint: '10.13.0',
  typescriptEslint: '8.72.1',
});
export const eslintConfigVersion = 'bundled-1';
/** Distinct from the default so typed and untyped runs never compare as one. */
export const eslintTypedConfigVersion = 'bundled-typed-1';
/** Heap ceiling for the type-aware ESLint process; exceeding it fails closed. */
const typedHeapMb = 2048;
const unresolvedSampleLimit = 20;
export const supportedExtensions = [
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.ts',
  '.mts',
  '.cts',
  '.tsx',
];
const excluded =
  /(?:(?:^|\/)(?:node_modules|dist|build|coverage|vendor)\/|\.min\.js$)/;
/** Customer ESLint configuration is never executed; its presence is refused. */
const customerConfig =
  /^(?:eslint\.config\.[cm]?[jt]s|\.eslintrc(?:\.[a-z]+)?|\.eslintignore)$/;
const listLimit = 100;

export interface EslintVersions {
  eslint: string;
  typescriptEslint: string;
  parser: string;
  plugin: string;
  eslintJs: string;
  espree: string;
}
export interface EslintScanReport {
  /** Always lint findings: never SAST, dependency, coverage or duplication. */
  analysis: 'lint';
  notAnalysed: readonly ['sast', 'dependencies', 'coverage', 'duplication'];
  versions?: EslintVersions;
  lintedFiles: number;
  /** Files of other languages or formats, listed and never silently lost. */
  unsupportedFiles: string[];
  excludedFiles: string[];
  /** Files ESLint could not parse; these are not findings and not clean. */
  parseFailures: string[];
  /** Counts beyond the listed names, when a list was truncated. */
  truncated: boolean;
  /** Present only for the type-aware opt-in. */
  typeAware?: {
    tsconfig: string;
    /** Distinct module specifiers TypeScript could not resolve. */
    unresolvedModuleCount: number;
    /** Bounded, sorted sample of those specifiers. */
    unresolvedModules: string[];
  };
}
/** The validated opt-in: the tsconfig and every file it extends (see eslint-tsconfig.ts). */
export interface TypedEslintInput {
  tsconfig: string;
  files: Readonly<Record<string, string>>;
}
export interface EslintScanResult {
  envelope: AdapterEnvelope;
  report: EslintScanReport;
}

function readVersions(): EslintVersions {
  const require = createRequire(import.meta.url);
  // Literal specifiers only: no module path is ever computed.
  const v = (manifest: unknown): string =>
    (manifest as { version: string }).version;
  return {
    eslint: v(require('eslint/package.json')),
    typescriptEslint: v(require('typescript-eslint/package.json')),
    parser: v(require('@typescript-eslint/parser/package.json')),
    plugin: v(require('@typescript-eslint/eslint-plugin/package.json')),
    eslintJs: v(require('@eslint/js/package.json')),
    espree: v(require('espree/package.json')),
  };
}

/** Classify requested paths. Pure, so admission is testable without ESLint. */
export function classifyFiles(paths: readonly string[]): {
  supported: string[];
  unsupported: string[];
  excluded: string[];
  customerConfig: string[];
} {
  const out = {
    supported: [] as string[],
    unsupported: [] as string[],
    excluded: [] as string[],
    customerConfig: [] as string[],
  };
  for (const p of [...paths].sort((a, b) => a.localeCompare(b, 'en'))) {
    if (customerConfig.test(basename(p))) out.customerConfig.push(p);
    else if (excluded.test(p)) out.excluded.push(p);
    else if (supportedExtensions.includes(extname(p))) out.supported.push(p);
    else out.unsupported.push(p);
  }
  return out;
}

interface Collected {
  parseFailures: string[];
  lintedFiles: number;
  unresolvedModules: Set<string>;
}

/** Throws if the installed engine or rules differ from the approved pins. */
export function createEslintAdapter(
  files: Readonly<Record<string, string>>,
  collected: Collected,
  typed?: TypedEslintInput,
): { adapter: ScannerAdapter; versions: EslintVersions } {
  const versions = readVersions();
  if (
    versions.eslint !== approvedVersions.eslint ||
    versions.typescriptEslint !== approvedVersions.typescriptEslint ||
    versions.parser !== approvedVersions.typescriptEslint ||
    versions.plugin !== approvedVersions.typescriptEslint
  )
    throw new Error('engine-version-mismatch');
  const require = createRequire(import.meta.url);
  const bin = join(
    dirname(require.resolve('eslint/package.json')),
    'bin',
    'eslint.js',
  );
  const config = join(
    dirname(fileURLToPath(import.meta.url)),
    typed ? 'eslint-scan-config-typed.js' : 'eslint-scan-config.js',
  );
  // Compact output: see eslint-compact-formatter.ts for why not `json`.
  const formatter = join(
    dirname(fileURLToPath(import.meta.url)),
    'eslint-compact-formatter.js',
  );
  const parse = (
    stdout: string,
    context: { sourceRoot: string },
  ): ParsedOutput | undefined => {
    // Bounded: the shared validator rejects oversize or inconsistent reports.
    if (parseEslintJson(stdout, adapterLimits.stdoutBytes).status !== 'parsed')
      return undefined;
    const report = JSON.parse(stdout) as Record<string, unknown>[];
    const candidates: {
      finding: Omit<AdapterFinding, 'fingerprint'>;
      snippet: string;
    }[] = [];
    let partial: EnvelopeReason | undefined;
    collected.lintedFiles = report.length;
    for (const entry of report) {
      const abs = typeof entry.filePath === 'string' ? entry.filePath : '';
      const rel = relative(context.sourceRoot, abs).split(sep).join('/');
      const source = Object.hasOwn(files, rel) ? files[rel] : undefined;
      if (source === undefined) {
        partial ??= 'path-outside-root';
        continue;
      }
      for (const m of entry.messages as Record<string, unknown>[]) {
        if (m.ruleId === unresolvedModuleRuleId) {
          // Probe, not a finding: it only says type information is partial.
          if (typeof m.message === 'string')
            collected.unresolvedModules.add(m.message);
          continue;
        }
        if (m.fatal === true) {
          collected.parseFailures.push(rel);
          partial = 'parse-failure';
          continue;
        }
        const pos = (k: string): number | undefined => {
          const value = m[k];
          return typeof value === 'number' &&
            Number.isSafeInteger(value) &&
            value >= 1
            ? value
            : undefined;
        };
        const startLine = pos('line');
        const startColumn = pos('column');
        const endLine = pos('endLine') ?? startLine;
        const endColumn = pos('endColumn') ?? startColumn;
        const ruleId =
          typeof m.ruleId === 'string' &&
          /^[A-Za-z0-9@/._:()-]{1,200}$/.test(m.ruleId)
            ? m.ruleId
            : undefined;
        if (
          startLine === undefined ||
          startColumn === undefined ||
          endLine === undefined ||
          endColumn === undefined ||
          ruleId === undefined ||
          endLine < startLine ||
          (endLine === startLine && endColumn < startColumn)
        ) {
          partial ??= 'invalid-output';
          continue;
        }
        const range = { startLine, startColumn, endLine, endColumn };
        candidates.push({
          finding: {
            ruleId,
            nativeSeverity: m.severity === 2 ? 'error' : 'warn',
            path: rel,
            range,
            message: redactMessage(m.message),
          },
          snippet: normalisedSnippet(source, range),
        });
      }
    }
    if (collected.unresolvedModules.size > 0) partial ??= 'type-info-partial';
    candidates.sort(
      (a, b) =>
        a.finding.path.localeCompare(b.finding.path, 'en') ||
        a.finding.range.startLine - b.finding.range.startLine ||
        a.finding.range.startColumn - b.finding.range.startColumn ||
        a.finding.ruleId.localeCompare(b.finding.ruleId, 'en'),
    );
    const seen = new Map<string, number>();
    const findings = candidates.map(({ finding, snippet }): AdapterFinding => {
      const key = `${finding.ruleId}\0${finding.path}\0${snippet}`;
      const occurrence = seen.get(key) ?? 0;
      seen.set(key, occurrence + 1);
      return {
        ...finding,
        fingerprint: stableFingerprint(
          'eslint',
          finding.ruleId,
          finding.path,
          snippet,
          occurrence,
        ),
      };
    });
    return partial ? { findings, partial } : { findings };
  };
  return {
    versions,
    adapter: {
      engine: { id: 'eslint', version: versions.eslint },
      rulesetVersion: `typescript-eslint-${versions.typescriptEslint}`,
      configVersion: typed ? eslintTypedConfigVersion : eslintConfigVersion,
      executable: process.execPath,
      versionArgs: [bin, '--version'],
      versionOutput: `v${versions.eslint}`,
      // Never --fix: results are advice only. Customer config is not looked up.
      fixedArgs: [
        ...(typed ? [`--max-old-space-size=${String(typedHeapMb)}`] : []),
        bin,
        '--no-config-lookup',
        '--config',
        config,
        // Type information comes from this one reviewed tsconfig only.
        ...(typed ? ['--parser-options', `project:./${typed.tsconfig}`] : []),
        '--format',
        formatter,
        '--no-warn-ignored',
        '.',
      ],
      allowedArgs: [],
      successExitCodes: [0, 1],
      parse,
    },
  };
}

const limit = (names: string[]): string[] => names.slice(0, listLimit);

/**
 * Lint supported JS/TS files with the bundled approved configuration only.
 * Customer ESLint config files are refused (`skipped`), never loaded. A file
 * ESLint cannot parse makes the run `incomplete`/`parse-failure`; unsupported
 * and excluded files are listed in the report. Lint findings are not SAST,
 * dependency, coverage or duplication results, and nothing is auto-fixed.
 */
export async function runEslintScan(
  request: AdapterRequest,
  typed?: TypedEslintInput,
): Promise<EslintScanResult> {
  const classes = classifyFiles(Object.keys(request.files));
  const collected: Collected = {
    parseFailures: [],
    lintedFiles: 0,
    unresolvedModules: new Set(),
  };
  const report = (versions?: EslintVersions): EslintScanReport => ({
    analysis: 'lint',
    notAnalysed: ['sast', 'dependencies', 'coverage', 'duplication'],
    ...(versions ? { versions } : {}),
    lintedFiles: collected.lintedFiles,
    unsupportedFiles: limit(classes.unsupported),
    excludedFiles: limit(classes.excluded),
    parseFailures: limit(
      [...collected.parseFailures].sort((a, b) => a.localeCompare(b, 'en')),
    ),
    truncated:
      classes.unsupported.length > listLimit ||
      classes.excluded.length > listLimit ||
      collected.parseFailures.length > listLimit,
    ...(typed
      ? {
          typeAware: {
            tsconfig: typed.tsconfig,
            unresolvedModuleCount: collected.unresolvedModules.size,
            unresolvedModules: [...collected.unresolvedModules]
              .sort((a, b) => a.localeCompare(b, 'en'))
              .slice(0, unresolvedSampleLimit),
          },
        }
      : {}),
  });
  const supported: Record<string, string> = {};
  for (const p of classes.supported) supported[p] = request.files[p];
  let built: ReturnType<typeof createEslintAdapter>;
  try {
    built = createEslintAdapter(supported, collected, typed);
  } catch {
    // Without a trusted pinned engine nothing runs; borrow a placeholder pin.
    const envelope = await runAdapter(
      {
        engine: { id: 'eslint', version: approvedVersions.eslint },
        rulesetVersion: `typescript-eslint-${approvedVersions.typescriptEslint}`,
        configVersion: eslintConfigVersion,
        executable: process.execPath,
        versionArgs: ['--version'],
        versionOutput: 'unmatchable',
        fixedArgs: [],
        allowedArgs: [],
        successExitCodes: [0],
        parse: () => undefined,
      },
      { ...request, files: {} },
    );
    return { envelope, report: report() };
  }
  const skip = async (reason: EnvelopeReason): Promise<EslintScanResult> => {
    // Run nothing: reuse runAdapter's envelope builder with an invalid request.
    const envelope = await runAdapter(
      {
        ...built.adapter,
        versionArgs: ['--version'],
        versionOutput: 'unmatchable',
      },
      { ...request, files: {}, signal: AbortSignal.abort() },
    );
    return {
      envelope: { ...envelope, status: 'skipped', reason },
      report: report(built.versions),
    };
  };
  if (classes.customerConfig.length > 0)
    return skip('customer-config-rejected');
  if (classes.supported.length === 0) return skip('no-supported-files');
  // The type-aware run reads the tsconfig chain from the workspace and gets the
  // adapter ceiling, since building a program is slower than parsing. It stays
  // bounded by that ceiling and the heap limit; either ends the run closed.
  const envelope = await runAdapter(
    built.adapter,
    typed
      ? {
          ...request,
          files: { ...typed.files, ...supported },
          timeoutMs: adapterLimits.timeoutMs,
        }
      : { ...request, files: supported },
  );
  return { envelope, report: report(built.versions) };
}
