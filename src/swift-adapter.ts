import type { AdapterEnvelope, EnvelopeScope } from './adapter-envelope.js';
import { type Draft, assembleDrafts } from './finding-assembly.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';
import { swiftlintPin } from './scanner-pins.js';

/**
 * Swift engine (follow-up slice 9): SwiftLint, the official static Linux
 * binary pinned by sha256, run as `swiftlint lint` over source files only.
 * It never runs `swift build` and never runs analyzer rules (`swiftlint
 * analyze` needs a compiler log); those are reported `skipped` by the runner.
 * Only `.swift` files and, when it passes `swiftConfigProblem`, the root
 * `.swiftlint.yml` are copied into the private workspace. Nested configs are
 * never copied, so they are never seen.
 */
export const swiftlintVersion = swiftlintPin.version;
export const swiftFile = /\.swift$/;
export const swiftConfigPath = '.swiftlint.yml';
/** The configuration used when the repository has none (or its own was rejected): default rules only. */
export const bundledSwiftConfig =
  '# Bundled by code-quality: SwiftLint default rules, no opt-in or analyzer rules.\ndisabled_rules: []\n';
export const swiftlintUnrunnableReason =
  'swiftlint could not run on this host (the binary did not start or did not report the pinned version, for example a glibc mismatch): engine-version-mismatch';
const maxConfigBytes = 65536;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * A SwiftLint configuration is plain YAML data, never code. It is honoured only
 * when it stays that way: bounded UTF-8 text with no control characters, no
 * YAML tags, and nothing that would make SwiftLint fetch or read another
 * configuration (`parent_config`, `child_config`, any URL). Returns the reason
 * it is refused, or `undefined` when it can be used.
 */
export function swiftConfigProblem(text: string): string | undefined {
  if (Buffer.byteLength(text, 'utf8') > maxConfigBytes)
    return 'larger than 64 KiB';
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    const allowed = code === 9 || code === 10 || code === 13;
    if ((code < 32 && !allowed) || code === 127)
      return 'contains control characters';
  }
  if (/^\s*-?\s*(?:parent_config|child_config)\s*:/m.test(text))
    return 'refers to another configuration (parent_config or child_config)';
  if (text.includes('://')) return 'contains a URL';
  if (/(?:^|[\s:[{,-])![A-Za-z!<]/m.test(text)) return 'contains a YAML tag';
  return undefined;
}

/**
 * SwiftLint `--reporter json`: `[{ file, line, character, severity, rule_id,
 * reason, type }]`. `severity` is `Warning` or `Error` and is lower-cased to
 * the native label; `character` may be null. Source text is never copied.
 */
export function parseSwiftlintReport(
  text: string,
  sourceRoot?: string,
): ParsedOutput {
  const root: unknown = JSON.parse(text);
  if (!Array.isArray(root)) throw new TypeError('not a swiftlint report');
  const drafts: Draft[] = (root as unknown[]).map((entry) => {
    const item = isRecord(entry) ? entry : {};
    return {
      ruleId: item.rule_id,
      severity:
        typeof item.severity === 'string'
          ? item.severity.toLowerCase()
          : undefined,
      path: item.file,
      line: item.line,
      column: item.character ?? 1,
      message: item.reason,
    };
  });
  return assembleDrafts('swiftlint', drafts, sourceRoot, false);
}

/**
 * Fixed arguments only; callers pass none. `--config` names the single file
 * placed in the workspace (bundled or the repository's own), `--no-cache`
 * writes nothing, and there is no `--fix`, `--format` or `analyze`, so source
 * is never modified. Exit 0 (clean or warnings only) and 2 (error-severity
 * violations) mean SwiftLint ran; anything else is an engine error.
 */
export function createSwiftlintAdapter(
  executable: string,
  executableSha256: string = swiftlintPin.sha256,
): ScannerAdapter {
  return {
    engine: { id: 'swiftlint', version: swiftlintVersion },
    rulesetVersion: `swiftlint-default-rules-${swiftlintVersion}`,
    configVersion: `bundled-or-plain-yaml-${swiftlintVersion}`,
    executable,
    executableSha256,
    executableMaxBytes: 128 * 1024 * 1024,
    versionArgs: ['version'],
    versionOutput: swiftlintVersion,
    fixedArgs: [
      'lint',
      '--reporter',
      'json',
      '--quiet',
      '--no-cache',
      '--config',
      swiftConfigPath,
    ],
    allowedArgs: [],
    successExitCodes: [0, 2],
    parse: (text, context) => parseSwiftlintReport(text, context.sourceRoot),
  };
}

/**
 * The workspace files: the Swift sources plus exactly one configuration. A
 * repository configuration that is not plain YAML data is replaced by the
 * bundled one and `configRejected` says why, so the caller cannot report a
 * clean run as if the repository's own rules had applied.
 */
export function swiftWorkspace(
  sources: Readonly<Record<string, string>>,
  repositoryConfig: string | undefined,
): { files: Record<string, string>; configRejected?: string } {
  const problem =
    repositoryConfig === undefined
      ? undefined
      : swiftConfigProblem(repositoryConfig);
  const useRepository = repositoryConfig !== undefined && problem === undefined;
  return {
    files: {
      ...sources,
      [swiftConfigPath]: useRepository ? repositoryConfig : bundledSwiftConfig,
    },
    ...(problem === undefined ? {} : { configRejected: problem }),
  };
}

/** Lint `.swift` files in a private workspace; see `runAdapter` for the status contract. */
export function runSwiftlintScan(request: {
  executable: string;
  scope: EnvelopeScope;
  files: Readonly<Record<string, string>>;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<AdapterEnvelope> {
  return runAdapter(createSwiftlintAdapter(request.executable), {
    scope: request.scope,
    files: request.files,
    timeoutMs: request.timeoutMs ?? 120000,
    signal: request.signal,
  });
}
