import {
  type AdapterEnvelope,
  type AdapterFinding,
  type EnvelopeReason,
  type EnvelopeScope,
  envelopeLimits,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import { assembleFindings, relativeToRoot } from './finding-assembly.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  adapterLimits,
  runAdapter,
} from './scanner-adapter.js';
import { detektPin, ktlintPin } from './scanner-pins.js';

/**
 * Kotlin engines (RRDSCRUM-186): detekt (static analysis) and ktlint (style).
 * Both are sha256-pinned jars run as `java -jar <verified copy>` with fixed
 * arguments. Neither reads project configuration: only `.kt`/`.kts` files are
 * copied into the private workspace, so detekt.yml, .editorconfig and
 * baselines are never seen. Neither installs anything, formats source or runs
 * project code. A missing Java runtime is reported as `skipped`, never clean.
 */
export const detektVersion = detektPin.version;
export const ktlintVersion = ktlintPin.version;
export const kotlinFile = /\.kts?$/;
export const javaSkipReason =
  'needs a Java runtime: no java executable was found (JAVA_HOME/bin/java or /usr/bin/java), so the Kotlin engines cannot run';

const jarBytes = 128 * 1024 * 1024;
const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const position = (v: unknown): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : undefined;
const ruleOk = /^[A-Za-z0-9@/._:()-]{1,200}$/;
const levelOk = /^[A-Za-z0-9._-]{1,32}$/;

interface Draft {
  ruleId: unknown;
  severity: unknown;
  path: unknown;
  line: unknown;
  column: unknown;
  endLine?: unknown;
  endColumn?: unknown;
  message: unknown;
}

/** Validate one raw entry; `undefined` means unusable (the run becomes incomplete). */
function toCandidate(
  d: Draft,
  sourceRoot: string | undefined,
): Omit<AdapterFinding, 'fingerprint'> | undefined {
  const path =
    typeof d.path === 'string' ? relativeToRoot(d.path, sourceRoot) : undefined;
  const startLine = position(d.line);
  const startColumn = position(d.column) ?? 1;
  const endLine = position(d.endLine) ?? startLine;
  const endColumn = position(d.endColumn) ?? startColumn;
  if (
    typeof d.ruleId !== 'string' ||
    !ruleOk.test(d.ruleId) ||
    typeof d.severity !== 'string' ||
    !levelOk.test(d.severity) ||
    !isSafeRelativePath(path) ||
    startLine === undefined ||
    endLine === undefined ||
    endLine < startLine
  )
    return undefined;
  return {
    ruleId: d.ruleId,
    nativeSeverity: d.severity,
    path,
    range: { startLine, startColumn, endLine, endColumn },
    message: redactMessage(d.message) || d.ruleId,
  };
}

function assemble(
  engine: string,
  drafts: readonly Draft[],
  sourceRoot: string | undefined,
  invalid: boolean,
): ParsedOutput {
  let partial: EnvelopeReason | undefined = invalid
    ? 'invalid-output'
    : undefined;
  const candidates: Omit<AdapterFinding, 'fingerprint'>[] = [];
  for (const draft of drafts) {
    const candidate = toCandidate(draft, sourceRoot);
    if (candidate) candidates.push(candidate);
    else partial ??= 'invalid-output';
  }
  return assembleFindings(engine, candidates, partial);
}

/**
 * detekt SARIF 2.1.0: `runs[].results[]` with `ruleId`, `level`
 * (`error`|`warning`|`note`), `message.text` and one physical location. The
 * location `uri` may be absolute, `file://` or relative; all are reduced to a
 * repository-relative path. Source snippets are never copied. Output that is
 * not a SARIF log is unusable.
 */
export function parseDetektSarif(
  text: string,
  sourceRoot?: string,
): ParsedOutput {
  const root: unknown = JSON.parse(text);
  if (!isRecord(root) || !Array.isArray(root.runs))
    throw new TypeError('not a SARIF log');
  const drafts: Draft[] = [];
  let invalid = false;
  for (const run of root.runs as unknown[]) {
    if (!isRecord(run) || !Array.isArray(run.results)) {
      invalid = true;
      continue;
    }
    for (const result of run.results as unknown[]) {
      const item = isRecord(result) ? result : {};
      const locations = Array.isArray(item.locations) ? item.locations : [];
      const first: unknown = locations[0];
      const physical =
        isRecord(first) && isRecord(first.physicalLocation)
          ? first.physicalLocation
          : {};
      const artifact = isRecord(physical.artifactLocation)
        ? physical.artifactLocation
        : {};
      const region = isRecord(physical.region) ? physical.region : {};
      drafts.push({
        ruleId: item.ruleId,
        severity: item.level ?? 'warning',
        path: artifact.uri,
        line: region.startLine,
        column: region.startColumn,
        endLine: region.endLine,
        endColumn: region.endColumn,
        message: isRecord(item.message) ? item.message.text : undefined,
      });
    }
  }
  return assemble('detekt', drafts, sourceRoot, invalid);
}

/**
 * ktlint `--reporter=json`: `[{ file, errors: [{ line, column, message, rule }] }]`.
 * ktlint has no severity, so every finding is labelled `style`. A rule that
 * ktlint reports without an id becomes `ktlint:unknown`.
 */
export function parseKtlintReport(
  text: string,
  sourceRoot?: string,
): ParsedOutput {
  const root: unknown = JSON.parse(text);
  if (!Array.isArray(root)) throw new TypeError('not a ktlint report');
  const drafts: Draft[] = [];
  let invalid = false;
  for (const entry of root as unknown[]) {
    if (!isRecord(entry) || !Array.isArray(entry.errors)) {
      invalid = true;
      continue;
    }
    for (const error of entry.errors as unknown[]) {
      const item = isRecord(error) ? error : {};
      drafts.push({
        ruleId:
          typeof item.rule === 'string' && item.rule !== ''
            ? item.rule
            : 'ktlint:unknown',
        severity: 'style',
        path: entry.file,
        line: item.line,
        column: item.column,
        message: item.message,
      });
    }
  }
  return assemble('ktlint', drafts, sourceRoot, invalid);
}

interface JarSpec {
  id: 'detekt' | 'ktlint';
  version: string;
  rulesetVersion: string;
  fixedArgs: readonly string[];
  parse: ScannerAdapter['parse'];
  outputFile?: ScannerAdapter['outputFile'];
  successExitCodes: readonly number[];
}

/** Shared declaration of a pinned jar run by a Java runtime. */
function jarAdapter(
  spec: JarSpec,
  java: string,
  executable: string,
  executableSha256: string,
  versionOutput: string,
): ScannerAdapter {
  return {
    engine: { id: spec.id, version: spec.version },
    rulesetVersion: spec.rulesetVersion,
    configVersion: `bundled-defaults-${spec.version}`,
    executable,
    executableSha256,
    executableMaxBytes: jarBytes,
    runtime: { executable: java, args: ['-Xmx1g', '-jar'] },
    versionArgs: ['--version'],
    versionOutput,
    fixedArgs: spec.fixedArgs,
    allowedArgs: [],
    successExitCodes: spec.successExitCodes,
    parse: spec.parse,
    ...(spec.outputFile ? { outputFile: spec.outputFile } : {}),
  };
}

/**
 * detekt exits 0 when clean and 2 when issues exceed `maxIssues`; both mean it
 * ran. The report goes to a file beside the source directory, never into it.
 */
export function createDetektAdapter(
  java: string,
  executable: string,
  versionOutput: string,
  executableSha256: string = detektPin.sha256,
): ScannerAdapter {
  return jarAdapter(
    {
      id: 'detekt',
      version: detektVersion,
      rulesetVersion: `detekt-default-ruleset-${detektVersion}`,
      fixedArgs: ['--input', '.', '--report', 'sarif:../out/detekt.sarif'],
      outputFile: {
        path: 'out/detekt.sarif',
        maxBytes: adapterLimits.stdoutBytes,
      },
      successExitCodes: [0, 2],
      parse: (text, context) => parseDetektSarif(text, context.sourceRoot),
    },
    java,
    executable,
    executableSha256,
    versionOutput,
  );
}

/** ktlint exits 0 when clean and 1 when it reports violations. */
export function createKtlintAdapter(
  java: string,
  executable: string,
  versionOutput: string,
  executableSha256: string = ktlintPin.sha256,
): ScannerAdapter {
  return jarAdapter(
    {
      id: 'ktlint',
      version: ktlintVersion,
      rulesetVersion: `ktlint-official-standard-${ktlintVersion}`,
      fixedArgs: ['--reporter=json', '--relative', '**/*.kt', '**/*.kts'],
      successExitCodes: [0, 1],
      parse: (text, context) => parseKtlintReport(text, context.sourceRoot),
    },
    java,
    executable,
    executableSha256,
    versionOutput,
  );
}

/** Lint `.kt`/`.kts` files in a private workspace; see `runAdapter` for the status contract. */
export function runKotlinScan(request: {
  adapter: ScannerAdapter;
  scope: EnvelopeScope;
  files: Readonly<Record<string, string>>;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<AdapterEnvelope> {
  return runAdapter(request.adapter, {
    scope: request.scope,
    files: request.files,
    timeoutMs: request.timeoutMs ?? 120000,
    signal: request.signal,
  });
}
