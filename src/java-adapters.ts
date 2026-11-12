import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
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
import { javaRuntime } from './java-runtime.js';
import {
  type ParsedOutput,
  type ScannerAdapter,
  runAdapter,
} from './scanner-adapter.js';
import { checkstylePin, pmdPin } from './scanner-pins.js';
import { relativeSourcePath } from './source-paths.js';

/**
 * Java source engines (RRDSCRUM-185): PMD and Checkstyle, both run on the
 * workflow's JDK over copied `.java` files only. No build, no classpath, no
 * project configuration: the ruleset (PMD quickstart) and the checks
 * (Checkstyle's bundled Google style) are fixed here. Both report a native
 * severity that `normaliseSeverity` maps to the gate's scale. SpotBugs needs
 * compiled classes and is reported skipped (see `spotbugsPin`).
 */
export const pmdVersion = pmdPin.version;
export const checkstyleVersion = checkstylePin.version;
export const pmdRulesetVersion = `pmd-quickstart-${pmdVersion}`;
export const checkstyleRulesetVersion = `checkstyle-google-checks-${checkstyleVersion}`;
export const isJavaFile = (path: string): boolean => path.endsWith('.java');

type Candidate = Omit<AdapterFinding, 'fingerprint'>;
type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const ruleIdPattern = /^[A-Za-z0-9._:/$-]{1,200}$/;
const lineOf = (v: unknown, fallback?: number): number | undefined =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : fallback;

/** Candidate for a finding whose end is the start unless a valid end is given. */
function candidate(
  ruleId: string,
  nativeSeverity: string,
  path: string,
  start: { line: number; column: number },
  end: { line: number; column: number },
  message: string,
): Candidate {
  const beforeStart =
    end.line < start.line ||
    (end.line === start.line && end.column < start.column);
  const to = beforeStart ? start : end;
  return {
    ruleId,
    nativeSeverity,
    path,
    range: {
      startLine: start.line,
      startColumn: start.column,
      endLine: to.line,
      endColumn: to.column,
    },
    message: redactMessage(message) || ruleId,
  };
}

const sarifLevels = new Set(['error', 'warning', 'note']);

/**
 * Convert PMD's SARIF 2.1.0 report (`-f sarif`). A result's level comes from
 * the result, else its rule's default level, else SARIF's default `warning`.
 * Source text is never copied. An unusable result, or any tool notification
 * (PMD reports files it could not parse there), marks the run incomplete;
 * output that is not a SARIF report is unusable.
 */
export function parsePmdSarif(
  stdout: string,
  sourceRoot?: string,
): ParsedOutput {
  const root: unknown = JSON.parse(stdout);
  if (!isRec(root) || !Array.isArray(root.runs) || root.runs.length !== 1)
    throw new TypeError('not a PMD SARIF report');
  const run: unknown = root.runs[0];
  if (!isRec(run) || !Array.isArray(run.results))
    throw new TypeError('not a PMD SARIF report');
  const tool = isRec(run.tool) ? run.tool : {};
  const driver = isRec(tool.driver) ? tool.driver : {};
  const rules: unknown[] = Array.isArray(driver.rules) ? driver.rules : [];
  let partial: EnvelopeReason | undefined;
  for (const invocation of Array.isArray(run.invocations)
    ? (run.invocations as unknown[])
    : [])
    if (
      isRec(invocation) &&
      (invocation.executionSuccessful === false ||
        (Array.isArray(invocation.toolExecutionNotifications) &&
          invocation.toolExecutionNotifications.length > 0))
    )
      partial ??= 'parse-failure';
  const candidates: Candidate[] = [];
  for (const result of run.results as unknown[]) {
    const found = pmdResult(result, rules, sourceRoot);
    if (found) candidates.push(found);
    else partial ??= 'invalid-output';
  }
  return assembleFindings('pmd', candidates, partial);
}

function pmdResult(
  result: unknown,
  rules: readonly unknown[],
  sourceRoot?: string,
): Candidate | undefined {
  if (!isRec(result)) return undefined;
  const rule =
    typeof result.ruleIndex === 'number' ? rules[result.ruleIndex] : undefined;
  const ruleDefault =
    isRec(rule) && isRec(rule.defaultConfiguration)
      ? rule.defaultConfiguration.level
      : undefined;
  const level = result.level ?? ruleDefault ?? 'warning';
  const location: unknown = Array.isArray(result.locations)
    ? result.locations[0]
    : undefined;
  const physical =
    isRec(location) && isRec(location.physicalLocation)
      ? location.physicalLocation
      : undefined;
  const uri =
    physical && isRec(physical.artifactLocation)
      ? physical.artifactLocation.uri
      : undefined;
  const region = physical && isRec(physical.region) ? physical.region : {};
  const startLine = lineOf(region.startLine);
  const message = isRec(result.message) ? result.message.text : undefined;
  if (
    typeof result.ruleId !== 'string' ||
    !ruleIdPattern.test(result.ruleId) ||
    typeof level !== 'string' ||
    !sarifLevels.has(level) ||
    typeof uri !== 'string' ||
    typeof message !== 'string' ||
    startLine === undefined
  )
    return undefined;
  let decoded = uri.replace(/^file:\/\//, '');
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    return undefined;
  }
  const path = relativeSourcePath(decoded, sourceRoot);
  if (!isSafeRelativePath(path)) return undefined;
  const startColumn = lineOf(region.startColumn, 1) ?? 1;
  return candidate(
    result.ruleId,
    level,
    path,
    { line: startLine, column: startColumn },
    {
      line: lineOf(region.endLine, startLine) ?? startLine,
      column: lineOf(region.endColumn, startColumn) ?? startColumn,
    },
    message,
  );
}

const xmlEntities: Record<string, string> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
};
function xmlDecode(text: string): string {
  return text.replace(
    /&(?:#(\d{1,7})|#x([0-9a-fA-F]{1,6})|(lt|gt|amp|quot|apos));/g,
    (
      whole,
      dec: string | undefined,
      hex: string | undefined,
      name?: string,
    ) => {
      if (name) return xmlEntities[name] ?? whole;
      const code = dec ? Number(dec) : Number.parseInt(hex ?? '', 16);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : ' ';
    },
  );
}
function xmlAttributes(source: string): Partial<Record<string, string>> {
  const out: Partial<Record<string, string>> = {};
  for (const m of source.matchAll(/([A-Za-z_:][\w:.-]*)="([^"]*)"/g))
    out[m[1]] = xmlDecode(m[2]);
  return out;
}
const checkstyleSeverities = new Set(['error', 'warning', 'info']);
const attributeList = String.raw`((?:\s+[A-Za-z_:][\w:.-]*="[^"]*")*)`;
const checkstyleTokens = new RegExp(
  String.raw`<file${attributeList}\s*(/?)>|<error${attributeList}\s*/>|</file>`,
  'g',
);

/**
 * Convert Checkstyle's XML report (`-f xml`). The format is flat
 * (`<file name><error line column severity message source/></file>`), so a
 * strict token scan is enough; no DTD or entity declaration is accepted, and
 * every `<file`/`<error` element must be understood or the output is unusable
 * (a silently dropped violation would read as clean). Source text is never
 * copied.
 */
export function parseCheckstyleXml(
  stdout: string,
  sourceRoot?: string,
): ParsedOutput {
  const start = stdout.indexOf('<checkstyle');
  if (start < 0 || /<!(?:DOCTYPE|ENTITY)/.test(stdout))
    throw new TypeError('not a Checkstyle report');
  const body = stdout.slice(start);
  const candidates: Candidate[] = [];
  let partial: EnvelopeReason | undefined;
  let file: string | undefined;
  let files = 0;
  let errors = 0;
  for (const token of body.matchAll(checkstyleTokens)) {
    if (token[0] === '</file>') {
      file = undefined;
    } else if (token[0].startsWith('<file')) {
      files += 1;
      const name = xmlAttributes(token[1]).name ?? '';
      file = relativeSourcePath(name, sourceRoot);
      if (!isSafeRelativePath(file)) {
        partial ??= 'path-outside-root';
        file = undefined;
      }
      if (token[2] === '/') file = undefined;
    } else {
      errors += 1;
      const found = file
        ? checkstyleError(xmlAttributes(token[3]), file)
        : undefined;
      if (found) candidates.push(found);
      else partial ??= 'invalid-output';
    }
  }
  const expectedFiles = (body.match(/<file[\s/>]/g) ?? []).length;
  const expectedErrors = (body.match(/<error[\s/>]/g) ?? []).length;
  if (files !== expectedFiles || errors !== expectedErrors)
    throw new TypeError('unrecognised Checkstyle element');
  return assembleFindings('checkstyle', candidates, partial);
}

function checkstyleError(
  attributes: Partial<Record<string, string>>,
  path: string,
): Candidate | undefined {
  const severity = attributes.severity ?? '';
  const line = Number(attributes.line);
  const column =
    attributes.column === undefined ? 1 : Number(attributes.column);
  const source = attributes.source ?? '';
  if (
    !checkstyleSeverities.has(severity) ||
    attributes.message === undefined ||
    lineOf(line) === undefined ||
    lineOf(column) === undefined ||
    !/^[A-Za-z0-9_$.]{0,300}$/.test(source)
  )
    return undefined;
  const ruleId = source.slice(source.lastIndexOf('.') + 1) || 'checkstyle';
  const at = { line, column };
  return candidate(ruleId, severity, path, at, at, attributes.message);
}

/**
 * PMD's `--version` line carries build date and host details, so the adapter
 * takes it verbatim, as with Trivy: read once under the same scrubbed
 * environment, and insist it names the pinned version. (The distribution tree
 * is already digest-pinned.)
 */
export async function pmdVersionOutput(
  java: string,
  pmdDirectory: string,
): Promise<string> {
  const { stdout } = await promisify(execFile)(
    java,
    pmdArguments(pmdDirectory, ['--version']),
    { env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' }, timeout: 20000 },
  );
  const output = stdout.trim();
  if (
    !output.startsWith(`PMD ${pmdVersion} `) &&
    output !== `PMD ${pmdVersion}`
  )
    throw new Error('unexpected pmd version');
  return output;
}
const pmdArguments = (directory: string, tail: readonly string[]) => [
  ...javaRuntime('', [
    '-cp',
    `${directory}/lib/*`,
    'net.sourceforge.pmd.cli.PmdCli',
  ]).args,
  ...tail,
];

/**
 * Fixed arguments only; callers pass none. `--no-fail-on-violation` makes
 * exit 0 mean PMD ran, with or without violations; `--no-cache` writes
 * nothing; the quickstart ruleset is read from PMD's own jar. A recoverable
 * processing error exits 5 and fails the engine rather than passing it.
 */
export function createPmdAdapter(
  java: string,
  pmdDirectory: string,
  versionOutput: string,
): ScannerAdapter {
  return {
    engine: { id: 'pmd', version: pmdVersion },
    rulesetVersion: pmdRulesetVersion,
    configVersion: `bundled-${pmdVersion}`,
    executable: `${pmdDirectory}/bin/pmd`,
    runtime: javaRuntime(java, [
      '-cp',
      `${pmdDirectory}/lib/*`,
      'net.sourceforge.pmd.cli.PmdCli',
    ]),
    versionArgs: ['--version'],
    versionOutput,
    fixedArgs: [
      'check',
      '--no-cache',
      '--no-progress',
      '--no-fail-on-violation',
      '--relativize-paths-with',
      '.',
      '--dir',
      '.',
      '--rulesets',
      'rulesets/java/quickstart.xml',
      '--format',
      'sarif',
    ],
    allowedArgs: [],
    successExitCodes: [0],
    parse: (stdout, context) => parsePmdSarif(stdout, context.sourceRoot),
  };
}

/**
 * Checkstyle with its bundled Google checks (`/google_checks.xml` from the
 * jar's classpath, the more common modern default than `sun_checks.xml`).
 * Those checks report at `warning`, so a run exits 0 even with violations.
 */
export function createCheckstyleAdapter(
  java: string,
  jar: string,
  jarSha256: string = checkstylePin.sha256,
): ScannerAdapter {
  return {
    engine: { id: 'checkstyle', version: checkstyleVersion },
    rulesetVersion: checkstyleRulesetVersion,
    configVersion: `bundled-${checkstyleVersion}`,
    executable: jar,
    executableSha256: jarSha256,
    runtime: javaRuntime(java, ['-jar', '{engine}']),
    versionArgs: ['--version'],
    versionOutput: `Checkstyle version: ${checkstyleVersion}`,
    fixedArgs: ['-c', '/google_checks.xml', '-f', 'xml', '.'],
    allowedArgs: [],
    successExitCodes: [0],
    parse: (stdout, context) => parseCheckstyleXml(stdout, context.sourceRoot),
  };
}

interface JavaScanRequest {
  scope: EnvelopeScope;
  files: Readonly<Record<string, string>>;
  timeoutMs?: number;
  signal?: AbortSignal;
}
/** Lint `.java` files in a private workspace; see `runAdapter` for the status contract. */
export function runPmdScan(
  request: JavaScanRequest & {
    java: string;
    pmdDirectory: string;
    versionOutput: string;
  },
): Promise<AdapterEnvelope> {
  const { java, pmdDirectory, versionOutput, ...rest } = request;
  return runAdapter(createPmdAdapter(java, pmdDirectory, versionOutput), rest);
}
/** Lint `.java` files in a private workspace; see `runAdapter` for the status contract. */
export function runCheckstyleScan(
  request: JavaScanRequest & { java: string; jar: string },
): Promise<AdapterEnvelope> {
  const { java, jar, ...rest } = request;
  return runAdapter(createCheckstyleAdapter(java, jar), rest);
}
