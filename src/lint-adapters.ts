import {
  type AdapterFinding,
  envelopeLimits,
  findingFingerprint,
  isSafeRelativePath,
  redactMessage,
} from './adapter-envelope.js';
import type { ParsedOutput, ScannerAdapter } from './scanner-adapter.js';
import {
  hadolintPin,
  markdownlintPin,
  tflintPin,
  yamllintPin,
} from './scanner-pins.js';

/**
 * Adapters for the Dockerfile, Terraform, YAML and Markdown lint engines
 * (docs/language-profiles.md slices 5, 6 and 10). All run through
 * `runAdapter` with the engine's bundled default configuration only: project
 * configs (`.hadolint.yaml`, `.tflint.hcl`, `.yamllint*`, `.markdownlint*`) are
 * never written to the workspace, and tflint never downloads a plugin. Native
 * severities are kept; the gate table lives in `normaliseSeverity`.
 */
export const lintEngineVersions = Object.freeze({
  hadolint: hadolintPin.version,
  tflint: tflintPin.version,
  yamllint: yamllintPin.version,
  markdownlint: markdownlintPin.version,
});

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const clampLine = (v: unknown, fallback = 1): number =>
  typeof v === 'number' &&
  Number.isSafeInteger(v) &&
  v >= 1 &&
  v <= envelopeLimits.maxLine
    ? v
    : fallback;
const label = (v: unknown, fallback: string): string =>
  typeof v === 'string' && /^[A-Za-z0-9._-]{1,32}$/.test(v) ? v : fallback;
const rule = (v: unknown): string =>
  (typeof v === 'string' ? v : 'unknown')
    .replaceAll(/[^A-Za-z0-9@/._:()-]/g, '_')
    .slice(0, 200) || 'unknown';

interface RawFinding {
  engine: string;
  rule: string;
  severity: string;
  path: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  message: string;
}
/** Accept only paths that were actually written to the workspace. */
function knownPath(value: unknown, files: ReadonlySet<string>): string {
  if (typeof value !== 'string') throw new TypeError('path');
  const path = value.replace(/^(?:\.\/)+/, '');
  if (!isSafeRelativePath(path) || !files.has(path))
    throw new TypeError('path');
  return path;
}
function toFindings(raw: readonly RawFinding[]): AdapterFinding[] {
  const seen = new Map<string, number>();
  return raw.map((r) => {
    const endLine = Math.max(r.line, r.endLine ?? r.line);
    const base = {
      ruleId: r.rule,
      nativeSeverity: r.severity,
      path: r.path,
      range: {
        startLine: r.line,
        startColumn: r.column,
        endLine,
        endColumn:
          endLine === r.line
            ? Math.max(r.column, r.endColumn ?? r.column)
            : (r.endColumn ?? 1),
      },
      message: redactMessage(r.message),
    };
    const key = JSON.stringify(base);
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    return {
      ...base,
      fingerprint: findingFingerprint(r.engine, base, occurrence),
    };
  });
}
const str = (v: unknown, fallback: string): string =>
  typeof v === 'string' && v !== '' ? v : fallback;
const json = (stdout: string): unknown => JSON.parse(stdout) as unknown;

/** `hadolint -f json`: an array of `{code, column, file, level, line, message}`. */
export function parseHadolint(
  stdout: string,
  files: ReadonlySet<string>,
): ParsedOutput {
  const root = json(stdout);
  if (!Array.isArray(root)) throw new TypeError('hadolint output');
  return {
    findings: toFindings(
      root.map((item: unknown): RawFinding => {
        if (!isRec(item)) throw new TypeError('hadolint item');
        return {
          engine: 'hadolint',
          rule: rule(item.code),
          severity: label(item.level, 'error'),
          path: knownPath(item.file, files),
          line: clampLine(item.line),
          column: clampLine(item.column),
          message: str(item.message, str(item.code, 'hadolint finding')),
        };
      }),
    ),
  };
}

/** `tflint --format json`: `{issues: [...], errors: [...]}`; errors make the run partial. */
export function parseTflint(
  stdout: string,
  files: ReadonlySet<string>,
): ParsedOutput {
  const root = json(stdout);
  if (!isRec(root) || !Array.isArray(root.issues))
    throw new TypeError('tflint output');
  const findings = toFindings(
    root.issues.map((item: unknown): RawFinding => {
      if (!isRec(item) || !isRec(item.rule) || !isRec(item.range))
        throw new TypeError('tflint item');
      const start = isRec(item.range.start) ? item.range.start : {};
      const end = isRec(item.range.end) ? item.range.end : {};
      return {
        engine: 'tflint',
        rule: rule(item.rule.name),
        severity: label(item.rule.severity, 'error'),
        path: knownPath(item.range.filename, files),
        line: clampLine(start.line),
        column: clampLine(start.column),
        endLine: clampLine(end.line, clampLine(start.line)),
        endColumn: clampLine(end.column, clampLine(start.column)),
        message: str(item.message, str(item.rule.name, 'tflint finding')),
      };
    }),
  );
  const errors = Array.isArray(root.errors) ? root.errors : [];
  return errors.length > 0
    ? { findings, partial: 'parse-failure' }
    : { findings };
}

const yamllintLine =
  /^(.+?):(\d+):(\d+): \[(error|warning)\] (.*?)(?: \(([a-z0-9-]+)\))?$/;
/** `yamllint -f parsable`: `path:line:col: [level] message (rule)`. */
export function parseYamllint(
  stdout: string,
  files: ReadonlySet<string>,
): ParsedOutput {
  const raw: RawFinding[] = [];
  for (const text of stdout.split('\n')) {
    if (text.trim() === '') continue;
    const m = yamllintLine.exec(text);
    if (!m) throw new TypeError('yamllint line');
    raw.push({
      engine: 'yamllint',
      rule: rule(m[6] || 'syntax'),
      severity: m[4],
      path: knownPath(m[1], files),
      line: clampLine(Number(m[2])),
      column: clampLine(Number(m[3])),
      message: m[5],
    });
  }
  return { findings: toFindings(raw) };
}

/**
 * Output formatter written next to the Markdown files. markdownlint-cli2's
 * default formatter prints to stderr, which adapters do not capture; this one
 * prints one JSON line to stdout. It is ReleaseReady code, not customer code.
 */
export const markdownlintFormatter = `export default function outputFormatter(options) {
  const rows = options.results.map((r) => ({
    file: r.fileName,
    line: r.lineNumber,
    rules: r.ruleNames,
    description: r.ruleDescription,
    range: r.errorRange ?? null,
  }));
  options.logMessage(JSON.stringify(rows));
}
`;
export const markdownlintConfig = `${JSON.stringify({
  config: { default: true },
  gitignore: false,
  noBanner: true,
  noProgress: true,
  outputFormatters: [['./.rr-formatter.mjs']],
})}\n`;
/** Files the bundled run adds to the workspace; project config of the same names is never copied. */
export const markdownlintSupportFiles: Readonly<Record<string, string>> =
  Object.freeze({
    '.markdownlint-cli2.jsonc': markdownlintConfig,
    '.rr-formatter.mjs': markdownlintFormatter,
  });
/** markdownlint's only native level is an error; it is recorded as `error`. */
export function parseMarkdownlint(
  stdout: string,
  files: ReadonlySet<string>,
): ParsedOutput {
  const root = json(stdout.trim());
  if (!Array.isArray(root)) throw new TypeError('markdownlint output');
  return {
    findings: toFindings(
      root.map((item: unknown): RawFinding => {
        if (!isRec(item) || !Array.isArray(item.rules))
          throw new TypeError('markdownlint item');
        const range = Array.isArray(item.range) ? item.range : [];
        const column = clampLine(range[0]);
        return {
          engine: 'markdownlint',
          rule: rule(item.rules.filter((n) => typeof n === 'string').join('/')),
          severity: 'error',
          path: knownPath(item.file, files),
          line: clampLine(item.line),
          column,
          endColumn: column + clampLine(range[1], 0),
          message: str(item.description, 'markdownlint finding'),
        };
      }),
    ),
  };
}

/** Project-owned configuration that must never reach an engine run. */
export const lintConfigFile =
  /(?:^|\/)(?:\.hadolint\.ya?ml|\.tflint\.hcl|\.yamllint(?:\.ya?ml)?|\.markdownlint(?:-cli2)?\.[A-Za-z]+|\.markdownlintignore)$/;
export const dockerfilePath =
  /(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[A-Za-z0-9_-]+)?$/;
export const isDockerfile = (p: string): boolean =>
  dockerfilePath.test(p) && !p.endsWith('.dockerignore');
export const isTerraformFile = (p: string): boolean =>
  p.endsWith('.tf') && !lintConfigFile.test(p);
export const isYamlFile = (p: string): boolean =>
  /\.ya?ml$/.test(p) && !lintConfigFile.test(p);
export const isMarkdownFile = (p: string): boolean =>
  /\.(?:md|markdown)$/.test(p) && !lintConfigFile.test(p);

interface Common {
  executable: string;
  versionOutput: string;
  files: ReadonlySet<string>;
}
const base = (c: Common) => ({
  executable: c.executable,
  versionOutput: c.versionOutput,
  versionArgs: ['--version'] as readonly string[],
});

/** hadolint takes explicit file arguments (at most 32 per run); chunk upstream. */
export function hadolintAdapter(c: Common): ScannerAdapter {
  return {
    ...base(c),
    engine: { id: 'hadolint', version: hadolintPin.version },
    rulesetVersion: 'hadolint-bundled',
    configVersion: 'hadolint-default-json-v1',
    executableSha256: hadolintPin.sha256,
    fixedArgs: ['--no-fail', '--no-color', '--format', 'json'],
    allowedArgs: [...c.files],
    successExitCodes: [0],
    parse: (stdout) => parseHadolint(stdout, c.files),
  };
}
/** tflint: bundled terraform ruleset only; `--init` is never allowed. */
export function tflintAdapter(c: Common): ScannerAdapter {
  return {
    ...base(c),
    engine: { id: 'tflint', version: tflintPin.version },
    rulesetVersion: 'tflint-terraform-bundled',
    configVersion: 'tflint-default-json-v1',
    executableSha256: tflintPin.sha256,
    fixedArgs: ['--recursive', '--format', 'json'],
    allowedArgs: [],
    // 0: clean, 2: issues found. 1 is an engine error.
    successExitCodes: [0, 2],
    parse: (stdout) => parseTflint(stdout, c.files),
  };
}
/** yamllint: the `default` preset, selected explicitly so no project file can apply. */
export function yamllintAdapter(c: Common): ScannerAdapter {
  return {
    ...base(c),
    engine: { id: 'yamllint', version: yamllintPin.version },
    rulesetVersion: 'yamllint-default',
    configVersion: 'yamllint-default-parsable-v1',
    fixedArgs: ['-d', 'default', '-f', 'parsable', '.'],
    allowedArgs: [],
    // 0: clean, 1: errors, 2: warnings only.
    successExitCodes: [0, 1, 2],
    parse: (stdout) => parseYamllint(stdout, c.files),
  };
}
/**
 * markdownlint-cli2 runs under `node` (the executable) with the pinned entry
 * script; the version is read from the package's own package.json.
 */
export function markdownlintAdapter(c: {
  node: string;
  script: string;
  packageJson: string;
  files: ReadonlySet<string>;
}): ScannerAdapter {
  return {
    engine: { id: 'markdownlint', version: markdownlintPin.version },
    rulesetVersion: `markdownlint-${markdownlintPin.engineVersion}-default`,
    configVersion: 'markdownlint-cli2-default-json-v1',
    executable: c.node,
    versionArgs: [
      '-p',
      `JSON.parse(require('node:fs').readFileSync(${JSON.stringify(c.packageJson)},'utf8')).version`,
    ],
    versionOutput: markdownlintPin.version,
    fixedArgs: [
      c.script,
      '**/*.{md,markdown}',
      '.*/**/*.{md,markdown}',
      '#**/node_modules',
    ],
    allowedArgs: [],
    // 0: clean, 1: rule violations.
    successExitCodes: [0, 1],
    parse: (stdout) => parseMarkdownlint(stdout, c.files),
  };
}
