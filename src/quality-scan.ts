import type { AdapterEnvelope, AdapterFinding } from './adapter-envelope.js';
import {
  isDockerfile,
  isMarkdownFile,
  isTerraformFile,
  isYamlFile,
} from './lint-adapters.js';
import { isJavaFile } from './java-adapters.js';
import { renderLanguages, type LanguageReport } from './language-detection.js';

/** Engines the reusable `quality-scan` workflow can run, in report order. */
export const engineIds = [
  'eslint',
  'gitleaks',
  'osv',
  'trivy',
  'semgrep',
  'jscpd',
  'ruff',
  'mypy',
  'pmd',
  'checkstyle',
  'spotbugs',
  'shellcheck',
  'shfmt',
  'actionlint',
  'zizmor',
  'hadolint',
  'tflint',
  'yamllint',
  'markdownlint',
] as const;
export type EngineId = (typeof engineIds)[number];
export type EngineStatus = 'completed' | 'failed' | 'incomplete' | 'skipped';
export const severityLevels = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
] as const;
export type Severity = (typeof severityLevels)[number];

export interface EngineResult {
  engine: EngineId;
  status: EngineStatus;
  /** Why the engine did not complete cleanly. Required unless `completed`. */
  reason?: string;
  /** For skipped engines: whether skipping is by design or an environment gap. */
  skipKind?: 'not-selected' | 'not-applicable' | 'unavailable';
  version?: string;
  findings: AdapterFinding[];
  /** Validated adapter envelope, when the engine produced one. */
  envelope?: AdapterEnvelope | null;
  /** Findings removed from `findings` by a reviewed, unexpired exception. */
  excepted?: number;
  /** What this engine sent off the runner, shown in the job summary. */
  disclosure?: string;
}

export type OsvMode = 'online' | 'offline' | 'off';
/** Parse the `osv-mode` input: empty means the default `online`. */
export function parseOsvMode(value: string | undefined): OsvMode | undefined {
  const mode = (value ?? '').trim().toLowerCase();
  if (mode === '') return 'online';
  return mode === 'online' || mode === 'offline' || mode === 'off'
    ? mode
    : undefined;
}

const toList = (value: string): string[] =>
  value
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part !== '');

/** `all` (or empty) selects every engine; unknown names are returned, never ignored. */
export function parseScanners(input: string): {
  selected: EngineId[];
  unknown: string[];
} {
  const names = toList(input);
  if (names.length === 0 || names.includes('all'))
    return {
      selected: [...engineIds],
      unknown: names.filter((n) => n !== 'all' && !isEngine(n)),
    };
  const unknown = names.filter((n) => !isEngine(n));
  return {
    selected: engineIds.filter((id) => names.includes(id)),
    unknown,
  };
}
const isEngine = (value: string): value is EngineId =>
  (engineIds as readonly string[]).includes(value);

const eslintExtension = /\.(?:[cm]?[jt]s)$/;
const semgrepExtension = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const pythonExtension = /\.pyi?$/;
const shellFile = /\.(?:sh|bash|ksh)$/;
const workflowFile = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const iacFile =
  /(?:\.(?:tf|tfvars|tf\.json|ya?ml|json|toml)|(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[A-Za-z0-9_-]+)?)$/;
/** Lockfiles osv-scanner understands; the offline adapter itself is npm-only. */
export const supportedLockfiles: readonly string[] = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'Pipfile.lock',
  'Cargo.lock',
  'go.mod',
  'Gemfile.lock',
  'composer.lock',
  'pom.xml',
  'gradle.lockfile',
  'packages.lock.json',
  'pubspec.lock',
  'mix.lock',
];
const baseName = (path: string): string =>
  path.slice(path.lastIndexOf('/') + 1);

export interface Applicability {
  applicable: boolean;
  reason?: string;
}
/** Which engines have anything to look at in a list of committed paths. */
export function detectApplicability(
  paths: readonly string[],
): Record<EngineId, Applicability> {
  const some = (test: (path: string) => boolean): boolean => paths.some(test);
  const yes: Applicability = { applicable: true };
  const no = (reason: string): Applicability => ({ applicable: false, reason });
  return {
    eslint: some((p) => eslintExtension.test(p))
      ? yes
      : no('no JavaScript or TypeScript files'),
    gitleaks: yes,
    jscpd: yes,
    osv: some((p) => supportedLockfiles.includes(baseName(p)))
      ? yes
      : no('no supported lockfile'),
    trivy: some((p) => iacFile.test(p))
      ? yes
      : no('no IaC or configuration files'),
    semgrep: some((p) => semgrepExtension.test(p))
      ? yes
      : no('no JavaScript or TypeScript files'),
    ruff: some((p) => pythonExtension.test(p)) ? yes : no('no Python files'),
    mypy: some((p) => pythonExtension.test(p)) ? yes : no('no Python files'),
    pmd: some((p) => isJavaFile(p)) ? yes : no('no Java files'),
    checkstyle: some((p) => isJavaFile(p)) ? yes : no('no Java files'),
    spotbugs: some((p) => isJavaFile(p)) ? yes : no('no Java files'),
    shellcheck: some((p) => shellFile.test(p)) ? yes : no('no shell scripts'),
    shfmt: some((p) => shellFile.test(p)) ? yes : no('no shell scripts'),
    actionlint: some((p) => workflowFile.test(p))
      ? yes
      : no('no GitHub Actions workflows'),
    zizmor: some((p) => workflowFile.test(p))
      ? yes
      : no('no GitHub Actions workflows'),
    hadolint: some(isDockerfile) ? yes : no('no Dockerfile or Containerfile'),
    tflint: some(isTerraformFile) ? yes : no('no Terraform (.tf) files'),
    yamllint: some(isYamlFile) ? yes : no('no YAML files'),
    markdownlint: some(isMarkdownFile) ? yes : no('no Markdown files'),
  };
}

/**
 * Normalised severity used only for the enforce threshold. Engine-native
 * labels stay untouched in the findings. An unrecognised label is ranked
 * `high` so that it fails closed instead of slipping under the threshold.
 */
export function normaliseSeverity(
  engine: EngineId,
  nativeSeverity: string,
): Severity {
  const label = nativeSeverity.toLowerCase();
  if (engine === 'gitleaks') return 'critical';
  if (engine === 'jscpd') return 'info';
  // ShellCheck levels. shfmt only reports formatting. actionlint reports
  // workflow errors without a native level. zizmor labels go through the table.
  if (engine === 'shellcheck')
    return label === 'error'
      ? 'high'
      : label === 'warning'
        ? 'medium'
        : label === 'info'
          ? 'low'
          : label === 'style'
            ? 'info'
            : 'high';
  if (engine === 'shfmt') return 'info';
  if (engine === 'actionlint') return 'medium';
  if (engine === 'eslint')
    return label === 'error' ? 'medium' : label === 'warn' ? 'low' : 'high';
  if (engine === 'semgrep')
    return label === 'error'
      ? 'high'
      : label === 'warning'
        ? 'medium'
        : label === 'info'
          ? 'low'
          : 'high';
  if (engine === 'ruff') {
    // Ruff has no severity; the adapter labels each finding by rule family.
    const ruff: Record<string, Severity> = {
      error: 'high',
      security: 'medium',
      bug: 'medium',
      convention: 'low',
    };
    return ruff[label] ?? 'high';
  }
  // Lint engines: errors are medium, warnings low, notices and style info.
  // markdownlint has no native levels (recorded as `error`), so it ranks low.
  if (engine === 'markdownlint') return label === 'error' ? 'low' : 'high';
  if (
    engine === 'hadolint' ||
    engine === 'tflint' ||
    engine === 'yamllint' ||
    engine === 'pmd' ||
    engine === 'checkstyle'
  ) {
    // PMD reports SARIF levels (error, warning, note); Checkstyle error, warning, info.
    const lint: Record<string, Severity> = {
      error: 'medium',
      warning: 'low',
      note: 'info',
      notice: 'info',
      info: 'info',
      style: 'info',
    };
    return lint[label] ?? 'high';
  }
  const table: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    moderate: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info',
  };
  return table[label] ?? 'high';
}
export const isSeverity = (value: string): value is Severity =>
  (severityLevels as readonly string[]).includes(value);
const rank = (severity: Severity): number => severityLevels.indexOf(severity);

export interface Decision {
  mode: 'advisory' | 'enforce';
  threshold: Severity;
  /** Engines that are failed or incomplete. */
  broken: EngineId[];
  /** Findings at or above the threshold. */
  blocking: number;
  /** Whether enforce mode would fail this run, even when advisory. */
  wouldFail: boolean;
  /** Process exit code: nonzero only in enforce mode. */
  exitCode: 0 | 1;
  reasons: string[];
}

/** The enforce decision. Advisory mode always exits 0 but still computes the verdict. */
export function decide(
  results: readonly EngineResult[],
  options: { enforce: boolean; failOnSeverity: Severity },
): Decision {
  const broken = results
    .filter((r) => r.status === 'failed' || r.status === 'incomplete')
    .map((r) => r.engine);
  let blocking = 0;
  for (const result of results)
    if (result.status === 'completed' || result.status === 'incomplete')
      for (const finding of result.findings)
        if (
          rank(normaliseSeverity(result.engine, finding.nativeSeverity)) >=
          rank(options.failOnSeverity)
        )
          blocking += 1;
  const reasons: string[] = [];
  if (broken.length) reasons.push(`failed or incomplete: ${broken.join(', ')}`);
  if (blocking)
    reasons.push(
      `${String(blocking)} finding(s) at or above ${options.failOnSeverity}`,
    );
  const wouldFail = reasons.length > 0;
  return {
    mode: options.enforce ? 'enforce' : 'advisory',
    threshold: options.failOnSeverity,
    broken,
    blocking,
    wouldFail,
    exitCode: options.enforce && wouldFail ? 1 : 0,
    reasons,
  };
}

export interface Baseline {
  /** Fingerprints per engine, only for engines that completed in the baseline. */
  engines: Partial<Record<EngineId, Set<string>>>;
}
/** Parse a previous `report.json`; anything unusable means "no baseline". */
export function parseBaseline(text: string): Baseline | null {
  try {
    const parsed: unknown = JSON.parse(text);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('engines' in parsed) ||
      !Array.isArray(parsed.engines)
    )
      return null;
    const engines: Baseline['engines'] = {};
    for (const entry of parsed.engines as unknown[]) {
      if (typeof entry !== 'object' || entry === null) continue;
      const { engine, status, findings } = entry as Record<string, unknown>;
      if (
        typeof engine !== 'string' ||
        !isEngine(engine) ||
        status !== 'completed' ||
        !Array.isArray(findings)
      )
        continue;
      engines[engine] = new Set(
        findings.flatMap((f: unknown) =>
          typeof f === 'object' &&
          f !== null &&
          'fingerprint' in f &&
          typeof f.fingerprint === 'string'
            ? [f.fingerprint]
            : [],
        ),
      );
    }
    return { engines };
  } catch {
    return null;
  }
}
/** Findings of an engine that are not in the baseline; `null` without a comparable baseline. */
export function newFindings(
  result: EngineResult,
  baseline: Baseline | null,
): AdapterFinding[] | null {
  const known = baseline?.engines[result.engine];
  if (!known || result.status !== 'completed') return null;
  return result.findings.filter((f) => !known.has(f.fingerprint));
}

/** The JSON artefact: stable, small, and enough to be a later baseline. */
export function buildReport(input: {
  commitSha: string;
  repository: string;
  results: readonly EngineResult[];
  decision: Decision;
  languages?: readonly LanguageReport[];
  newCode?: unknown;
}): unknown {
  return {
    schemaVersion: 1,
    repository: input.repository,
    commitSha: input.commitSha,
    decision: input.decision,
    languages: input.languages ?? [],
    newCode: input.newCode ?? null,
    engines: input.results.map((r) => ({
      engine: r.engine,
      status: r.status,
      reason: r.reason,
      skipKind: r.skipKind,
      version: r.version,
      findingCount: r.findings.length,
      findings: r.findings,
    })),
  };
}

/** Human text for an unknown measure's reason. */
export const unknownText = (reason: string): string =>
  reason === 'no-report'
    ? 'no coverage report supplied'
    : reason === 'no-base-ref'
      ? 'no comparison base (not a pull request and no base ref given)'
      : reason.replace(/-/g, ' ');

/** Escape text for a Markdown table cell so engine output cannot inject markup. */
export const mdEscape = (value: string): string =>
  value
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\\`*_{}[\]<>()#+!|~&]/g, (c) => `\\${c}`)
    .slice(0, 300);

const topRules = (
  findings: readonly AdapterFinding[],
  count: number,
): string => {
  const counts = new Map<string, number>();
  for (const f of findings)
    counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1);
  return [...counts]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'en'))
    .slice(0, count)
    .map(([rule, n]) => `${mdEscape(rule)} (${String(n)})`)
    .join(', ');
};

/** Job summary Markdown. Skipped, failed and incomplete engines are never shown as clean. */
export function renderSummary(input: {
  commitSha: string;
  results: readonly EngineResult[];
  decision: Decision;
  baseline: Baseline | null;
  exceptions?: {
    source: 'base-commit' | 'scanned-commit';
    pending: readonly { fingerprint: string; ruleId: string; path: string }[];
    pendingError?: string;
  };
  languages?: readonly LanguageReport[];
  newCode?: {
    baseSource: string;
    baseSha: string | null;
    measures: readonly {
      id: string;
      state: string;
      percent?: number;
      numerator?: number;
      denominator?: number;
      reason?: string;
    }[];
  };
}): string {
  const { results, decision, baseline } = input;
  const lines: string[] = [
    '## Quality scan',
    '',
    `Commit \`${input.commitSha.slice(0, 12)}\` · mode **${decision.mode}** · fail-on-severity **${decision.threshold}**`,
    '',
    baseline
      ? 'Baseline: provided; "new" counts findings absent from it.'
      : 'Baseline: none, so no new-vs-baseline split is available.',
    '',
    '| Engine | Status | Findings | New | Notes |',
    '| --- | --- | ---: | ---: | --- |',
  ];
  for (const r of results) {
    const fresh = newFindings(r, baseline);
    const ran = r.status === 'completed' || r.status === 'incomplete';
    const notes = [
      r.status === 'skipped' && r.skipKind ? `skipped (${r.skipKind})` : '',
      r.reason ? mdEscape(r.reason) : '',
      r.excepted ? `${String(r.excepted)} excepted (reviewed exception)` : '',
    ]
      .filter(Boolean)
      .join(': ');
    lines.push(
      `| ${r.engine}${r.version ? ` ${mdEscape(r.version)}` : ''} | ${r.status} | ${ran ? `${String(r.findings.length)}${r.status === 'incomplete' ? '+' : ''}` : '–'} | ${String(fresh ? fresh.length : '–')} | ${notes} |`,
    );
  }
  const ex = input.exceptions;
  if (ex?.source === 'base-commit') {
    lines.push(
      '',
      'Exceptions: read from the pull request base commit only; exceptions added in this pull request take effect after merge.',
    );
    if (ex.pending.length || ex.pendingError) {
      lines.push('', '### Exceptions pending review', '');
      if (ex.pendingError) lines.push(`- ${mdEscape(ex.pendingError)}`);
      for (const e of ex.pending)
        lines.push(
          `- \`${mdEscape(e.ruleId)}\` in \`${mdEscape(e.path)}\` (${mdEscape(e.fingerprint.slice(0, 19))}…): added or changed in this pull request, not suppressing anything yet`,
        );
    }
  }
  lines.push('', ...renderLanguages(input.languages ?? []));
  const notClean = results.filter((r) => r.status !== 'completed');
  if (notClean.length) {
    lines.push(
      '',
      '### Not a clean result',
      '',
      'These engines did not complete. "–" above means no result, not zero findings.',
      '',
      ...notClean.map(
        (r) =>
          `- **${r.engine}**: ${r.status}${r.reason ? ` (${mdEscape(r.reason)})` : ''}`,
      ),
    );
  }
  const withFindings = results.filter((r) => r.findings.length > 0);
  if (withFindings.length) {
    lines.push('', '### Top rules', '');
    for (const r of withFindings)
      lines.push(`- **${r.engine}**: ${topRules(r.findings, 5)}`);
  }
  const disclosed = results.filter((r) => r.disclosure);
  if (disclosed.length)
    lines.push(
      '',
      '### Data sent off the runner',
      '',
      ...disclosed.map(
        (r) => `- **${r.engine}**: ${mdEscape(r.disclosure ?? '')}`,
      ),
    );
  if (input.newCode) {
    const nc = input.newCode;
    lines.push(
      '',
      '### New-code measures',
      '',
      nc.baseSha
        ? `Compared with \`${nc.baseSha.slice(0, 12)}\` (${nc.baseSource === 'pull-request-base' ? 'pull request base' : 'configured base ref'}).`
        : 'No comparison base, so new code could not be determined.',
      '',
      '| Measure | Result | Lines |',
      '| --- | --- | --- |',
      ...nc.measures.map(
        (m) =>
          `| ${m.id} | ${m.state === 'known' ? `${(Math.round((m.percent ?? 0) * 100) / 100).toString()}%` : `unknown: ${mdEscape(unknownText(m.reason ?? ''))}`} | ${m.state === 'known' ? `${String(m.numerator)}/${String(m.denominator)}` : '–'} |`,
      ),
    );
  }
  lines.push(
    '',
    '### Gate',
    '',
    decision.wouldFail
      ? `Would fail in enforce mode: ${decision.reasons.map(mdEscape).join('; ')}.`
      : 'Would pass in enforce mode.',
    decision.mode === 'advisory'
      ? 'Advisory mode: this job reports findings but does not fail the pull request.'
      : decision.exitCode === 1
        ? 'Enforce mode: this job fails.'
        : 'Enforce mode: this job passes.',
    '',
  );
  return lines.join('\n');
}
