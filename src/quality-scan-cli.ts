import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  buildReport,
  isSeverity,
  parseBaseline,
  parseOsvMode,
  parseScanners,
  renderSummary,
  type EngineResult,
} from './quality-scan.js';
import {
  buildLocalManifest,
  buildManifest,
  ManifestError,
  manifestApplies,
  validateLocalIdentity,
  type LocalIdentityFlags,
} from './quality-manifest.js';
import { detectLanguages } from './language-detection.js';
import { resolveJava } from './java-runtime.js';
import { tsconfigPathProblem } from './eslint-tsconfig.js';
import { loadGate, decideWithGate, gateMeasuresFrom } from './quality-gate.js';
import { computeNewCode, readCoverageReport } from './new-code.js';
import {
  applyGitleaksExceptions,
  ExceptionSourceError,
  loadExceptions,
  type ExceptionLoad,
  installEngine,
  installableEngines,
  installOnDemand,
  runEngines,
  scopeFromEnvironment,
  trackedPaths,
} from './quality-scan-run.js';

const exec = promisify(execFile);

async function readIfPresent(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') return undefined;
    throw error;
  }
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
}

/**
 * `install --dir D --scanners LIST` downloads and verifies pinned engines and
 * writes `D/install.json`. `run ...` scans the checked-out commit and writes
 * the report, envelopes and Markdown summary. Install failures never abort:
 * they are recorded and surface as failed engines in `run`.
 */
async function install(args: string[]): Promise<number> {
  const dir = resolve(option(args, 'dir') ?? '');
  const { selected, unknown } = parseScanners(option(args, 'scanners') ?? '');
  if (unknown.length) {
    process.stderr.write(`unknown scanners: ${unknown.join(', ')}\n`);
    return 2;
  }
  const record: {
    tools: Record<string, string>;
    errors: Record<string, string>;
  } = { tools: {}, errors: {} };
  // With --repo, engines in `installOnDemand` download only when the checkout
  // has files they scan; without it they install like every other engine.
  const repoOption = option(args, 'repo');
  const tracked =
    repoOption === undefined
      ? undefined
      : await trackedPaths(resolve(repoOption));
  for (const id of installableEngines.filter((e) => selected.includes(e))) {
    const wanted = installOnDemand[id];
    if (wanted && tracked && !tracked.some(wanted)) {
      process.stdout.write(`skipped ${id}: nothing to scan\n`);
      continue;
    }
    try {
      record.tools[id] = await installEngine(id, dir);
      process.stdout.write(`installed ${id}\n`);
    } catch (error) {
      record.errors[id] =
        error instanceof Error ? error.message : 'install failed';
      process.stdout.write(`FAILED ${id}: ${record.errors[id]}\n`);
    }
  }
  await writeFile(join(dir, 'install.json'), JSON.stringify(record, null, 2));
  return 0;
}

const localIdentityFlags = [
  'repository',
  'ref',
  'event',
  'run-id',
  'run-attempt',
];

/**
 * `--manifest local` selects an explicit, flag-given identity for runs outside
 * GitHub Actions. Returns the validated flags, undefined when local mode is
 * off, or an error message (exit 2). Identity flags without `--manifest local`
 * are refused rather than ignored, and local mode never runs under Actions.
 */
function localMode(
  args: string[],
  environment: NodeJS.ProcessEnv,
): { flags?: LocalIdentityFlags; error?: string } {
  const mode = option(args, 'manifest');
  if (args.includes('--manifest') && mode !== 'local')
    return { error: '--manifest must be local' };
  if (mode !== 'local') {
    const stray = localIdentityFlags.find((n) => args.includes(`--${n}`));
    return stray ? { error: `--${stray} requires --manifest local` } : {};
  }
  if (environment.GITHUB_ACTIONS === 'true')
    return { error: '--manifest local cannot be used on GitHub Actions' };
  const flags: LocalIdentityFlags = {
    repository: option(args, 'repository'),
    ref: option(args, 'ref'),
    event: option(args, 'event'),
    runId: option(args, 'run-id'),
    runAttempt: option(args, 'run-attempt'),
  };
  try {
    validateLocalIdentity(flags);
  } catch (error) {
    if (!(error instanceof ManifestError)) throw error;
    return { error: error.message };
  }
  return { flags };
}

async function run(args: string[]): Promise<number> {
  const repo = resolve(option(args, 'repo') ?? '.');
  const out = resolve(option(args, 'out') ?? 'quality-scan');
  const { selected, unknown } = parseScanners(option(args, 'scanners') ?? '');
  const failOnOption = option(args, 'fail-on-severity');
  if (
    unknown.length ||
    (failOnOption !== undefined && !isSeverity(failOnOption))
  ) {
    process.stderr.write(
      `invalid input: ${unknown.length ? `unknown scanners ${unknown.join(', ')}` : `fail-on-severity ${failOnOption ?? ''}`}\n`,
    );
    return 2;
  }
  const osvMode = parseOsvMode(option(args, 'osv-mode'));
  if (!osvMode) {
    process.stderr.write(
      'invalid input: osv-mode must be online, offline or off\n',
    );
    return 2;
  }
  const local = localMode(args, process.env);
  if (local.error !== undefined) {
    process.stderr.write(`invalid input: ${local.error}\n`);
    return 2;
  }
  // Optional type-aware ESLint. An empty value means "not requested".
  const tsconfigOption = option(args, 'eslint-tsconfig');
  const eslintTsconfig = tsconfigOption === '' ? undefined : tsconfigOption;
  const tsconfigProblem =
    eslintTsconfig === undefined
      ? undefined
      : tsconfigPathProblem(eslintTsconfig);
  if (tsconfigProblem) {
    process.stderr.write(`invalid input: ${tsconfigProblem.detail}\n`);
    return 2;
  }
  const enforce = option(args, 'enforce') === 'true';
  // Reviewed, time-bounded gitleaks exceptions. Pull requests use the BASE
  // commit's file only; see loadExceptions.
  const exceptionsPath =
    option(args, 'exceptions') ?? 'quality-exceptions.json';
  const exceptionsFile = resolve(repo, exceptionsPath);
  let loaded: ExceptionLoad;
  try {
    loaded = await loadExceptions({
      environment: process.env,
      readEvent: (path) => readFile(path, 'utf8'),
      readHead: () => readIfPresent(exceptionsFile),
      readBase: async (baseSha) => {
        try {
          await exec('git', [
            '-C',
            repo,
            'cat-file',
            '-e',
            `${baseSha}^{commit}`,
          ]);
        } catch {
          throw new Error('base commit missing');
        }
        try {
          await exec('git', [
            '-C',
            repo,
            'cat-file',
            '-e',
            `${baseSha}:${exceptionsPath}`,
          ]);
        } catch {
          return undefined;
        }
        return (
          await exec('git', [
            '-C',
            repo,
            'show',
            `${baseSha}:${exceptionsPath}`,
          ])
        ).stdout;
      },
    });
  } catch (error) {
    process.stderr.write(
      `invalid input: ${error instanceof ExceptionSourceError ? error.message : 'exceptions file is malformed'}\n`,
    );
    return 2;
  }
  const exceptions = loaded.exceptions;
  let installed: {
    tools?: Record<string, string>;
    errors?: Record<string, string>;
  } = {};
  const toolsDir = option(args, 'tools-dir');
  if (toolsDir) {
    try {
      installed = JSON.parse(
        await readFile(join(toolsDir, 'install.json'), 'utf8'),
      ) as typeof installed;
    } catch {
      installed = {};
    }
  }
  const tools: Record<string, string> = { ...installed.tools };
  const semgrep = option(args, 'semgrep');
  const errors: Record<string, string> = { ...installed.errors };
  if (semgrep) tools.semgrep = resolve(semgrep);
  else
    errors.semgrep = option(args, 'semgrep-error') ?? 'semgrep not installed';
  const yamllint = option(args, 'yamllint');
  if (yamllint) tools.yamllint = resolve(yamllint);
  else
    errors.yamllint =
      option(args, 'yamllint-error') ?? 'yamllint not installed';
  const java = resolveJava(option(args, 'java'), process.env);
  if (java.java) tools.java = java.java;
  else
    for (const id of ['pmd', 'checkstyle'])
      errors[id] ??= java.error ?? 'no Java runtime';
  const markdownlint = option(args, 'markdownlint-cli2');
  if (markdownlint) tools.markdownlint = resolve(markdownlint);
  else
    errors.markdownlint =
      option(args, 'markdownlint-cli2-error') ??
      'markdownlint-cli2 not installed';
  const { stdout: head } = await exec('git', ['-C', repo, 'rev-parse', 'HEAD']);
  const commitSha = head.trim();
  const gitExecutable = (
    await exec('sh', ['-c', 'command -v git'])
  ).stdout.trim();
  const scanned: EngineResult[] = await runEngines({
    repo,
    scope: scopeFromEnvironment(
      process.env,
      commitSha,
      local.flags?.repository,
    ),
    selected,
    tools,
    installErrors: errors,
    gitExecutable,
    rulesDirectory: resolve(
      option(args, 'rules') ?? join(repo, 'rules/semgrep'),
    ),
    osvMode,
    ...(eslintTsconfig === undefined ? {} : { eslintTsconfig }),
  });
  const now = new Date();
  const results = scanned.map((r) =>
    applyGitleaksExceptions(r, exceptions, now),
  );
  let baseline = null;
  const baselinePath = option(args, 'baseline');
  if (baselinePath) {
    try {
      baseline = parseBaseline(
        await readFile(resolve(repo, baselinePath), 'utf8'),
      );
    } catch {
      baseline = null;
    }
  }
  // The versioned gate file is the policy; an explicit --fail-on-severity only
  // overrides its new-issue threshold.
  let gate;
  try {
    gate = await loadGate(option(args, 'gate'));
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : 'quality gate unreadable'}\n`,
    );
    return 2;
  }
  if (failOnOption !== undefined && isSeverity(failOnOption))
    gate = { ...gate, newIssues: { failOnSeverity: failOnOption } };
  const languages = detectLanguages(await trackedPaths(repo));
  // New-code measures: base from the PR event (pull requests) or --base-ref,
  // read from local git only. The scan never runs tests; coverage is a
  // caller-supplied report.
  const coveragePath = option(args, 'coverage');
  let coverageReport: string | undefined;
  if (coveragePath) {
    try {
      coverageReport = await readCoverageReport(resolve(coveragePath));
    } catch {
      process.stderr.write('invalid input: coverage report unreadable\n');
      return 2;
    }
  }
  const newCode = await computeNewCode({
    git: gitExecutable,
    repo,
    headSha: commitSha,
    env: process.env,
    readEvent: (path) => readFile(path, 'utf8'),
    baseRef: option(args, 'base-ref'),
    tracked: await trackedPaths(repo),
    ...(coverageReport === undefined ? {} : { coverageReport }),
    jscpd: results.find((r) => r.engine === 'jscpd'),
  });
  const decision = decideWithGate(results, {
    enforce,
    gate,
    baseline,
    measures: gateMeasuresFrom(newCode.measures),
  });
  const summary = renderSummary({
    commitSha,
    results,
    decision,
    baseline,
    languages,
    exceptions: loaded,
    newCode,
  });
  await mkdir(join(out, 'envelopes'), { recursive: true });
  await writeFile(
    join(out, 'report.json'),
    JSON.stringify(
      buildReport({
        commitSha,
        repository:
          local.flags?.repository ?? process.env.GITHUB_REPOSITORY ?? 'local',
        results,
        decision,
        languages,
        newCode,
      }),
      null,
      2,
    ),
  );
  const envelopeFiles = new Map<string, string>();
  for (const r of results)
    if (r.envelope) {
      envelopeFiles.set(r.engine, `envelopes/${r.engine}.json`);
      await writeFile(
        join(out, envelopeFiles.get(r.engine) ?? ''),
        JSON.stringify(r.envelope, null, 2),
      );
    }
  await writeFile(join(out, 'summary.md'), summary);
  if (process.env.GITHUB_STEP_SUMMARY)
    await appendFile(process.env.GITHUB_STEP_SUMMARY, summary + '\n');
  process.stdout.write(summary + '\n');
  // The portal contract: required on GitHub Actions, where the identity comes
  // from, and in local mode, where it comes from validated flags. A manual
  // workflow_dispatch run has no identity the portal can trust: it writes no
  // manifest and its result is the gate decision alone.
  const actions = !local.flags && process.env.GITHUB_ACTIONS === 'true';
  if (actions && !manifestApplies(process.env))
    process.stderr.write(
      'manifest skipped: manual workflow_dispatch run; the portal does not ingest it\n',
    );
  else if (local.flags || actions) {
    try {
      const manifestInput = {
        commitSha,
        codeQualityRef: option(args, 'code-quality-ref') ?? '',
        results,
        envelopeFiles,
        measures: newCode.measures,
      };
      const manifest = local.flags
        ? buildLocalManifest(local.flags, manifestInput)
        : buildManifest(process.env, manifestInput);
      await writeFile(
        join(out, 'manifest.json'),
        JSON.stringify(manifest, null, 2),
      );
    } catch (error) {
      if (!(error instanceof ManifestError)) throw error;
      process.stderr.write(`manifest invalid: ${error.message}\n`);
      return 2;
    }
  }
  return decision.exitCode;
}

const [command, ...rest] = process.argv.slice(2);
(command === 'install'
  ? install(rest)
  : command === 'run'
    ? run(rest)
    : Promise.resolve(2)
)
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(
      `quality-scan failed: ${error instanceof Error ? error.message : 'unknown'}\n`,
    );
    process.exitCode = 2;
  });
