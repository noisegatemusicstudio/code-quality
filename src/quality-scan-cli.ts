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
import { buildManifest, ManifestError } from './quality-manifest.js';
import { detectLanguages } from './language-detection.js';
import { loadGate, decideWithGate } from './quality-gate.js';
import {
  applyGitleaksExceptions,
  ExceptionSourceError,
  findJava,
  loadExceptions,
  type ExceptionLoad,
  installEngine,
  installableEngines,
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
  for (const id of installableEngines.filter((e) => selected.includes(e))) {
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
      `invalid input: ${unknown.length ? `unknown scanners ${unknown.join(', ')}` : `fail-on-severity ${failOnOption}`}\n`,
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
    scope: scopeFromEnvironment(process.env, commitSha),
    selected,
    tools,
    installErrors: errors,
    gitExecutable,
    rulesDirectory: resolve(
      option(args, 'rules') ?? join(repo, 'rules/semgrep'),
    ),
    osvMode,
    java: await findJava(process.env),
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
  const decision = decideWithGate(results, { enforce, gate, baseline });
  const summary = renderSummary({
    commitSha,
    results,
    decision,
    baseline,
    languages,
    exceptions: loaded,
  });
  await mkdir(join(out, 'envelopes'), { recursive: true });
  await writeFile(
    join(out, 'report.json'),
    JSON.stringify(
      buildReport({
        commitSha,
        repository: process.env.GITHUB_REPOSITORY ?? 'local',
        results,
        decision,
        languages,
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
  // The portal contract: required on GitHub Actions, where the identity comes from.
  if (process.env.GITHUB_ACTIONS === 'true') {
    try {
      const manifest = buildManifest(process.env, {
        commitSha,
        codeQualityRef: option(args, 'code-quality-ref') ?? '',
        results,
        envelopeFiles,
      });
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
