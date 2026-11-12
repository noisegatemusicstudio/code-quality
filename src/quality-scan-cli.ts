import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  buildReport,
  decide,
  isSeverity,
  parseBaseline,
  parseOsvMode,
  parseScanners,
  renderSummary,
  type EngineResult,
} from './quality-scan.js';
import { buildManifest, ManifestError } from './quality-manifest.js';
import {
  applyGitleaksExceptions,
  installEngine,
  installableEngines,
  parseExceptions,
  runEngines,
  scopeFromEnvironment,
} from './quality-scan-run.js';

const exec = promisify(execFile);

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
  const failOn = option(args, 'fail-on-severity') ?? 'high';
  if (unknown.length || !isSeverity(failOn)) {
    process.stderr.write(
      `invalid input: ${unknown.length ? `unknown scanners ${unknown.join(', ')}` : `fail-on-severity ${failOn}`}\n`,
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
  // Reviewed, time-bounded gitleaks exceptions live in the scanned repository.
  const exceptionsFile = resolve(
    repo,
    option(args, 'exceptions') ?? 'quality-exceptions.json',
  );
  let exceptions: ReturnType<typeof parseExceptions> = [];
  try {
    exceptions = parseExceptions(await readFile(exceptionsFile, 'utf8'));
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') {
      process.stderr.write('invalid input: exceptions file is malformed\n');
      return 2;
    }
  }
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
  const decision = decide(results, {
    enforce,
    failOnSeverity: failOn,
  });
  const summary = renderSummary({ commitSha, results, decision, baseline });
  await mkdir(join(out, 'envelopes'), { recursive: true });
  await writeFile(
    join(out, 'report.json'),
    JSON.stringify(
      buildReport({
        commitSha,
        repository: process.env.GITHUB_REPOSITORY ?? 'local',
        results,
        decision,
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
