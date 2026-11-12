/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Runs synthetic engine output and fake executables through the hadolint, tflint, yamllint and markdownlint adapters via runAdapter, plus the severity table, applicability and language coverage; does not run any real lint engine, download one or read a real repository.
*/
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { EnvelopeScope } from '../src/adapter-envelope.js';
import { detectLanguages } from '../src/language-detection.js';
import {
  hadolintAdapter,
  isDockerfile,
  isMarkdownFile,
  isTerraformFile,
  isYamlFile,
  lintConfigFile,
  markdownlintAdapter,
  markdownlintSupportFiles,
  parseTflint,
  tflintAdapter,
  yamllintAdapter,
} from '../src/lint-adapters.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineId,
} from '../src/quality-scan.js';
import { runAdapter, type ScannerAdapter } from '../src/scanner-adapter.js';
import {
  hadolintPin,
  releaseAssets,
  tflintPin,
  yamllintPin,
} from '../src/scanner-pins.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'c'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const linux = { skip: process.platform !== 'linux' };
const dir = await mkdtemp(join(tmpdir(), 'lint-adapters-test-'));
/** Fake engine: prints the version for --version/-p, otherwise `output`, then exits with `code`. */
async function fake(name: string, output: string, code = 0, version = 'v1') {
  const path = join(dir, name);
  const body = `#!${process.execPath}
const a = process.argv.slice(2);
if (a[0] === '--version') { console.log(${JSON.stringify(version)}); process.exit(0); }
process.stdout.write(${JSON.stringify(output)});
process.exit(${String(code)});
`;
  await writeFile(path, body);
  await chmod(path, 0o755);
  return { path, sha: createHash('sha256').update(body).digest('hex') };
}
const unpin = (adapter: ScannerAdapter, sha: string): ScannerAdapter => ({
  ...adapter,
  executableSha256: sha,
});

const hadolintJson = JSON.stringify([
  {
    code: 'DL3006',
    column: 1,
    file: 'svc/Dockerfile',
    level: 'warning',
    line: 1,
    message: 'Always tag the version of an image explicitly',
  },
  {
    code: 'DL1000',
    column: 3,
    file: 'svc/Dockerfile',
    level: 'error',
    line: 4,
    message: 'unexpected token',
  },
]);

await test(
  'hadolint: native levels are kept and the real binary hash is enforced',
  linux,
  async () => {
    const { path, sha } = await fake('hadolint', hadolintJson);
    const files = new Set(['svc/Dockerfile']);
    const adapter = hadolintAdapter({
      executable: path,
      versionOutput: 'v1',
      files,
    });
    // A binary that is not the pinned one is refused before it runs.
    const refused = await runAdapter(adapter, {
      scope,
      files: { 'svc/Dockerfile': 'FROM alpine\n' },
      args: ['svc/Dockerfile'],
    });
    assert.equal(refused.status, 'failed');
    assert.equal(refused.reason, 'engine-version-mismatch');
    const ok = await runAdapter(unpin(adapter, sha), {
      scope,
      files: { 'svc/Dockerfile': 'FROM alpine\n' },
      args: ['svc/Dockerfile'],
    });
    assert.equal(ok.status, 'completed');
    assert.deepEqual(
      ok.findings.map((f) => [f.ruleId, f.nativeSeverity, f.path]),
      [
        ['DL3006', 'warning', 'svc/Dockerfile'],
        ['DL1000', 'error', 'svc/Dockerfile'],
      ],
    );
    // Only the declared Dockerfile arguments are accepted.
    const bad = await runAdapter(unpin(adapter, sha), {
      scope,
      files: { 'svc/Dockerfile': 'FROM alpine\n' },
      args: ['--config', '/etc/passwd'],
    });
    assert.equal(bad.status, 'skipped');
    assert.equal(bad.reason, 'invalid-request');
    assert.equal(adapter.fixedArgs.includes('--no-fail'), true);
  },
);

await test(
  'hadolint: output naming a file outside the input fails closed',
  linux,
  async () => {
    const { path, sha } = await fake('hadolint-bad', hadolintJson);
    const adapter = unpin(
      hadolintAdapter({
        executable: path,
        versionOutput: 'v1',
        files: new Set(['other/Dockerfile']),
      }),
      sha,
    );
    const result = await runAdapter(adapter, {
      scope,
      files: { 'other/Dockerfile': 'FROM alpine\n' },
      args: ['other/Dockerfile'],
    });
    assert.equal(result.status, 'failed');
    assert.equal(result.reason, 'invalid-output');
    assert.equal(result.findings.length, 0);
  },
);

const tflintJson = JSON.stringify({
  issues: [
    {
      rule: { name: 'terraform_required_version', severity: 'warning' },
      message: 'terraform "required_version" attribute is required',
      range: {
        filename: 'infra/main.tf',
        start: { line: 1, column: 1 },
        end: { line: 1, column: 1 },
      },
    },
  ],
  errors: [],
});

await test(
  'tflint: exit 2 means findings, bundled ruleset only, no init or plugin arguments',
  linux,
  async () => {
    const { path, sha } = await fake('tflint', tflintJson, 2);
    const files = new Set(['infra/main.tf']);
    const adapter = unpin(
      tflintAdapter({ executable: path, versionOutput: 'v1', files }),
      sha,
    );
    assert.equal(adapter.executableSha256, sha);
    assert.deepEqual(adapter.allowedArgs, []);
    assert.ok(!adapter.fixedArgs.some((a) => /init|config|plugin/.test(a)));
    const result = await runAdapter(adapter, {
      scope,
      files: { 'infra/main.tf': 'terraform {}\n' },
    });
    assert.equal(result.status, 'completed');
    assert.equal(result.findings[0]?.ruleId, 'terraform_required_version');
    assert.equal(result.findings[0]?.nativeSeverity, 'warning');
    const init = await runAdapter(adapter, {
      scope,
      files: { 'infra/main.tf': 'terraform {}\n' },
      args: ['--init'],
    });
    assert.equal(init.status, 'skipped');
    // Exit 1 is an engine error, never a clean result.
    const crashed = await fake('tflint-crash', '', 1);
    const failed = await runAdapter(
      unpin(
        tflintAdapter({ executable: crashed.path, versionOutput: 'v1', files }),
        crashed.sha,
      ),
      { scope, files: { 'infra/main.tf': 'terraform {}\n' } },
    );
    assert.equal(failed.status, 'failed');
    assert.equal(failed.reason, 'engine-error');
  },
);

await test('tflint: engine-reported errors make the result incomplete, not clean', () => {
  const parsed = parseTflint(
    JSON.stringify({ issues: [], errors: [{ message: 'cannot parse' }] }),
    new Set(['a.tf']),
  );
  assert.equal(parsed.partial, 'parse-failure');
});

await test(
  'yamllint: default preset is explicit and parsable lines map to native levels',
  linux,
  async () => {
    const out =
      './.github/workflows/ci.yml:1:1: [warning] missing document start "---" (document-start)\n' +
      './conf/app.yaml:7:81: [error] line too long (95 > 80 characters) (line-length)\n' +
      './conf/app.yaml:9:3: [error] syntax error: mapping values are not allowed here (syntax)\n';
    const { path } = await fake('yamllint', out, 1);
    const files = new Set(['.github/workflows/ci.yml', 'conf/app.yaml']);
    const adapter = yamllintAdapter({
      executable: path,
      versionOutput: 'v1',
      files,
    });
    assert.deepEqual(adapter.fixedArgs, [
      '-d',
      'default',
      '-f',
      'parsable',
      '.',
    ]);
    const result = await runAdapter(adapter, {
      scope,
      files: {
        '.github/workflows/ci.yml': 'on: push\n',
        'conf/app.yaml': 'a: b\n',
      },
    });
    assert.equal(result.status, 'completed');
    assert.deepEqual(
      result.findings.map((f) => [
        f.ruleId,
        f.nativeSeverity,
        f.range.startLine,
      ]),
      [
        ['document-start', 'warning', 1],
        ['line-length', 'error', 7],
        ['syntax', 'error', 9],
      ],
    );
    // A line yamllint was never given is not accepted.
    const unknown = await fake(
      'yamllint-bad',
      './elsewhere.yml:1:1: [error] x (y)\n',
      1,
    );
    const bad = await runAdapter(
      yamllintAdapter({ executable: unknown.path, versionOutput: 'v1', files }),
      { scope, files: { 'conf/app.yaml': 'a: b\n' } },
    );
    assert.equal(bad.status, 'failed');
  },
);

await test(
  'markdownlint: runs the pinned script under node with its own config and formatter only',
  linux,
  async () => {
    const pkg = join(dir, 'package.json');
    await writeFile(pkg, JSON.stringify({ version: '0.24.1' }));
    const script = await fake(
      'mdl.mjs',
      JSON.stringify([
        {
          file: 'docs/a.md',
          line: 3,
          rules: ['MD013', 'line-length'],
          description: 'Line length',
          range: [81, 20],
        },
      ]),
      1,
    );
    const adapter = markdownlintAdapter({
      node: process.execPath,
      script: script.path,
      packageJson: pkg,
      files: new Set(['docs/a.md']),
    });
    // The caller cannot add arguments, and no project config name is shipped.
    assert.deepEqual(adapter.allowedArgs, []);
    const result = await runAdapter(adapter, {
      scope,
      files: { 'docs/a.md': '# A\n', ...markdownlintSupportFiles },
    });
    assert.equal(result.status, 'completed');
    assert.equal(result.findings[0]?.ruleId, 'MD013/line-length');
    assert.equal(result.findings[0]?.nativeSeverity, 'error');
    assert.equal(result.findings[0]?.range.startColumn, 81);
    assert.equal(
      (
        JSON.parse(
          markdownlintSupportFiles['.markdownlint-cli2.jsonc'] ?? '{}',
        ) as { config: { default: boolean } }
      ).config.default,
      true,
    );
    // A wrong version in the package is refused before the script runs.
    await writeFile(pkg, JSON.stringify({ version: '0.0.1' }));
    const wrong = await runAdapter(adapter, {
      scope,
      files: { 'docs/a.md': '# A\n' },
    });
    assert.equal(wrong.status, 'failed');
    assert.equal(wrong.reason, 'engine-version-mismatch');
  },
);

await test('project lint configs are never selected as input', () => {
  for (const name of [
    '.hadolint.yaml',
    'svc/.hadolint.yml',
    '.tflint.hcl',
    'infra/.tflint.hcl',
    '.yamllint',
    '.yamllint.yaml',
    '.markdownlint.json',
    '.markdownlint.cjs',
    '.markdownlint-cli2.mjs',
    'docs/.markdownlintignore',
  ])
    assert.ok(lintConfigFile.test(name), name);
  assert.equal(isYamlFile('.yamllint.yaml'), false);
  assert.equal(isYamlFile('ci/build.yml'), true);
  assert.equal(isMarkdownFile('docs/.markdownlint.cjs'), false);
  assert.equal(isMarkdownFile('README.md'), true);
  assert.equal(isDockerfile('svc/Dockerfile.prod'), true);
  assert.equal(isDockerfile('Dockerfile.dockerignore'), false);
  assert.equal(isTerraformFile('infra/.tflint.hcl'), false);
  assert.equal(isTerraformFile('infra/main.tf'), true);
});

await test('gate severity table: lint levels map, unknown fails closed, natives untouched', () => {
  const sev = (e: EngineId, n: string) => normaliseSeverity(e, n);
  for (const e of ['hadolint', 'tflint', 'yamllint'] as const) {
    assert.equal(sev(e, 'error'), 'medium');
    assert.equal(sev(e, 'warning'), 'low');
    assert.equal(sev(e, 'surprise'), 'high');
  }
  assert.equal(sev('hadolint', 'style'), 'info');
  assert.equal(sev('hadolint', 'info'), 'info');
  assert.equal(sev('tflint', 'notice'), 'info');
  assert.equal(sev('markdownlint', 'error'), 'low');
  assert.equal(sev('markdownlint', 'surprise'), 'high');
});

await test('engines apply only where their files exist', () => {
  const none = detectApplicability(['src/a.ts']);
  for (const e of ['hadolint', 'tflint', 'yamllint', 'markdownlint'] as const)
    assert.equal(none[e].applicable, false, e);
  const all = detectApplicability([
    'Dockerfile',
    'infra/main.tf',
    'ci.yml',
    'README.md',
  ]);
  for (const e of ['hadolint', 'tflint', 'yamllint', 'markdownlint'] as const)
    assert.equal(all[e].applicable, true, e);
});

await test('Dockerfile, Terraform, YAML and Markdown count as covered', () => {
  const byName = new Map(
    detectLanguages(['Dockerfile', 'a.tf', 'b.yml', 'c.md']).map((l) => [
      l.language,
      l,
    ]),
  );
  for (const name of ['Dockerfile', 'Terraform', 'YAML', 'Markdown'])
    assert.equal(byName.get(name)?.status, 'covered', name);
  assert.deepEqual(byName.get('Dockerfile')?.engines, ['trivy', 'hadolint']);
  assert.deepEqual(byName.get('Terraform')?.engines, ['trivy', 'tflint']);
});

await test('pins: release assets use the pinned binaries and the lock holds the wheel hash', async () => {
  assert.equal(releaseAssets.hadolint.binarySha256, hadolintPin.sha256);
  assert.ok(releaseAssets.hadolint.url.includes(`v${hadolintPin.version}/`));
  assert.equal(releaseAssets.tflint.binarySha256, tflintPin.sha256);
  assert.ok(releaseAssets.tflint.url.includes(`v${tflintPin.version}/`));
  const lock = await readFile(
    new URL('../../scanners/yamllint-requirements.txt', import.meta.url),
    'utf8',
  );
  assert.ok(lock.includes(`yamllint==${yamllintPin.version}`));
  assert.ok(lock.includes(`--hash=sha256:${yamllintPin.wheelSha256}`));
  for (const block of lock.split(/\n(?=\S)/))
    assert.ok(block.includes('--hash=sha256:'), block.slice(0, 30));
});
