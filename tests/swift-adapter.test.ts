/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves SwiftLint report parsing, severity mapping, fixed arguments, the plain-YAML config guard, the sha256 pin guard, the unrunnable-binary failure, the no-Swift skip (including no download) and the analyze skip by running a fake swiftlint through runAdapter and runEngines on synthetic Swift sources; does not run the real SwiftLint binary (the pull request's quality scan job does).
*/
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { writeFakeExecutable } from './fake-executable.js';
import { runAdapter } from '../src/scanner-adapter.js';
import {
  bundledSwiftConfig,
  createSwiftlintAdapter,
  parseSwiftlintReport,
  swiftConfigProblem,
  swiftConfigPath,
  swiftWorkspace,
  swiftlintVersion,
} from '../src/swift-adapter.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineId,
} from '../src/quality-scan.js';
import {
  installOnDemand,
  runEngines,
  scopeFromEnvironment,
} from '../src/quality-scan-run.js';
import {
  releaseAssets,
  swiftlintAnalyzePin,
  swiftlintPin,
} from '../src/scanner-pins.js';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const dir = await mkdtemp(join(tmpdir(), 'swift-test-'));
const marker = join(dir, 'ran');
const modeFile = join(dir, 'mode.txt');

// Synthetic sources: a force cast is the known violation.
const defects = 'func f(_ x: Any) -> String {\n    return x as! String\n}\n';
const clean = 'func total(_ v: [Int]) -> Int {\n    v.reduce(0, +)\n}\n';
const plainConfig =
  'disabled_rules:\n  - line_length\n# marker: repository-config\n';

const swiftlintArgs = createSwiftlintAdapter('/x/swiftlint').fixedArgs;

// The fake exits 3 unless it receives exactly the reviewed arguments, so it
// also proves nothing else (fix, format, analyze) is passed. It reads the
// config file it was given to prove which configuration applied.
const fakeBody = `const fs = require('node:fs');
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(marker)}, 'ran');
const mode = fs.readFileSync(${JSON.stringify(modeFile)}, 'utf8').trim();
if (mode === 'unrunnable') { console.error('GLIBC_2.38 not found'); process.exit(127); }
if (args[0] === 'version') { console.log('${swiftlintVersion}'); process.exit(0); }
if (JSON.stringify(args) !== JSON.stringify(${JSON.stringify(swiftlintArgs)})) { console.error('unexpected args'); process.exit(3); }
const cwd = process.cwd();
const config = fs.readFileSync(cwd + '/.swiftlint.yml', 'utf8');
if (mode === 'crash') process.exit(1);
if (mode === 'garbage') { console.log('nope'); process.exit(0); }
const r = (file, severity, rule_id, line, character) => ({ file: cwd + '/' + file, line, character, severity, rule_id, reason: rule_id + ' found', type: rule_id });
if (mode === 'defects') { console.log(JSON.stringify([r('App/Defects.swift', 'Error', 'force_cast', 2, 14), r('App/Defects.swift', 'Warning', 'line_length', 1, null)])); process.exit(2); }
if (mode === 'invalid') { console.log(JSON.stringify([r('App/Defects.swift', 'Error', 'force_cast', 2, 14), { nofile: true }])); process.exit(2); }
if (mode === 'config') { console.log(JSON.stringify(config.includes('repository-config') ? [r('App/A.swift', 'Warning', 'repository_config_used', 1, 1)] : [])); process.exit(0); }
console.log('[]');
`;
const fake = await writeFakeExecutable(dir, 'fake-swiftlint', fakeBody);
const mode = (value: string) => writeFile(modeFile, value);
const ran = () =>
  access(marker).then(
    () => true,
    () => false,
  );
const swiftlint = (files: Record<string, string>) =>
  runAdapter(createSwiftlintAdapter(fake.path, fake.sha256), {
    scope,
    files: { ...files, [swiftConfigPath]: bundledSwiftConfig },
  });

await test(
  'known violations become findings with relative paths and native severities',
  linux,
  async () => {
    await mode('defects');
    const envelope = await swiftlint({ 'App/Defects.swift': defects });
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(
      envelope.findings.map((f) => [f.ruleId, f.nativeSeverity, f.path]),
      [
        ['line_length', 'warning', 'App/Defects.swift'],
        ['force_cast', 'error', 'App/Defects.swift'],
      ],
    );
    assert.equal(envelope.findings[1]?.range.startColumn, 14);
    assert.equal(envelope.findings[0]?.range.startColumn, 1);
    assert.match(
      envelope.findings[0]?.fingerprint ?? '',
      /^sha256:[a-f0-9]{64}$/,
    );
    assert.equal(envelope.engine.id, 'swiftlint');
  },
);

await test('clean Swift completes with no findings', linux, async () => {
  await mode('clean');
  const envelope = await swiftlint({ 'App/Clean.swift': clean });
  assert.equal(envelope.status, 'completed');
  assert.deepEqual(envelope.findings, []);
});

await test('only the reviewed arguments run: no fix, format, analyze or remote config', () => {
  assert.deepEqual(swiftlintArgs.slice(0, 4), [
    'lint',
    '--reporter',
    'json',
    '--quiet',
  ]);
  assert.ok(
    !swiftlintArgs.some((a) =>
      /fix|format|analyze|autocorrect|compiler|http/.test(a),
    ),
  );
  assert.ok(swiftlintArgs.includes(swiftConfigPath));
});

await test(
  'an unusable entry makes the run incomplete, never clean',
  linux,
  async () => {
    await mode('invalid');
    const envelope = await swiftlint({ 'App/Defects.swift': defects });
    assert.equal(envelope.status, 'incomplete');
    assert.equal(envelope.reason, 'invalid-output');
    assert.equal(envelope.findings.length, 1);
  },
);

await test(
  'engine crashes and garbage output fail the engine',
  linux,
  async () => {
    await mode('crash');
    const crashed = await swiftlint({ 'a.swift': clean });
    assert.equal(crashed.status, 'failed');
    assert.equal(crashed.reason, 'engine-error');
    await mode('garbage');
    const garbage = await swiftlint({ 'a.swift': clean });
    assert.equal(garbage.status, 'failed');
    assert.equal(garbage.reason, 'invalid-output');
  },
);

await test(
  'a binary that cannot run on the host is failed, never a pass',
  linux,
  async () => {
    await mode('unrunnable');
    const envelope = await swiftlint({ 'a.swift': clean });
    assert.equal(envelope.status, 'failed');
    assert.notEqual(envelope.status, 'completed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
    assert.deepEqual(envelope.findings, []);
  },
);

await test(
  'an executable that does not match the pinned sha256 is refused and never runs',
  linux,
  async () => {
    await rm(marker, { force: true });
    // No explicit sha: the adapter falls back to the real pin, which the fake cannot match.
    const envelope = await runAdapter(createSwiftlintAdapter(fake.path), {
      scope,
      files: { 'a.swift': clean },
    });
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
    assert.equal(await ran(), false);
    assert.match(swiftlintPin.sha256, /^[a-f0-9]{64}$/);
    assert.match(releaseAssets.swiftlint.assetSha256, /^[a-f0-9]{64}$/);
    assert.equal(releaseAssets.swiftlint.binarySha256, swiftlintPin.sha256);
    assert.ok(
      releaseAssets.swiftlint.url.includes(`/${swiftlintPin.version}/`),
    );
    assert.ok(releaseAssets.swiftlint.url.endsWith('.zip'));
    assert.equal(releaseAssets.swiftlint.member, 'swiftlint-static');
  },
);

await test('severity maps to the gate scale and unknown labels fail closed', () => {
  assert.equal(normaliseSeverity('swiftlint', 'error'), 'high');
  assert.equal(normaliseSeverity('swiftlint', 'warning'), 'medium');
  assert.equal(normaliseSeverity('swiftlint', 'surprise'), 'high');
});

await test('the parser rejects non-report output and keeps no source text', () => {
  assert.throws(() => parseSwiftlintReport('{"a":1}'));
  const parsed = parseSwiftlintReport(
    JSON.stringify([
      {
        file: '/w/source/x.swift',
        line: 1,
        character: 1,
        severity: 'Warning',
        rule_id: 'line_length',
        reason: 'too long',
        type: 'Line Length',
        source: 'SECRET',
      },
    ]),
    '/w/source',
  );
  assert.equal(parsed.findings[0]?.path, 'x.swift');
  assert.ok(!JSON.stringify(parsed).includes('SECRET'));
});

await test(
  'only a plain-YAML repository config is honoured; anything else falls back and says why',
  linux,
  async () => {
    assert.equal(swiftConfigProblem(plainConfig), undefined);
    const refused: [string, string][] = [
      [
        'parent_config: https://example.com/base.yml\n',
        'refers to another configuration (parent_config or child_config)',
      ],
      ['include: https://example.com/base.yml\n', 'contains a URL'],
      [
        'parent_config: ../base.yml\n',
        'refers to another configuration (parent_config or child_config)',
      ],
      [
        'child_config: sub.yml\n',
        'refers to another configuration (parent_config or child_config)',
      ],
      ['rules: !!python/object x\n', 'contains a YAML tag'],
      ['a: b\u0000\n', 'contains control characters'],
      [`# ${'x'.repeat(70000)}\n`, 'larger than 64 KiB'],
    ];
    for (const [text, why] of refused) {
      assert.equal(swiftConfigProblem(text), why, text.slice(0, 30));
      const ws = swiftWorkspace({ 'a.swift': clean }, text);
      assert.equal(ws.configRejected, why);
      assert.equal(ws.files[swiftConfigPath], bundledSwiftConfig);
    }
    const honoured = swiftWorkspace({ 'a.swift': clean }, plainConfig);
    assert.equal(honoured.configRejected, undefined);
    assert.equal(honoured.files[swiftConfigPath], plainConfig);
    assert.equal(
      swiftWorkspace({ 'a.swift': clean }, undefined).files[swiftConfigPath],
      bundledSwiftConfig,
    );
    // End to end through the adapter: the engine sees the repository config only when it was honoured.
    await mode('config');
    const used = await runAdapter(
      createSwiftlintAdapter(fake.path, fake.sha256),
      {
        scope,
        files: swiftWorkspace({ 'App/A.swift': clean }, plainConfig).files,
      },
    );
    assert.deepEqual(
      used.findings.map((f) => f.ruleId),
      ['repository_config_used'],
    );
    const bundled = await runAdapter(
      createSwiftlintAdapter(fake.path, fake.sha256),
      {
        scope,
        files: swiftWorkspace(
          { 'App/A.swift': clean },
          'parent_config: ../x.yml\n',
        ).files,
      },
    );
    assert.deepEqual(bundled.findings, []);
  },
);

await test('Swift files make swiftlint and the analyze skip applicable; other repos skip them', () => {
  const swift = detectApplicability(['App/A.swift']);
  assert.equal(swift.swiftlint.applicable, true);
  assert.equal(swift['swiftlint-analyze'].applicable, true);
  const none = detectApplicability(['src/a.ts', 'App.kt', 'swiftlint.yml']);
  assert.equal(none.swiftlint.applicable, false);
  assert.equal(none.swiftlint.reason, 'no Swift files');
  assert.equal(none['swiftlint-analyze'].applicable, false);
});

await test('the installer downloads SwiftLint only for a checkout with Swift files', () => {
  const wanted = installOnDemand.swiftlint;
  assert.ok(wanted);
  assert.equal(wanted('Sources/App/Main.swift'), true);
  assert.equal(wanted('src/a.ts'), false);
  assert.equal(wanted('.swiftlint.yml'), false);
  assert.equal(installOnDemand.ruff, undefined);
});

const commitRepo = async (name: string, content: string) => {
  const repo = await mkdtemp(join(tmpdir(), 'swift-repo-'));
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
  git('init', '-q');
  await writeFile(join(repo, name), content);
  git('add', '.');
  git(
    '-c',
    'user.email=t@example.com',
    '-c',
    'user.name=t',
    'commit',
    '-q',
    '-m',
    'x',
  );
  return repo;
};
const selected: EngineId[] = ['swiftlint', 'swiftlint-analyze'];
const scanRepo = async (repo: string, tools: { swiftlint?: string } = {}) =>
  (
    await runEngines({
      repo,
      scope,
      selected,
      tools,
      installErrors: {},
      gitExecutable: 'git',
      rulesDirectory: repo,
    })
  ).filter((r) => selected.includes(r.engine));

await test(
  'a repository without Swift skips both engines as not applicable and runs nothing',
  linux,
  async () => {
    const repo = await commitRepo('app.ts', 'export const a = 1;\n');
    try {
      await rm(marker, { force: true });
      for (const r of await scanRepo(repo, { swiftlint: fake.path })) {
        assert.equal(r.status, 'skipped', r.engine);
        assert.equal(r.skipKind, 'not-applicable', r.engine);
        assert.equal(r.reason, 'no Swift files', r.engine);
      }
      assert.equal(await ran(), false);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  },
);

await test('analyzer rules are reported skipped with a reason, never run or clean', async () => {
  const repo = await commitRepo('App.swift', defects);
  try {
    const analyze = (await scanRepo(repo)).find(
      (r) => r.engine === 'swiftlint-analyze',
    );
    assert.equal(analyze?.status, 'skipped');
    assert.equal(analyze.skipKind, 'unavailable');
    assert.equal(analyze.reason, swiftlintAnalyzePin.skipReason);
    assert.match(analyze.reason ?? '', /compiled|compiler/);
    assert.deepEqual(analyze.findings, []);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test(
  'Swift with no installed or a mismatching SwiftLint fails, never clean',
  linux,
  async () => {
    const repo = await commitRepo('App.swift', defects);
    try {
      for (const tools of [{}, { swiftlint: fake.path }]) {
        await rm(marker, { force: true });
        const r = (await scanRepo(repo, tools)).find(
          (x) => x.engine === 'swiftlint',
        );
        assert.equal(r?.status, 'failed');
        assert.deepEqual(r.findings, []);
        assert.equal(await ran(), false);
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  },
);

await rm(dir, { recursive: true, force: true }).catch(() => undefined);
