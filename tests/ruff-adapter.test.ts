/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves Ruff report parsing, the gate severity mapping, fixed isolated arguments, sha256 refusal and failure states by running a fake executable through runAdapter on synthetic Python sources, plus runEngines reporting mypy as skipped; does not run the real ruff or mypy binaries (the pull request's quality scan job does).
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
  createRuffAdapter,
  parseRuffReport,
  ruffFamily,
  ruffSelect,
  ruffVersion,
  runRuffScan,
} from '../src/ruff-adapter.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineId,
} from '../src/quality-scan.js';
import { runEngines, scopeFromEnvironment } from '../src/quality-scan-run.js';
import { mypyPin } from '../src/scanner-pins.js';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const dir = await mkdtemp(join(tmpdir(), 'ruff-test-'));
const marker = join(dir, 'ran');
const modeFile = join(dir, 'mode.txt');

// Synthetic sources: known defects, clean code and a syntax error.
const defects =
  'import os\nimport subprocess\n\n\ndef run(x):\n    subprocess.call("ls", shell=True)\n    if x == None:\n        return 1\n';
const clean = 'def total(values: list[int]) -> int:\n    return sum(values)\n';
const syntax = 'def broken(:\n    pass\n';

const entry = (
  filename: string,
  code: string | null,
  message: string,
  row = 1,
  column = 1,
) => ({
  cell: null,
  code,
  filename,
  fix: null,
  location: { row, column },
  end_location: { row, column: column + 3 },
  message,
  noqa_row: row,
  url: null,
});

// The fake exits 3 unless it receives exactly the reviewed arguments, so it
// also proves the bundled isolated config is what is passed.
const expectedArgs = createRuffAdapter('/x').fixedArgs;
const fakeBody = `const fs = require('node:fs');
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(marker)}, 'ran');
const mode = fs.readFileSync(${JSON.stringify(modeFile)}, 'utf8').trim();
if (args[0] === '--version') { console.log('ruff ${ruffVersion}'); process.exit(0); }
if (JSON.stringify(args) !== ${JSON.stringify(JSON.stringify(expectedArgs))}) { console.error('unexpected args'); process.exit(3); }
const cwd = process.cwd();
const e = (f, code, message, row, column) => ({ cell: null, code, filename: cwd + '/' + f, fix: null, location: { row, column }, end_location: { row, column: column + 3 }, message, noqa_row: row, url: null });
if (mode === 'defects') {
  const seen = fs.existsSync(cwd + '/pyproject.toml') ? 'project-config-present' : 'ok';
  console.log(JSON.stringify([e('app/defects.py', 'F401', '\`os\` imported but unused', 1, 8), e('app/defects.py', 'S602', 'subprocess call with shell=True', 6, 5), e('app/defects.py', 'E711', 'Comparison to None', 7, 8), e('app/defects.py', 'UP035', seen, 2, 1)]));
  process.exit(1);
}
if (mode === 'syntax') { console.log(JSON.stringify([e('app/syntax.py', null, 'SyntaxError: Expected parameter name', 1, 12)])); process.exit(1); }
if (mode === 'invalid-entry') { console.log(JSON.stringify([e('app/defects.py', 'F401', 'unused', 1, 1), { code: 'F401', message: 7 }])); process.exit(1); }
if (mode === 'crash') { process.exit(2); }
if (mode === 'garbage') { console.log('not json'); process.exit(0); }
console.log('[]');
`;
const fake = await writeFakeExecutable(dir, 'fake-ruff', fakeBody);
const executable = fake.path;
const fakeSha = fake.sha256;
const mode = (value: string) => writeFile(modeFile, value);
const ran = () =>
  access(marker).then(
    () => true,
    () => false,
  );
const scan = (files: Record<string, string>) =>
  runAdapter(createRuffAdapter(executable, fakeSha), { scope, files });

await test(
  'known defects become findings with rule-family severity and relative paths',
  linux,
  async () => {
    await mode('defects');
    const envelope = await scan({ 'app/defects.py': defects });
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(
      envelope.findings.map((f) => [f.ruleId, f.nativeSeverity, f.path]),
      [
        ['F401', 'bug', 'app/defects.py'],
        ['UP035', 'convention', 'app/defects.py'],
        ['S602', 'security', 'app/defects.py'],
        ['E711', 'convention', 'app/defects.py'],
      ],
    );
    assert.equal(envelope.findings[0]?.range.startColumn, 8);
    assert.match(
      envelope.findings[0]?.fingerprint ?? '',
      /^sha256:[a-f0-9]{64}$/,
    );
    assert.equal(envelope.engine.id, 'ruff');
  },
);

await test(
  'the project configuration is never present or read',
  linux,
  async () => {
    await mode('defects');
    const envelope = await scan({ 'app/defects.py': defects });
    assert.ok(
      !envelope.findings.some((f) => f.message === 'project-config-present'),
    );
    assert.ok(expectedArgs.includes('--isolated'));
    assert.ok(!expectedArgs.includes('--fix'));
    assert.ok(!expectedArgs.some((a) => /pyproject|ruff\.toml/.test(a)));
    assert.ok(
      expectedArgs.includes(
        `lint.select=[${ruffSelect.map((r) => `"${r}"`).join(',')}]`,
      ),
    );
  },
);

await test('clean code completes with no findings', linux, async () => {
  await mode('clean');
  const envelope = await runRuffScan({
    executable,
    scope,
    files: { 'ok.py': clean },
  }).catch(() => null);
  // The pinned sha256 does not match the fake, so the public entry refuses it.
  assert.equal(envelope?.status, 'failed');
  const direct = await scan({ 'ok.py': clean });
  assert.equal(direct.status, 'completed');
  assert.deepEqual(direct.findings, []);
});

await test(
  'a syntax error is a finding at high severity, not a failed run',
  linux,
  async () => {
    await mode('syntax');
    const envelope = await scan({ 'app/syntax.py': syntax });
    assert.equal(envelope.status, 'completed');
    assert.equal(envelope.findings[0]?.ruleId, 'invalid-syntax');
    assert.equal(envelope.findings[0]?.nativeSeverity, 'error');
    assert.equal(normaliseSeverity('ruff', 'error'), 'high');
  },
);

await test(
  'an unusable entry makes the run incomplete, never clean',
  linux,
  async () => {
    await mode('invalid-entry');
    const envelope = await scan({ 'app/defects.py': defects });
    assert.equal(envelope.status, 'incomplete');
    assert.equal(envelope.reason, 'invalid-output');
    assert.equal(envelope.findings.length, 1);
  },
);

await test(
  'ruff internal errors and garbage output fail the engine',
  linux,
  async () => {
    for (const [value, reason] of [
      ['crash', 'engine-error'],
      ['garbage', 'invalid-output'],
    ] as const) {
      await mode(value);
      const envelope = await scan({ 'a.py': clean });
      assert.equal(envelope.status, 'failed', value);
      assert.equal(envelope.reason, reason, value);
    }
  },
);

await test(
  'an executable that does not match the sha256 is refused unrun',
  linux,
  async () => {
    await rm(marker, { force: true });
    const envelope = await runAdapter(createRuffAdapter(executable), {
      scope,
      files: { 'a.py': clean },
    });
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
    assert.equal(await ran(), false);
  },
);

await test('rule families map to the gate scale and unknown labels fail closed', () => {
  assert.equal(ruffFamily(null), 'error');
  assert.equal(ruffFamily('E902'), 'error');
  assert.equal(ruffFamily('S101'), 'security');
  assert.equal(ruffFamily('F821'), 'bug');
  assert.equal(ruffFamily('B006'), 'bug');
  assert.equal(ruffFamily('PLE0602'), 'bug');
  assert.equal(ruffFamily('PLR2004'), 'convention');
  assert.equal(ruffFamily('I001'), 'convention');
  assert.equal(normaliseSeverity('ruff', 'security'), 'medium');
  assert.equal(normaliseSeverity('ruff', 'bug'), 'medium');
  assert.equal(normaliseSeverity('ruff', 'convention'), 'low');
  assert.equal(normaliseSeverity('ruff', 'surprise'), 'high');
});

await test('parseRuffReport rejects non-array output and keeps no source text', () => {
  assert.throws(() => parseRuffReport('{"a":1}'));
  const parsed = parseRuffReport(
    JSON.stringify([
      {
        ...entry('/w/source/x.py', 'F401', 'unused'),
        fix: { content: 'SECRET' },
      },
    ]),
    '/w/source',
  );
  assert.equal(parsed.findings[0]?.path, 'x.py');
  assert.ok(!JSON.stringify(parsed).includes('SECRET'));
});

await test('Python files make ruff and mypy applicable; other repos skip them', () => {
  const python = detectApplicability(['src/a.py', 'types/b.pyi']);
  assert.equal(python.ruff.applicable, true);
  assert.equal(python.mypy.applicable, true);
  const none = detectApplicability(['src/a.ts']);
  assert.equal(none.ruff.applicable, false);
  assert.equal(none.mypy.applicable, false);
});

await test('mypy is reported skipped with a reason and ruff without an install fails, never clean', async () => {
  const repo = await mkdtemp(join(tmpdir(), 'ruff-repo-'));
  try {
    const git = (...args: string[]) =>
      execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
    git('init', '-q');
    await writeFile(join(repo, 'app.py'), defects);
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
    const selected: EngineId[] = ['ruff', 'mypy'];
    const results = await runEngines({
      repo,
      scope,
      selected,
      tools: {},
      installErrors: {},
      gitExecutable: 'git',
      rulesDirectory: repo,
    });
    const byEngine = new Map(results.map((r) => [r.engine, r]));
    const mypy = byEngine.get('mypy');
    assert.equal(mypy?.status, 'skipped');
    assert.equal(mypy.skipKind, 'unavailable');
    assert.match(mypy.reason ?? '', /^needs dependency environment/);
    assert.equal(mypy.reason, mypyPin.skipReason);
    assert.deepEqual(mypy.findings, []);
    assert.equal(byEngine.get('ruff')?.status, 'failed');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await rm(dir, { recursive: true, force: true }).catch(() => undefined);
