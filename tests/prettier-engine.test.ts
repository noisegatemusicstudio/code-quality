/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Runs runEngines with the real Prettier on a synthetic git repository per case (tracked-only, .prettierignore, JS config refusal, parse errors), then checks the severity mapping, applicability and the advisory gate; does not run the CLI, the workflow or any other engine.
*/
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { approvedPrettierVersion } from '../src/prettier-adapter.js';
import { decideWithGate, loadGate, parseGate } from '../src/quality-gate.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineResult,
} from '../src/quality-scan.js';
import { runEngines, scopeFromEnvironment } from '../src/quality-scan-run.js';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const root = await mkdtemp(join(tmpdir(), 'prettier-engine-'));
const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

/** Build a git repo; `tracked` files are committed, `untracked` files are only on disk. */
async function scan(
  name: string,
  tracked: Record<string, string>,
  untracked: Record<string, string> = {},
): Promise<EngineResult> {
  const repo = join(root, name);
  await mkdir(repo, { recursive: true });
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
  git('init', '-q');
  for (const [path, content] of Object.entries({ ...tracked, ...untracked })) {
    await mkdir(dirname(join(repo, path)), { recursive: true });
    await writeFile(join(repo, path), content);
  }
  git('add', ...Object.keys(tracked));
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
  const results = await runEngines({
    repo,
    scope,
    selected: ['prettier'],
    tools: {},
    installErrors: {},
    gitExecutable: 'git',
    rulesDirectory: repo,
  });
  const result = results.find((r) => r.engine === 'prettier');
  assert.ok(result);
  return result;
}
const paths = (r: EngineResult) => r.findings.map((f) => f.path);
const bad = 'const   a = 1\n';
const good = 'const a = 1;\n';

await test(
  'a tracked unformatted file is one prettier/format finding at info severity',
  linux,
  async () => {
    const r = await scan('tracked', { 'a.ts': bad, 'b.ts': good });
    assert.equal(r.status, 'completed');
    assert.equal(r.version, approvedPrettierVersion);
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].ruleId, 'prettier/format');
    assert.equal(
      normaliseSeverity('prettier', r.findings[0].nativeSeverity),
      'info',
    );
    assert.deepEqual(paths(r), ['a.ts']);
  },
);

await test('untracked files are never checked', linux, async () => {
  const r = await scan(
    'untracked',
    { 'a.ts': good },
    { 'scratch.ts': bad, 'notes/draft.md': '# x\n\n\n\ny\n' },
  );
  assert.equal(r.status, 'completed');
  assert.deepEqual(paths(r), []);
});

await test(
  '.prettierignore keeps tracked files out of the check',
  linux,
  async () => {
    const r = await scan('ignored', {
      '.prettierignore': 'vendored-copy/\n',
      'vendored-copy/a.ts': bad,
      'src/b.ts': bad,
    });
    assert.equal(r.status, 'completed');
    assert.deepEqual(paths(r), ['src/b.ts']);
    const control = await scan('not-ignored', {
      'vendored-copy/a.ts': bad,
      'src/b.ts': bad,
    });
    assert.deepEqual(paths(control), ['src/b.ts', 'vendored-copy/a.ts']);
  },
);

await test(
  'a JS config in the scanned repo is not executed and is reported',
  linux,
  async () => {
    const marker = join(root, 'js-config-ran');
    const r = await scan('js-config', {
      'prettier.config.js': `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x'); module.exports = { semi: false };`,
      'a.ts': 'const a = 1\n',
    });
    assert.equal(await exists(marker), false, 'repository code executed');
    assert.equal(r.status, 'incomplete');
    assert.match(r.reason ?? '', /^customer-config-rejected/);
    assert.match(r.reason ?? '', /prettier\.config\.js/);
    // semi: false would accept this file; Prettier defaults do not.
    assert.deepEqual(paths(r), ['a.ts']);
    assert.equal(r.envelope?.reason, 'customer-config-rejected');
  },
);

await test('a JSON config in the scanned repo is honoured', linux, async () => {
  const r = await scan('json-config', {
    '.prettierrc.json': '{ "semi": false }',
    'a.ts': 'const a = 1\n',
    'b.ts': good,
  });
  assert.equal(r.status, 'completed');
  assert.deepEqual(paths(r), ['b.ts']);
});

await test(
  'a parse error is incomplete and named, not a pass',
  linux,
  async () => {
    const r = await scan('parse-error', {
      'broken.ts': 'const = ;\n',
      'ok.ts': good,
    });
    assert.equal(r.status, 'incomplete');
    assert.match(r.reason ?? '', /^parse-failure: 1 file\(s\)/);
    assert.match(r.reason ?? '', /broken\.ts/);
    assert.equal(r.envelope?.reason, 'parse-failure');
    const strict = decideWithGate([r], {
      enforce: true,
      gate: { ...(await loadGate()), advisoryEngines: [] },
    });
    assert.equal(strict.exitCode, 1);
    assert.match(strict.reasons.join(), /failed or incomplete: prettier/);
  },
);

await test(
  'every tracked file ignored is a completed run with no findings',
  linux,
  async () => {
    const r = await scan('all-ignored', {
      '.prettierignore': '*.ts\n',
      'a.ts': bad,
    });
    assert.equal(r.status, 'completed');
    assert.deepEqual(r.findings, []);
  },
);

await test('applicability follows the supported file types', () => {
  assert.equal(detectApplicability(['a.ts']).prettier.applicable, true);
  for (const p of ['a.json', 'a.yml', 'a.md', 'a.css', 'a.jsx'])
    assert.equal(detectApplicability([p]).prettier.applicable, true, p);
  const none = detectApplicability(['a.py', 'package-lock.json', 'dist/x.js']);
  assert.equal(none.prettier.applicable, false);
  assert.match(none.prettier.reason ?? '', /no JS, TS/);
});

await test('the default gate lists Prettier as advisory: findings and a broken run are reported, not blocking', async () => {
  const gate = await loadGate();
  assert.deepEqual(gate.advisoryEngines, ['prettier']);
  const finding = {
    ruleId: 'prettier/format',
    nativeSeverity: 'format',
    path: 'a.ts',
    range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    fingerprint: `sha256:${'0'.repeat(64)}`,
    message: 'm',
  };
  const results: EngineResult[] = [
    {
      engine: 'prettier',
      status: 'incomplete',
      reason: 'x',
      findings: [finding],
    },
  ];
  const advisory = decideWithGate(results, { enforce: true, gate });
  assert.equal(advisory.blocking, 0);
  assert.equal(advisory.exitCode, 0);
  assert.deepEqual(advisory.broken, ['prettier']);
  // Guard: without the advisory entry the same run blocks.
  const required = decideWithGate(results, {
    enforce: true,
    gate: { ...gate, advisoryEngines: [] },
  });
  assert.equal(required.exitCode, 1);
  // An advisory engine does not excuse other engines.
  const other = decideWithGate(
    [
      ...results,
      { engine: 'ruff', status: 'failed', reason: 'x', findings: [] },
    ],
    { enforce: true, gate },
  );
  assert.match(other.reasons.join(), /failed or incomplete: ruff$/);
});

await test('advisoryEngines is optional but strict when present', async () => {
  const base = JSON.parse(
    JSON.stringify({ ...(await loadGate()), advisoryEngines: undefined }),
  ) as Record<string, unknown>;
  assert.equal(parseGate(JSON.stringify(base)).advisoryEngines, undefined);
  const withList = (value: unknown) =>
    JSON.stringify({ ...base, advisoryEngines: value });
  assert.deepEqual(parseGate(withList(['prettier'])).advisoryEngines, [
    'prettier',
  ]);
  assert.throws(() => parseGate(withList(['nope'])), /unknown engine/);
  assert.throws(() => parseGate(withList(['ruff', 'ruff'])), /repeats ruff/);
  assert.throws(() => parseGate(withList('prettier')), /must be an array/);
  assert.throws(
    () => parseGate(JSON.stringify({ ...base, surprise: 1 })),
    /unknown key gate\.surprise/,
  );
});

await rm(root, { recursive: true, force: true }).catch(() => undefined);
