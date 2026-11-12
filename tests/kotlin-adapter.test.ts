/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves detekt and ktlint report parsing, severity mapping, fixed arguments, the sha256 pin guard, the Java-missing skip and the no-Kotlin skip by running a fake java through runAdapter and runEngines on synthetic Kotlin sources; does not run the real detekt or ktlint jars (the pull request's quality scan job does).
*/
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { writeFakeExecutable } from './fake-executable.js';
import { runAdapter } from '../src/scanner-adapter.js';
import {
  createDetektAdapter,
  createKtlintAdapter,
  detektVersion,
  javaSkipReason,
  ktlintVersion,
  parseDetektSarif,
  parseKtlintReport,
} from '../src/kotlin-adapter.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineId,
} from '../src/quality-scan.js';
import {
  findJava,
  runEngines,
  scopeFromEnvironment,
} from '../src/quality-scan-run.js';
import { detektPin, ktlintPin } from '../src/scanner-pins.js';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const dir = await mkdtemp(join(tmpdir(), 'kotlin-test-'));
const marker = join(dir, 'ran');
const modeFile = join(dir, 'mode.txt');

// Synthetic sources: a magic number and a wildcard import are the known violations.
const defects =
  'package app\n\nimport java.util.*\n\nfun f(x: Int): Int = x * 42\n';
const clean = 'package app\n\nfun total(v: List<Int>): Int = v.sum()\n';

const sarif = (
  uri: string,
  level: string,
  ruleId: string,
  line: number,
  column: number,
) => ({
  ruleId,
  level,
  message: { text: `${ruleId} found` },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri },
        region: { startLine: line, startColumn: column },
      },
    },
  ],
});

const detektArgs = createDetektAdapter('/x/java', '/x/jar', 'v').fixedArgs;
const ktlintArgs = createKtlintAdapter('/x/java', '/x/jar', 'v').fixedArgs;

// The fake java exits 3 unless it receives exactly `-Xmx1g -jar <jar>` then the
// reviewed arguments, so it also proves nothing else (config, plugins) is passed.
const fakeBody = `const fs = require('node:fs');
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(marker)}, 'ran');
const mode = fs.readFileSync(${JSON.stringify(modeFile)}, 'utf8').trim();
const [engine, kind] = mode.split(':');
if (args[0] !== '-Xmx1g' || args[1] !== '-jar') process.exit(4);
const rest = args.slice(3);
if (rest[0] === '--version') { console.log(engine === 'detekt' ? '${detektVersion}' : 'ktlint ${ktlintVersion}'); process.exit(0); }
const expected = engine === 'detekt' ? ${JSON.stringify(detektArgs)} : ${JSON.stringify(ktlintArgs)};
if (JSON.stringify(rest) !== JSON.stringify(expected)) { console.error('unexpected args'); process.exit(3); }
const cwd = process.cwd();
if (kind === 'crash') process.exit(1 + (engine === 'detekt' ? 0 : 1));
if (engine === 'detekt') {
  fs.mkdirSync(cwd + '/../out', { recursive: true });
  const r = (uri, level, ruleId, line, column) => ({ ruleId, level, message: { text: ruleId }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, startColumn: column } } }] });
  let results = [];
  if (kind === 'defects') results = [r('file://' + cwd + '/app/Defects.kt', 'warning', 'detekt.style.MagicNumber', 5, 28), r('app/Defects.kt', 'error', 'detekt.potential-bugs.UnsafeCast', 1, 1), r('./app/Defects.kt', 'note', 'detekt.style.MaxLineLength', 2, 1)];
  if (kind === 'invalid') results = [r('app/Defects.kt', 'warning', 'detekt.style.MagicNumber', 5, 28), { ruleId: 7 }];
  fs.writeFileSync(cwd + '/../out/detekt.sarif', kind === 'garbage' ? 'not json' : JSON.stringify({ version: '2.1.0', runs: [{ results }] }));
  process.exit(kind === 'clean' ? 0 : 2);
}
if (kind === 'garbage') { console.log('nope'); process.exit(0); }
if (kind === 'invalid') { console.log(JSON.stringify([{ file: 'app/Defects.kt', errors: [{ line: 3, column: 1, message: 'm', rule: 'standard:no-wildcard-imports' }] }, { nofile: true }])); process.exit(1); }
if (kind === 'defects') { console.log(JSON.stringify([{ file: 'app/Defects.kt', errors: [{ line: 3, column: 1, message: 'Wildcard import', rule: 'standard:no-wildcard-imports' }, { line: 5, column: 1, message: 'Missing newline', rule: '' }] }])); process.exit(1); }
console.log('[]');
`;
const fakeJava = await writeFakeExecutable(dir, 'fake-java', fakeBody);
const jarBytes = 'PK fake jar bytes';
const jar = join(dir, 'fake.jar');
await writeFile(jar, jarBytes);
const jarSha = createHash('sha256').update(jarBytes).digest('hex');
const mode = (value: string) => writeFile(modeFile, value);
const ran = () =>
  access(marker).then(
    () => true,
    () => false,
  );
const detekt = (files: Record<string, string>) =>
  runAdapter(createDetektAdapter(fakeJava.path, jar, detektVersion, jarSha), {
    scope,
    files,
  });
const ktlint = (files: Record<string, string>) =>
  runAdapter(
    createKtlintAdapter(fakeJava.path, jar, `ktlint ${ktlintVersion}`, jarSha),
    { scope, files },
  );

await test(
  'detekt known violations become findings with relative paths from every uri form',
  linux,
  async () => {
    await mode('detekt:defects');
    const envelope = await detekt({ 'app/Defects.kt': defects });
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(
      envelope.findings.map((f) => [f.ruleId, f.nativeSeverity, f.path]),
      [
        ['detekt.potential-bugs.UnsafeCast', 'error', 'app/Defects.kt'],
        ['detekt.style.MaxLineLength', 'note', 'app/Defects.kt'],
        ['detekt.style.MagicNumber', 'warning', 'app/Defects.kt'],
      ],
    );
    assert.equal(envelope.findings[2]?.range.startColumn, 28);
    assert.match(
      envelope.findings[0]?.fingerprint ?? '',
      /^sha256:[a-f0-9]{64}$/,
    );
    assert.equal(envelope.engine.id, 'detekt');
  },
);

await test(
  'ktlint known violations become style findings; a missing rule id is named',
  linux,
  async () => {
    await mode('ktlint:defects');
    const envelope = await ktlint({ 'app/Defects.kt': defects });
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(
      envelope.findings.map((f) => [
        f.ruleId,
        f.nativeSeverity,
        f.range.startLine,
      ]),
      [
        ['standard:no-wildcard-imports', 'style', 3],
        ['ktlint:unknown', 'style', 5],
      ],
    );
    assert.equal(envelope.engine.id, 'ktlint');
  },
);

await test('clean Kotlin completes with no findings', linux, async () => {
  for (const [run, name] of [
    [detekt, 'detekt'],
    [ktlint, 'ktlint'],
  ] as const) {
    await mode(`${name}:clean`);
    const envelope = await run({ 'app/Clean.kt': clean });
    assert.equal(envelope.status, 'completed', name);
    assert.deepEqual(envelope.findings, [], name);
  }
});

await test('only the reviewed arguments run: no config, plugin or fix flag', () => {
  for (const args of [detektArgs, ktlintArgs]) {
    assert.ok(!args.some((a) => /config|plugin|format|-F$|baseline/.test(a)));
  }
  assert.ok(detektArgs.includes('sarif:../out/detekt.sarif'));
  assert.ok(ktlintArgs.includes('--reporter=json'));
});

await test(
  'an unusable entry makes the run incomplete, never clean',
  linux,
  async () => {
    for (const [run, name] of [
      [detekt, 'detekt'],
      [ktlint, 'ktlint'],
    ] as const) {
      await mode(`${name}:invalid`);
      const envelope = await run({ 'app/Defects.kt': defects });
      assert.equal(envelope.status, 'incomplete', name);
      assert.equal(envelope.reason, 'invalid-output', name);
      assert.equal(envelope.findings.length, 1, name);
    }
  },
);

await test(
  'engine crashes and garbage output fail the engine',
  linux,
  async () => {
    for (const [run, name] of [
      [detekt, 'detekt'],
      [ktlint, 'ktlint'],
    ] as const) {
      await mode(`${name}:crash`);
      const crashed = await run({ 'a.kt': clean });
      assert.equal(crashed.status, 'failed', name);
      assert.equal(crashed.reason, 'engine-error', name);
      await mode(`${name}:garbage`);
      const garbage = await run({ 'a.kt': clean });
      assert.equal(garbage.status, 'failed', name);
      assert.equal(garbage.reason, 'invalid-output', name);
    }
  },
);

await test(
  'a jar that does not match the pinned sha256 is refused and java never runs',
  linux,
  async () => {
    for (const make of [createDetektAdapter, createKtlintAdapter]) {
      await rm(marker, { force: true });
      // No explicit sha: the adapter falls back to the real pin, which the fake jar cannot match.
      const envelope = await runAdapter(make(fakeJava.path, jar, 'v'), {
        scope,
        files: { 'a.kt': clean },
      });
      assert.equal(envelope.status, 'failed');
      assert.equal(envelope.reason, 'engine-version-mismatch');
      assert.equal(await ran(), false);
    }
    assert.match(detektPin.sha256, /^[a-f0-9]{64}$/);
    assert.match(ktlintPin.sha256, /^[a-f0-9]{64}$/);
    assert.notEqual(detektPin.sha256, ktlintPin.sha256);
  },
);

await test('severity maps to the gate scale and unknown labels fail closed', () => {
  assert.equal(normaliseSeverity('detekt', 'error'), 'high');
  assert.equal(normaliseSeverity('detekt', 'warning'), 'medium');
  assert.equal(normaliseSeverity('detekt', 'note'), 'low');
  assert.equal(normaliseSeverity('detekt', 'surprise'), 'high');
  assert.equal(normaliseSeverity('ktlint', 'style'), 'low');
  assert.equal(normaliseSeverity('ktlint', 'surprise'), 'high');
});

await test('parsers reject non-report output and keep no source text', () => {
  assert.throws(() => parseDetektSarif('{"a":1}'));
  assert.throws(() => parseKtlintReport('{"a":1}'));
  const parsed = parseDetektSarif(
    JSON.stringify({
      runs: [
        {
          results: [
            {
              ...sarif('/w/source/x.kt', 'warning', 'detekt.style.A', 1, 1),
              snippet: 'SECRET',
            },
          ],
        },
      ],
    }),
    '/w/source',
  );
  assert.equal(parsed.findings[0]?.path, 'x.kt');
  assert.ok(!JSON.stringify(parsed).includes('SECRET'));
});

await test('Kotlin files make detekt and ktlint applicable; other repos skip them', () => {
  const kotlin = detectApplicability(['app/A.kt', 'build.gradle.kts']);
  assert.equal(kotlin.detekt.applicable, true);
  assert.equal(kotlin.ktlint.applicable, true);
  const none = detectApplicability(['src/a.ts', 'App.java']);
  assert.equal(none.detekt.applicable, false);
  assert.equal(none.detekt.reason, 'no Kotlin files');
  assert.equal(none.ktlint.applicable, false);
});

const commitRepo = async (name: string, content: string) => {
  const repo = await mkdtemp(join(tmpdir(), 'kotlin-repo-'));
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
const selected: EngineId[] = ['detekt', 'ktlint'];
const scanRepo = async (repo: string, java?: string) =>
  (
    await runEngines({
      repo,
      scope,
      selected,
      tools: {},
      installErrors: {},
      gitExecutable: 'git',
      rulesDirectory: repo,
      java,
    })
  ).filter((r) => selected.includes(r.engine));

await test('a repository without Kotlin skips both engines as not applicable', async () => {
  const repo = await commitRepo('app.ts', 'export const a = 1;\n');
  try {
    for (const r of await scanRepo(repo, fakeJava.path)) {
      assert.equal(r.status, 'skipped', r.engine);
      assert.equal(r.skipKind, 'not-applicable', r.engine);
      assert.equal(r.reason, 'no Kotlin files', r.engine);
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test('Kotlin without a Java runtime is skipped with a reason, never clean', async () => {
  const repo = await commitRepo('App.kt', defects);
  try {
    for (const r of await scanRepo(repo, undefined)) {
      assert.equal(r.status, 'skipped', r.engine);
      assert.equal(r.skipKind, 'unavailable', r.engine);
      assert.equal(r.reason, javaSkipReason, r.engine);
      assert.deepEqual(r.findings, [], r.engine);
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test('Kotlin with Java but no installed engine fails, never clean', async () => {
  const repo = await commitRepo('App.kt', defects);
  try {
    for (const r of await scanRepo(repo, fakeJava.path))
      assert.equal(r.status, 'failed', r.engine);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test('findJava prefers JAVA_HOME/bin/java and ignores a relative or missing home', async () => {
  const home = join(dir, 'jdk');
  await mkdir(join(home, 'bin'), { recursive: true });
  await writeFakeExecutable(join(home, 'bin'), 'java', '');
  assert.equal(await findJava({ JAVA_HOME: home }), join(home, 'bin', 'java'));
  const fallback = await findJava({});
  assert.equal(await findJava({ JAVA_HOME: '/nonexistent' }), fallback);
  assert.equal(await findJava({ JAVA_HOME: 'relative/path' }), fallback);
});

await rm(dir, { recursive: true, force: true }).catch(() => undefined);
