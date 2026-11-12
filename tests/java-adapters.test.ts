/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves PMD SARIF and Checkstyle XML parsing, the severity mapping, fixed source-only arguments, the sha256/tree pin refusals, the JDK launcher and the Java applicability and SpotBugs-skipped rules by running fake java launchers through runAdapter and runEngines on synthetic Java sources; does not run the real PMD, Checkstyle or JDK (the pull request's quality scan job does).
*/
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  access,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { writeFakeExecutable } from './fake-executable.js';
import { makeSyntheticOsvZip } from './osv-fixtures.js';
import { runAdapter } from '../src/scanner-adapter.js';
import {
  createCheckstyleAdapter,
  createPmdAdapter,
  parseCheckstyleXml,
  parsePmdSarif,
  runCheckstyleScan,
  runPmdScan,
} from '../src/java-adapters.js';
import { jvmFlags, resolveJava } from '../src/java-runtime.js';
import {
  detectApplicability,
  normaliseSeverity,
  type EngineId,
} from '../src/quality-scan.js';
import { detectLanguages } from '../src/language-detection.js';
import { runEngines, scopeFromEnvironment } from '../src/quality-scan-run.js';
import {
  checkstylePin,
  pmdPin,
  releaseAssets,
  releaseTrees,
  spotbugsPin,
} from '../src/scanner-pins.js';
import {
  installZipTree,
  treeDigest,
  treeMatches,
} from '../src/tree-install.js';
import { createHash } from 'node:crypto';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const dir = await mkdtemp(join(tmpdir(), 'java-test-'));
const marker = join(dir, 'ran');
const configFile = join(dir, 'config.json');
const argsFile = join(dir, 'args.json');
const sha = (text: string) => createHash('sha256').update(text).digest('hex');

// Synthetic source with a known violation: a public method without Javadoc,
// an unused local and an empty catch block.
const sample = `package app;

public class Sample {
  public int Unused(int a) {
    int unused = 5;
    try {
      return a;
    } catch (Exception e) {
    }
    return 0;
  }
}
`;
const sampleFiles = { 'src/main/java/app/Sample.java': sample };

// The fake `java` records what it was asked to run, hashes the jar it was
// handed, and prints the configured report. `@CWD@` stands for the workspace.
const fakeBody = `const fs = require('node:fs');
const crypto = require('node:crypto');
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(marker)}, 'ran');
const cfg = JSON.parse(fs.readFileSync(${JSON.stringify(configFile)}, 'utf8'));
if (args[args.length - 1] === '--version') { console.log(cfg.version); process.exit(0); }
const jar = args.includes('-jar') ? args[args.indexOf('-jar') + 1] : undefined;
const jarSha = jar && fs.existsSync(jar) ? crypto.createHash('sha256').update(fs.readFileSync(jar)).digest('hex') : null;
fs.writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify({ args, cwd: process.cwd(), jarSha }));
console.log(cfg.out.split('@CWD@').join(process.cwd()));
process.exit(cfg.code);
`;
const fakeJava = await writeFakeExecutable(dir, 'fake-java', fakeBody);
const jarText = 'fake checkstyle jar bytes';
const jar = join(dir, 'checkstyle.jar');
await writeFile(jar, jarText);
const pmdDirectory = join(dir, 'pmd');
const pmdVersionLine = `PMD ${pmdPin.version} (30-Oct-2026) for Linux 6.1 running on Java 21`;

const configure = (config: { out?: string; code?: number; version?: string }) =>
  writeFile(
    configFile,
    JSON.stringify({ out: '', code: 0, version: '', ...config }),
  );
const ran = () =>
  access(marker).then(
    () => true,
    () => false,
  );
const reset = () => rm(marker, { force: true });

const xml = (body: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<checkstyle version="${checkstylePin.version}">\n${body}</checkstyle>\n`;
const checkstyleReport = xml(
  `<file name="@CWD@/./src/main/java/app/Sample.java">\n` +
    `<error line="4" column="14" severity="warning" message="Method name &apos;Unused&apos; must match pattern &quot;^[a-z]\\w*$&quot; &amp; more" source="com.puppycrawl.tools.checkstyle.checks.naming.MethodNameCheck"/>\n` +
    `<error line="1" severity="error" message="Missing package-info.java" source="com.puppycrawl.tools.checkstyle.checks.javadoc.JavadocPackageCheck"/>\n` +
    `</file>\n<file name="@CWD@/src/Clean.java">\n</file>\n`,
);
const checkstyleScan = (files: Record<string, string> = sampleFiles) =>
  runAdapter(createCheckstyleAdapter(fakeJava.path, jar, sha(jarText)), {
    scope,
    files,
  });

await test(
  'Checkstyle: a known violation becomes a finding with its native severity and a relative path',
  linux,
  async () => {
    await configure({
      version: `Checkstyle version: ${checkstylePin.version}`,
      out: checkstyleReport,
    });
    const envelope = await checkstyleScan();
    assert.equal(envelope.status, 'completed');
    assert.equal(envelope.engine.id, 'checkstyle');
    assert.deepEqual(
      envelope.findings.map((f) => [f.ruleId, f.nativeSeverity, f.path]),
      [
        ['JavadocPackageCheck', 'error', 'src/main/java/app/Sample.java'],
        ['MethodNameCheck', 'warning', 'src/main/java/app/Sample.java'],
      ],
    );
    assert.equal(envelope.findings[1]?.range.startLine, 4);
    assert.equal(envelope.findings[1]?.range.startColumn, 14);
    assert.equal(envelope.findings[0]?.range.startColumn, 1);
    assert.match(
      envelope.findings[1]?.message ?? '',
      /^Method name 'Unused' must match pattern "\^\[a-z\]\\w\*\$" & more$/,
    );
    assert.match(
      envelope.findings[0]?.fingerprint ?? '',
      /^sha256:[a-f0-9]{64}$/,
    );
  },
);

await test(
  'Checkstyle runs source-only: fixed Google-checks arguments on the verified jar, nothing from the caller',
  linux,
  async () => {
    await configure({
      version: `Checkstyle version: ${checkstylePin.version}`,
      out: xml(''),
    });
    const envelope = await checkstyleScan();
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(envelope.findings, []);
    const seen = JSON.parse(
      await (await import('node:fs/promises')).readFile(argsFile, 'utf8'),
    ) as { args: string[]; cwd: string; jarSha: string };
    const adapter = createCheckstyleAdapter(fakeJava.path, jar);
    assert.deepEqual(seen.args.slice(0, jvmFlags.length), [...jvmFlags]);
    assert.equal(seen.args[jvmFlags.length], '-jar');
    // The jar that runs is the private copy of the bytes that were hashed.
    assert.notEqual(seen.args[jvmFlags.length + 1], jar);
    assert.equal(seen.jarSha, sha(jarText));
    assert.deepEqual(seen.args.slice(jvmFlags.length + 2), [
      '-c',
      '/google_checks.xml',
      '-f',
      'xml',
      '.',
    ]);
    assert.deepEqual(seen.args.slice(jvmFlags.length + 2), [
      ...adapter.fixedArgs,
    ]);
    assert.ok(seen.cwd.endsWith('/source'));
  },
);

await test(
  'Checkstyle: a jar that does not match the sha256 pin is refused before java runs',
  linux,
  async () => {
    await reset();
    await configure({ version: 'x', out: xml('') });
    const envelope = await runAdapter(
      createCheckstyleAdapter(fakeJava.path, jar, sha('another jar')),
      { scope, files: sampleFiles },
    );
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
    assert.equal(await ran(), false);
    // The public runner uses the real pin, which the fake jar cannot satisfy.
    const real = await runCheckstyleScan({
      java: fakeJava.path,
      jar,
      scope,
      files: sampleFiles,
    });
    assert.equal(real.status, 'failed');
    assert.equal(real.reason, 'engine-version-mismatch');
    assert.equal(await ran(), false);
  },
);

await test(
  'Checkstyle: a different engine version, a crash and unusable output are failures, never clean',
  linux,
  async () => {
    await configure({ version: 'Checkstyle version: 0.0.1', out: xml('') });
    assert.equal((await checkstyleScan()).reason, 'engine-version-mismatch');
    const good = `Checkstyle version: ${checkstylePin.version}`;
    await configure({ version: good, out: '', code: 255 });
    const crashed = await checkstyleScan();
    assert.equal(crashed.status, 'failed');
    assert.equal(crashed.reason, 'engine-error');
    await configure({ version: good, out: 'Starting audit...\nnot xml' });
    const garbage = await checkstyleScan();
    assert.equal(garbage.status, 'failed');
    assert.equal(garbage.reason, 'invalid-output');
  },
);

await test('Checkstyle parser refuses a report that drops or hides violations', () => {
  const broken = xml(
    `<file name="a/A.java">\n<error line="1" severity="warning" message="m" source="x.YCheck"/>\n<error broken>\n</file>\n`,
  );
  assert.throws(() => parseCheckstyleXml(broken), /unrecognised/);
  assert.throws(
    () => parseCheckstyleXml('<!DOCTYPE x [<!ENTITY a "b">]><checkstyle/>'),
    /not a Checkstyle report/,
  );
  assert.throws(() => parseCheckstyleXml('plain text'), /not a Checkstyle/);
  // Progress text before the XML is tolerated; the report itself is not.
  const tolerated = parseCheckstyleXml(
    `Starting audit...\n${xml('<file name="a/A.java">\n<error line="2" column="3" severity="info" message="m" source="x.YCheck"/>\n</file>\n')}`,
  );
  assert.equal(tolerated.findings.length, 1);
  assert.equal(tolerated.partial, undefined);
  // An unknown severity or a path outside the workspace marks the run incomplete.
  const odd = parseCheckstyleXml(
    xml(
      `<file name="a/A.java">\n<error line="2" severity="fatal" message="m" source="x.YCheck"/>\n</file>\n<file name="../../etc/passwd">\n</file>\n`,
    ),
  );
  assert.equal(odd.findings.length, 0);
  assert.equal(odd.partial, 'invalid-output');
});

const sarif = (results: unknown[], extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PMD',
            version: pmdPin.version,
            rules: [
              {
                id: 'UnusedLocalVariable',
                defaultConfiguration: { level: 'note' },
              },
              {
                id: 'EmptyCatchBlock',
                defaultConfiguration: { level: 'warning' },
              },
            ],
          },
        },
        results,
        ...extra,
      },
    ],
  });
const result = (
  ruleId: string,
  uri: string,
  startLine: number,
  extra: Record<string, unknown> = {},
) => ({
  ruleId,
  message: { text: `${ruleId} violated` },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri },
        region: {
          startLine,
          startColumn: 9,
          endLine: startLine,
          endColumn: 20,
        },
      },
    },
  ],
  ...extra,
});
const pmdScan = (versionOutput = pmdVersionLine) =>
  runAdapter(createPmdAdapter(fakeJava.path, pmdDirectory, versionOutput), {
    scope,
    files: sampleFiles,
  });

await test(
  'PMD: known violations become findings; level comes from the result, else the rule, else SARIF default',
  linux,
  async () => {
    await configure({
      version: pmdVersionLine,
      out: sarif([
        result('UnusedLocalVariable', 'src/main/java/app/Sample.java', 5, {
          ruleIndex: 0,
        }),
        result(
          'EmptyCatchBlock',
          'file://@CWD@/src/main/java/app/Sample.java',
          8,
          {
            ruleIndex: 1,
            level: 'error',
          },
        ),
        result(
          'UncommentedEmptyMethodBody',
          '@CWD@/src/main/java/app/Sample.java',
          4,
        ),
      ]),
    });
    const envelope = await pmdScan();
    assert.equal(envelope.status, 'completed');
    assert.equal(envelope.engine.id, 'pmd');
    assert.deepEqual(
      envelope.findings.map((f) => [
        f.ruleId,
        f.nativeSeverity,
        f.path,
        f.range.startLine,
      ]),
      [
        [
          'UncommentedEmptyMethodBody',
          'warning',
          'src/main/java/app/Sample.java',
          4,
        ],
        ['UnusedLocalVariable', 'note', 'src/main/java/app/Sample.java', 5],
        ['EmptyCatchBlock', 'error', 'src/main/java/app/Sample.java', 8],
      ],
    );
  },
);

await test(
  'PMD runs source-only with the quickstart ruleset on the pinned distribution classpath',
  linux,
  async () => {
    await configure({ version: pmdVersionLine, out: sarif([]) });
    const envelope = await pmdScan();
    assert.equal(envelope.status, 'completed');
    assert.deepEqual(envelope.findings, []);
    const seen = JSON.parse(
      await (await import('node:fs/promises')).readFile(argsFile, 'utf8'),
    ) as { args: string[] };
    const adapter = createPmdAdapter(fakeJava.path, pmdDirectory, 'x');
    assert.deepEqual(seen.args.slice(0, jvmFlags.length), [...jvmFlags]);
    assert.deepEqual(seen.args.slice(jvmFlags.length, jvmFlags.length + 3), [
      '-cp',
      `${pmdDirectory}/lib/*`,
      'net.sourceforge.pmd.cli.PmdCli',
    ]);
    assert.deepEqual(seen.args.slice(jvmFlags.length + 3), [
      ...adapter.fixedArgs,
    ]);
    assert.ok(adapter.fixedArgs.includes('rulesets/java/quickstart.xml'));
    assert.ok(adapter.fixedArgs.includes('--no-cache'));
    assert.ok(adapter.fixedArgs.includes('--no-fail-on-violation'));
  },
);

await test(
  'PMD: version drift, processing errors and unusable output are never clean',
  linux,
  async () => {
    await configure({ version: 'PMD 1.0.0', out: sarif([]) });
    assert.equal((await pmdScan()).reason, 'engine-version-mismatch');

    await configure({
      version: pmdVersionLine,
      out: sarif(
        [result('EmptyCatchBlock', 'src/main/java/app/Sample.java', 8)],
        {
          invocations: [
            {
              executionSuccessful: true,
              toolExecutionNotifications: [
                {
                  level: 'error',
                  message: { text: 'Cannot parse Broken.java' },
                },
              ],
            },
          ],
        },
      ),
    });
    const noted = await pmdScan();
    assert.equal(noted.status, 'incomplete');
    assert.equal(noted.reason, 'parse-failure');
    assert.equal(noted.findings.length, 1);

    await configure({
      version: pmdVersionLine,
      out: sarif([
        result('EmptyCatchBlock', 'src/main/java/app/Sample.java', 8),
        { ruleId: 'X', message: 'not an object' },
        result('EmptyCatchBlock', '../outside/Escape.java', 1),
        result('EmptyCatchBlock', 'src/main/java/app/Sample.java', 9, {
          level: 'fatal',
        }),
      ]),
    });
    const partial = await pmdScan();
    assert.equal(partial.status, 'incomplete');
    assert.equal(partial.reason, 'invalid-output');
    assert.equal(partial.findings.length, 1);

    await configure({ version: pmdVersionLine, out: 'Not SARIF' });
    assert.equal((await pmdScan()).reason, 'invalid-output');
    await configure({ version: pmdVersionLine, out: '', code: 5 });
    const recoverable = await pmdScan();
    assert.equal(recoverable.status, 'failed');
    assert.equal(recoverable.reason, 'engine-error');
  },
);

await test('PMD parser: a SARIF report needs exactly one run with results', () => {
  assert.throws(() => parsePmdSarif('{"runs":[]}'), /not a PMD SARIF/);
  assert.throws(() => parsePmdSarif('[]'), /not a PMD SARIF/);
  assert.deepEqual(parsePmdSarif(sarif([])).findings, []);
});

const gitRepo = async (files: Record<string, string>) => {
  const repo = await mkdtemp(join(tmpdir(), 'java-repo-'));
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
  git('init', '-q');
  for (const [name, content] of Object.entries(files)) {
    await mkdir(join(repo, name, '..'), { recursive: true });
    await writeFile(join(repo, name), content);
  }
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
const runAll = (repo: string, tools: Record<string, string> = {}) =>
  runEngines({
    repo,
    scope,
    selected: ['pmd', 'checkstyle', 'spotbugs'] satisfies EngineId[],
    tools,
    installErrors: {},
    gitExecutable: 'git',
    rulesDirectory: repo,
  });

await test(
  'PMD: the installed tree must match the pin before it runs (end to end through runEngines)',
  linux,
  async () => {
    await reset();
    const repo = await gitRepo({ 'src/Sample.java': sample });
    try {
      const results = await runEngines({
        repo,
        scope,
        selected: ['pmd', 'checkstyle'],
        tools: { java: fakeJava.path, pmd: pmdDirectory, checkstyle: jar },
        installErrors: {},
        gitExecutable: 'git',
        rulesDirectory: repo,
      });
      const byEngine = new Map(results.map((r) => [r.engine, r]));
      // Neither a missing PMD tree nor a jar with another digest can pass.
      assert.equal(byEngine.get('pmd')?.status, 'failed');
      assert.equal(byEngine.get('checkstyle')?.status, 'failed');
      assert.equal(await ran(), false);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  },
);

await test('severity mapping: PMD and Checkstyle labels map to the gate scale and unknown labels fail closed', () => {
  for (const engine of ['pmd', 'checkstyle'] as const) {
    assert.equal(normaliseSeverity(engine, 'error'), 'medium', engine);
    assert.equal(normaliseSeverity(engine, 'warning'), 'low', engine);
    assert.equal(normaliseSeverity(engine, 'WARNING'), 'low', engine);
    assert.equal(normaliseSeverity(engine, 'fatal'), 'high', engine);
    assert.equal(normaliseSeverity(engine, ''), 'high', engine);
  }
  assert.equal(normaliseSeverity('pmd', 'note'), 'info');
  assert.equal(normaliseSeverity('checkstyle', 'info'), 'info');
});

await test('pins: release assets agree with the engine pins and versions', () => {
  assert.equal(releaseAssets.checkstyle.binarySha256, checkstylePin.sha256);
  assert.equal(releaseAssets.checkstyle.assetSha256, checkstylePin.sha256);
  assert.ok(releaseAssets.checkstyle.url.includes(`-${checkstylePin.version}`));
  assert.equal(releaseTrees.pmd.treeSha256, pmdPin.treeSha256);
  assert.ok(releaseTrees.pmd.url.includes(pmdPin.version));
  assert.equal(releaseTrees.pmd.member, `pmd-bin-${pmdPin.version}`);
  for (const value of [
    checkstylePin.sha256,
    pmdPin.treeSha256,
    releaseTrees.pmd.assetSha256,
  ])
    assert.match(value, /^[a-f0-9]{64}$/);
  assert.ok(releaseTrees.pmd.url.startsWith('https://'));
});

await test('tree digest: any changed, added or non-regular entry breaks the pin', async () => {
  const tree = join(dir, 'tree');
  await mkdir(join(tree, 'lib'), { recursive: true });
  await writeFile(join(tree, 'lib/a.jar'), 'a');
  await writeFile(join(tree, 'LICENSE'), 'l');
  const digest = await treeDigest(tree);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(await treeMatches(tree, digest), true);
  await writeFile(join(tree, 'lib/a.jar'), 'tampered');
  assert.equal(await treeMatches(tree, digest), false);
  await writeFile(join(tree, 'lib/a.jar'), 'a');
  assert.equal(await treeMatches(tree, digest), true);
  await writeFile(join(tree, 'lib/extra.jar'), 'x');
  assert.equal(await treeMatches(tree, digest), false);
  await rm(join(tree, 'lib/extra.jar'));
  await symlink('/etc/passwd', join(tree, 'lib/link.jar'));
  assert.equal(await treeMatches(tree, digest), false);
  assert.equal(await treeMatches(join(dir, 'missing'), digest), false);
});

await test('tree install: a zip whose tree differs from the pin is refused and nothing is left behind', async () => {
  const bytes = makeSyntheticOsvZip([
    { name: 'top/lib/a.jar', data: Buffer.from('a') },
    { name: 'top/LICENSE', data: Buffer.from('l') },
  ]);
  const reference = join(dir, 'reference');
  await mkdir(join(reference, 'lib'), { recursive: true });
  await writeFile(join(reference, 'lib/a.jar'), 'a');
  await writeFile(join(reference, 'LICENSE'), 'l');
  const good = await treeDigest(reference);
  const target = join(dir, 'engines', 'pmd');
  await assert.rejects(
    installZipTree({ bytes, member: 'top', treeSha256: sha('wrong'), target }),
    /tree sha256 mismatch/,
  );
  await assert.rejects(access(target));
  await installZipTree({ bytes, member: 'top', treeSha256: good, target });
  assert.equal(await treeMatches(target, good), true);
});

await test('no Java files: the Java engines are not applicable, skipped, and never need a JDK', async () => {
  assert.equal(
    detectApplicability(['src/a.ts', 'README.md']).pmd.applicable,
    false,
  );
  const java = detectApplicability(['app/Main.java']);
  for (const id of ['pmd', 'checkstyle', 'spotbugs'] as const) {
    assert.equal(java[id].applicable, true, id);
    assert.equal(detectApplicability(['src/a.ts'])[id].applicable, false, id);
  }
  const repo = await gitRepo({ 'src/a.ts': 'export const a = 1;\n' });
  try {
    const results = (await runAll(repo)).filter((r) =>
      ['pmd', 'checkstyle', 'spotbugs'].includes(r.engine),
    );
    assert.equal(results.length, 3);
    for (const r of results) {
      assert.equal(r.status, 'skipped', r.engine);
      assert.equal(r.skipKind, 'not-applicable', r.engine);
      assert.equal(r.reason, 'no Java files', r.engine);
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test('Java files without the engines installed fail, never pass; SpotBugs is skipped with its reason', async () => {
  const repo = await gitRepo({ 'src/Sample.java': sample });
  try {
    const byEngine = new Map((await runAll(repo)).map((r) => [r.engine, r]));
    assert.equal(byEngine.get('pmd')?.status, 'failed');
    assert.equal(byEngine.get('checkstyle')?.status, 'failed');
    const spotbugs = byEngine.get('spotbugs');
    assert.ok(spotbugs);
    assert.equal(spotbugs.status, 'skipped');
    assert.equal(spotbugs.skipKind, 'unavailable');
    assert.match(spotbugs.reason ?? '', /^requires compiled classes/);
    assert.equal(spotbugs.reason, spotbugsPin.skipReason);
    assert.equal(spotbugs.version, spotbugsPin.version);
    assert.deepEqual(spotbugs.findings, []);
    assert.equal(spotbugs.envelope, undefined);
    assert.notEqual(spotbugs.status, 'completed');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

await test('Java is covered by PMD and Checkstyle in language detection', () => {
  const java = detectLanguages(['app/Main.java']).find(
    (l) => l.language === 'Java',
  );
  assert.equal(java?.status, 'covered');
  assert.deepEqual(java?.engines, ['pmd', 'checkstyle']);
});

await test('JDK launcher: explicit path wins, JAVA_HOME is used, and a missing JDK is an error', async () => {
  const home = join(dir, 'jdk');
  await mkdir(join(home, 'bin'), { recursive: true });
  await writeFile(join(home, 'bin/java'), '');
  assert.deepEqual(resolveJava(undefined, { JAVA_HOME: home }), {
    java: join(home, 'bin/java'),
  });
  assert.deepEqual(resolveJava(fakeJava.path, { JAVA_HOME: home }), {
    java: fakeJava.path,
  });
  for (const [explicit, env] of [
    [undefined, {}],
    [undefined, { JAVA_HOME: join(dir, 'nowhere') }],
    ['relative/java', {}],
  ] as const) {
    const resolved = resolveJava(explicit, env);
    assert.equal(resolved.java, undefined);
    assert.match(resolved.error ?? '', /Java/);
  }
});

await test('a runtime launcher is held to the same executable rules as the engine', async () => {
  const adapter = createCheckstyleAdapter('/bin/sh', jar, sha(jarText));
  await assert.rejects(
    runAdapter(adapter, { scope, files: sampleFiles }),
    /Invalid adapter/,
  );
  const relative = createPmdAdapter('java', pmdDirectory, 'x');
  await assert.rejects(
    runAdapter(relative, { scope, files: sampleFiles }),
    /Invalid adapter/,
  );
  await assert.rejects(
    runPmdScan({
      java: 'java',
      pmdDirectory,
      versionOutput: 'x',
      scope,
      files: sampleFiles,
    }),
    /Invalid adapter/,
  );
});

await rm(dir, { recursive: true, force: true }).catch(() => undefined);
