/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Runs the real Prettier from this checkout through runPrettierScan and runAdapter on synthetic in-memory files (formatting findings, JSON/YAML config, JS config and plugin refusal, .prettierignore, parse errors, strict runner output); does not read a git repository or go through the full scan pipeline.
*/
import assert from 'node:assert/strict';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  approvedPrettierVersion,
  isPrettierFile,
  isPrettierInput,
  parsePrettierReport,
  prettierRuleId,
  readRunnerOutput,
  runPrettierScan,
} from '../src/prettier-adapter.js';
import { scopeFromEnvironment } from '../src/quality-scan-run.js';

const linux = { skip: process.platform !== 'linux' };
const scope = scopeFromEnvironment({}, 'a'.repeat(40));
const run = (files: Record<string, string>) =>
  runPrettierScan({ scope, files });
const paths = (r: Awaited<ReturnType<typeof run>>) =>
  r.envelope.findings.map((f) => f.path);
const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

// Prettier's defaults write double quotes and semicolons.
const formatted = 'const a = "x";\n';
const singleQuoted = "const a = 'x';\n";
// package.json is written the way Prettier's json-stringify parser expects.
const pkg = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
const dir = await mkdtemp(join(tmpdir(), 'prettier-test-'));

await test('selects only supported, non-generated files and config inputs', () => {
  for (const p of ['a.ts', 'b.mjs', 'c.json', 'd.yml', 'e.md', 'f.css'])
    assert.equal(isPrettierFile(p), true, p);
  for (const p of [
    'a.py',
    'package-lock.json',
    'sub/pnpm-lock.yaml',
    'node_modules/x/i.js',
    'dist/o.js',
    'x.min.css',
  ])
    assert.equal(isPrettierFile(p), false, p);
  assert.equal(isPrettierInput('.prettierrc'), true);
  assert.equal(isPrettierInput('web/prettier.config.mjs'), true);
  assert.equal(isPrettierInput('.prettierignore'), true);
  assert.equal(isPrettierInput('sub/.prettierignore'), false);
});

await test(
  'one finding per unformatted file across TS, JSON, YAML, Markdown and CSS',
  linux,
  async () => {
    const r = await run({
      'ok.ts': formatted,
      'bad.ts': 'const   a = "x"\n',
      'bad.json': '{"a":1}\n',
      'bad.yaml': 'a:   1\n',
      'bad.md': '# Title\n\n\n\ntext\n',
      'bad.css': 'a{color:red}\n',
    });
    assert.equal(r.envelope.status, 'completed');
    assert.deepEqual(paths(r), [
      'bad.css',
      'bad.json',
      'bad.md',
      'bad.ts',
      'bad.yaml',
    ]);
    assert.ok(r.envelope.findings.every((f) => f.ruleId === prettierRuleId));
    assert.equal(r.report.checkedFiles, 6);
    assert.equal(r.envelope.engine.version, approvedPrettierVersion);
  },
);

await test(
  'a clean tree is a completed run with no findings and the file count',
  linux,
  async () => {
    const r = await run({ 'ok.ts': formatted, 'ok.json': '{ "a": 1 }\n' });
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.envelope.findings.length, 0);
    assert.equal(r.report.checkedFiles, 2);
  },
);

await test(
  'a JSON .prettierrc.json is honoured and applies to nested files',
  linux,
  async () => {
    const r = await run({
      '.prettierrc.json': '{"singleQuote": true, "semi": false}',
      'a.ts': "const a = 'x'\n",
      'sub/b.ts': formatted,
    });
    assert.deepEqual(paths(r), ['sub/b.ts']);
    assert.deepEqual(r.report.configUsed, ['.prettierrc.json']);
    assert.equal(r.envelope.status, 'completed');
  },
);

await test(
  'an object under package.json "prettier" is honoured; a module name is refused',
  linux,
  async () => {
    const marker = join(dir, 'package-module-ran');
    const object = await run({
      'package.json': pkg({ name: 'x', prettier: { singleQuote: true } }),
      'a.ts': singleQuoted,
    });
    assert.equal(object.envelope.status, 'completed');
    assert.deepEqual(paths(object), []);
    assert.deepEqual(object.report.configUsed, ['package.json']);
    const module = await run({
      'package.json': pkg({ name: 'x', prettier: './cfg.mjs' }),
      'cfg.mjs': `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'x'); export default { singleQuote: true };`,
      'a.ts': singleQuoted,
    });
    assert.equal(await exists(marker), false, 'repository code executed');
    assert.equal(module.envelope.reason, 'customer-config-rejected');
    assert.deepEqual(module.report.configRejected, [
      'package.json: prettier module',
    ]);
    // Defaults flag single quotes, so the module's singleQuote was not applied.
    assert.ok(paths(module).includes('a.ts'));
  },
);

await test('a YAML .prettierrc is honoured', linux, async () => {
  const r = await run({
    '.prettierrc': 'singleQuote: true\n',
    'a.ts': singleQuoted,
    'b.ts': formatted,
  });
  assert.deepEqual(paths(r), ['b.ts']);
  assert.deepEqual(r.report.configUsed, ['.prettierrc']);
});

for (const name of [
  'prettier.config.js',
  'prettier.config.mjs',
  'prettier.config.ts',
  '.prettierrc.cjs',
  '.prettierrc.mts',
])
  await test(
    `${name} is never loaded: defaults apply and the run says why`,
    linux,
    async () => {
      const marker = join(dir, `ran-${name}`);
      const r = await run({
        [name]: `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'x'); export default { singleQuote: true };`,
        'a.ts': singleQuoted,
      });
      assert.equal(await exists(marker), false, 'repository code executed');
      // The config asks for single quotes; defaults flag them, so it was not applied.
      assert.deepEqual(paths(r), ['a.ts']);
      assert.equal(r.envelope.status, 'incomplete');
      assert.equal(r.envelope.reason, 'customer-config-rejected');
      assert.deepEqual(r.report.configRejected, [name]);
      assert.deepEqual(r.report.configUsed, []);
    },
  );

await test(
  'with a JS config present, a valid JSON config elsewhere is not applied either',
  linux,
  async () => {
    const r = await run({
      'prettier.config.js': 'export default {};',
      '.prettierrc.json': '{"singleQuote": true}',
      'a.ts': singleQuoted,
    });
    assert.equal(r.envelope.reason, 'customer-config-rejected');
    // singleQuote: true would accept this file; defaults flag it.
    assert.deepEqual(paths(r), ['a.ts']);
  },
);

await test(
  'config plugins and custom parsers are dropped, not loaded',
  linux,
  async () => {
    const marker = join(dir, 'plugin-ran');
    const r = await run({
      '.prettierrc.json': JSON.stringify({
        plugins: ['./plugin.mjs'],
        parser: './parser.mjs',
      }),
      'plugin.mjs': `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'x'); export default {};`,
      'a.ts': formatted,
    });
    assert.equal(await exists(marker), false, 'plugin code executed');
    assert.equal(r.envelope.status, 'incomplete');
    assert.equal(r.envelope.reason, 'customer-config-rejected');
    assert.deepEqual(r.report.configRejected, [
      '.prettierrc.json: parser',
      '.prettierrc.json: plugins',
    ]);
  },
);

await test(
  '.prettierignore is honoured and ignored files are counted',
  linux,
  async () => {
    const files = {
      'generated/a.ts': 'const   a = 1\n',
      'src/b.ts': 'const   b = 1\n',
    };
    const without = await run(files);
    assert.deepEqual(paths(without), ['generated/a.ts', 'src/b.ts']);
    const withIgnore = await run({
      ...files,
      '.prettierignore': 'generated/\n',
    });
    assert.deepEqual(paths(withIgnore), ['src/b.ts']);
    assert.equal(withIgnore.report.ignoredFiles, 1);
    assert.equal(withIgnore.envelope.status, 'completed');
  },
);

await test(
  'a parse error is incomplete with parse-failure, never a pass, and healthy files still report',
  linux,
  async () => {
    const r = await run({
      'broken.ts': 'const = ;\n',
      'bad.ts': 'const   a = 1\n',
      'broken.json': '{"a": }\n',
    });
    assert.equal(r.envelope.status, 'incomplete');
    assert.equal(r.envelope.reason, 'parse-failure');
    assert.deepEqual(r.report.parseFailures, ['broken.json', 'broken.ts']);
    assert.deepEqual(paths(r), ['bad.ts']);
    assert.ok(
      !JSON.stringify(r).includes('const = ;'),
      'source text must not leak into the result',
    );
  },
);

await test('runner output that is not the expected shape is rejected, not trusted', () => {
  const ok = {
    checked: 1,
    ignored: 0,
    files: [{ path: 'a.ts', state: 'unformatted' }],
    configUsed: [],
    configRejected: [],
  };
  assert.equal(parsePrettierReport(JSON.stringify(ok))?.findings.length, 1);
  for (const bad of [
    { ...ok, files: [{ path: '../x.ts', state: 'unformatted' }] },
    { ...ok, files: [{ path: 'a.ts', state: 'clean' }] },
    { ...ok, checked: -1 },
    { ...ok, configRejected: 'x' },
    [],
    { files: 'no' },
  ])
    assert.equal(readRunnerOutput(JSON.stringify(bad)), undefined);
  assert.throws(() => parsePrettierReport('not json'));
});

await rm(dir, { recursive: true, force: true }).catch(() => undefined);
