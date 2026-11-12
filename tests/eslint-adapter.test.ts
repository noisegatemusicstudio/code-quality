// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: Runs the real pinned ESLint through runAdapter on synthetic inline fixtures (findings, parse failures, config rejection, stable ids, bounded output); not a full hosted service path.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyFiles, runEslintScan } from '../src/eslint-adapter.js';
import {
  benign,
  defects,
  jsCommonjs,
  jsModule,
  malformed,
  scope,
  shifted,
} from './eslint-fixtures.js';

const linux = process.platform === 'linux';
const run = (files: Record<string, string>) => runEslintScan({ scope, files });
const rules = (r: Awaited<ReturnType<typeof run>>) =>
  r.envelope.findings.map((f) => f.ruleId).sort();

await test('classifies supported, unsupported, excluded and customer config files', () => {
  const c = classifyFiles([
    'a.ts',
    'b.mjs',
    'c.cjs',
    'd.js',
    'e.py',
    'f.jsx',
    'g.tsx',
    'node_modules/x/i.js',
    'dist/o.js',
    'x.min.js',
    'eslint.config.js',
    '.eslintrc.json',
  ]);
  assert.deepEqual(c.supported, [
    'a.ts',
    'b.mjs',
    'c.cjs',
    'd.js',
    'f.jsx',
    'g.tsx',
  ]);
  assert.deepEqual(c.unsupported, ['e.py']);
  assert.equal(c.excluded.length, 3);
  assert.deepEqual(c.customerConfig, ['.eslintrc.json', 'eslint.config.js']);
});

await test(
  'known defects produce findings with native severity and versions',
  { skip: !linux },
  async () => {
    const r = await run({ 'src/bad.ts': defects, 'src/ok.ts': benign });
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.envelope.provenance, 'adapter-executed');
    assert.ok(r.envelope.findings.length >= 3, JSON.stringify(rules(r)));
    assert.ok(r.envelope.findings.every((f) => f.path === 'src/bad.ts'));
    assert.ok(rules(r).includes('eqeqeq') || rules(r).includes('no-debugger'));
    assert.ok(r.envelope.findings.every((f) => f.nativeSeverity === 'error'));
    assert.equal(r.report.analysis, 'lint');
    assert.deepEqual(r.report.notAnalysed, [
      'sast',
      'dependencies',
      'coverage',
      'duplication',
    ]);
    assert.equal(r.report.versions?.eslint, '10.13.0');
    assert.equal(r.report.versions?.parser, '8.72.1');
    assert.equal(r.envelope.engine.version, '10.13.0');
    assert.equal(r.envelope.rulesetVersion, 'typescript-eslint-8.72.1');
    assert.equal(r.report.lintedFiles, 2);
  },
);

await test(
  'benign code is clean but reported only as lint',
  { skip: !linux },
  async () => {
    const r = await run({ 'ok.ts': benign });
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.envelope.findings.length, 0);
    assert.equal(r.report.analysis, 'lint');
  },
);

await test(
  'JavaScript-only scope supports ESM and CommonJS without TS config',
  { skip: !linux },
  async () => {
    const r = await run({
      'a.cjs': jsCommonjs,
      'b.mjs': jsModule,
      'c.js': jsModule,
    });
    assert.equal(r.envelope.status, 'completed');
    assert.deepEqual(rules(r), ['no-unused-vars']);
    assert.equal(r.envelope.findings[0].path, 'a.cjs');
  },
);

await test(
  'malformed syntax is a parse failure, incomplete, never clean',
  { skip: !linux },
  async () => {
    const r = await run({ 'broken.ts': malformed, 'ok.ts': benign });
    assert.equal(r.envelope.status, 'incomplete');
    assert.equal(r.envelope.reason, 'parse-failure');
    assert.deepEqual(r.report.parseFailures, ['broken.ts']);
    assert.equal(r.envelope.findings.length, 0);
  },
);

await test(
  'unsupported files are reported distinctly and do not hide supported ones',
  { skip: !linux },
  async () => {
    const r = await run({
      'ok.ts': benign,
      'app.py': 'x=1',
      'ui.vue': '<template/>',
    });
    assert.equal(r.envelope.status, 'completed');
    assert.deepEqual(r.report.unsupportedFiles, ['app.py', 'ui.vue']);
    const none = await run({ 'app.py': 'x=1' });
    assert.equal(none.envelope.status, 'skipped');
    assert.equal(none.envelope.reason, 'no-supported-files');
  },
);

await test(
  'JSX in .js/.jsx/.mjs/.cjs and TSX parse with the bundled parser; broken files are still named',
  { skip: !linux },
  async () => {
    const r = await run({
      'a.js': 'export const A = () => <div className="a">{1}</div>;\n',
      'b.jsx': 'export const B = () => <><span /></>;\n',
      'c.mjs': 'export const C = () => <i />;\n',
      'd.cjs': 'module.exports = () => <b />;\n',
      'e.tsx': 'export const E = <T,>(p: { v: T }) => <p>{String(p.v)}</p>;\n',
      'f.ts': 'const g = <T,>(x: T): T => x;\nexport { g };\n',
      'ok.ts': benign,
    });
    assert.deepEqual(r.report.parseFailures, []);
    assert.equal(r.envelope.status, 'completed');
    assert.equal(r.report.lintedFiles, 7);
    const broken = await run({ 'x.tsx': 'const = <div', 'ok.ts': benign });
    assert.equal(broken.envelope.status, 'incomplete');
    assert.equal(broken.envelope.reason, 'parse-failure');
    assert.deepEqual(broken.report.parseFailures, ['x.tsx']);
  },
);

await test('customer executable config is rejected and never loaded', async () => {
  const marker = 'globalThis.__loaded = true; throw new Error("executed");';
  for (const name of [
    'eslint.config.js',
    'eslint.config.ts',
    '.eslintrc.cjs',
    'pkg/eslint.config.mjs',
  ]) {
    const r = await run({ 'ok.ts': benign, [name]: marker });
    assert.equal(r.envelope.status, 'skipped', name);
    assert.equal(r.envelope.reason, 'customer-config-rejected');
    assert.equal(r.envelope.findings.length, 0);
  }
});

await test(
  'inline comments cannot disable or reconfigure bundled rules',
  { skip: !linux },
  async () => {
    const r = await run({ 'x.ts': '/* eslint-disable */\n' + defects });
    assert.ok(r.envelope.findings.length >= 3);
  },
);

await test(
  'fingerprints are unique and survive unrelated line shifts',
  { skip: !linux },
  async () => {
    const a = await run({ 'x.ts': defects });
    const b = await run({ 'x.ts': shifted });
    const fp = (r: typeof a) =>
      r.envelope.findings.map((f) => f.fingerprint).sort();
    assert.equal(new Set(fp(a)).size, a.envelope.findings.length);
    assert.deepEqual(fp(a), fp(b));
    assert.notEqual(
      a.envelope.findings[0].range.startLine,
      b.envelope.findings[0].range.startLine,
    );
  },
);

await test(
  'output is bounded: oversize reports fail closed',
  { skip: !linux },
  async () => {
    const many = Array.from({ length: 4000 }, (_, i) => `var v${i} = 1;`).join(
      '\n',
    );
    const r = await run({ 'big.js': many });
    assert.ok(['failed', 'incomplete'].includes(r.envelope.status));
    assert.notEqual(r.envelope.status, 'completed');
  },
);
