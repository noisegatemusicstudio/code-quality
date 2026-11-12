/*
Test classification: contract
Review status: Not Reviewed
Evidence: synthetic
Scope: Parses recorded synthetic Semgrep JSON, runs a fake executable through the adapter to prove policy refusals, argument allowlist and failure states, and validates the starter rule files as YAML; does not run the real semgrep binary or check that the rules match real code.
*/
import assert from 'node:assert/strict';
import {
  access,
  chmod,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';
import { type EnvelopeScope } from '../src/adapter-envelope.js';
import {
  type SemgrepOptions,
  createSemgrepAdapter,
  isLocalRulesPath,
  parseSemgrepReport,
  releaseReadyRulesVersion,
  runSemgrepScan,
  semgrepVersion,
} from '../src/semgrep-adapter.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'c'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
// Synthetic; looks like a secret to prove matched source is never copied.
const dummyCode = 'const apiKey = "dummy-not-real-0123456789abcdef";';
const rulesPath = '/opt/releaseready/rules/semgrep';
const loc = (ln: number) => ({
  path: 'src/a.ts',
  start: { line: ln, col: 1, offset: 0 },
  end: { line: ln, col: 9, offset: 8 },
});
const vulnerable = {
  version: '1.185.0',
  errors: [],
  results: [
    {
      check_id: 'opt.releaseready.rules.semgrep.releaseready.js.no-eval',
      path: 'src/a.ts',
      start: { line: 4, col: 3, offset: 40 },
      end: { line: 4, col: 20, offset: 57 },
      extra: {
        message:
          'Dynamic code evaluation can execute attacker-controlled code.',
        severity: 'ERROR',
        lines: dummyCode,
        fix: dummyCode,
        metadata: {
          cwe: ['CWE-95: Improper Neutralization of Directives'],
          confidence: 'HIGH',
          'finding-type': 'vulnerability',
          remediation: 'Replace dynamic evaluation with a lookup.',
        },
        dataflow_trace: {
          taint_source: ['CliLoc', [loc(2), dummyCode]],
          intermediate_vars: [{ location: loc(3), content: dummyCode }],
          taint_sink: ['CliLoc', [loc(4), dummyCode]],
        },
      },
    },
    {
      check_id: 'releaseready.js.dynamic-require',
      path: './src/b.ts',
      start: { line: 1, col: 1 },
      end: { line: 1, col: 12 },
      extra: {
        message: 'Module loaded from a non-literal path.',
        severity: 'WARNING',
        metadata: { cwe: 'CWE-829: Inclusion', confidence: 'LOW' },
      },
    },
  ],
};
const safe = { version: '1.185.0', errors: [], results: [] };
const json = (o: unknown) => JSON.stringify(o);

// The fake fails (exit 3) unless it receives exactly the reviewed arguments.
const expectedArgs = [
  'scan',
  '--json',
  '--metrics=off',
  '--disable-version-check',
  '--config',
  rulesPath,
  '.',
];
const dir = await mkdtemp(join(tmpdir(), 'semgrep-test-'));
const marker = join(dir, 'ran');
const fakeSource = `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(marker)}, 'ran');
const mode = fs.readFileSync(${JSON.stringify(join(dir, 'mode.txt'))}, 'utf8').trim();
if (args[0] === '--version') { console.log(mode === 'old' ? '1.0.0' : '${semgrepVersion}'); process.exit(0); }
if (JSON.stringify(args) !== ${JSON.stringify(JSON.stringify(expectedArgs))}) { console.error('unexpected args'); process.exit(3); }
if (mode === 'vulnerable') { console.log(${JSON.stringify(json(vulnerable))}); process.exit(0); }
if (mode === 'partial') { console.log(${JSON.stringify(json({ ...vulnerable, errors: [{ type: 'PartialParsing', path: 'src/c.ts' }] }))}); process.exit(0); }
if (mode === 'crash') { process.exit(2); }
if (mode === 'garbage') { console.log('not json'); process.exit(0); }
console.log(${JSON.stringify(json(safe))});
`;
const executable = join(dir, 'fake-semgrep');
await writeFile(executable, fakeSource);
await chmod(executable, 0o755);
const modeFile = join(dir, 'mode.txt');
await writeFile(modeFile, 'safe');
const options: SemgrepOptions = {
  executable,
  ruleset: {
    source: 'releaseready-authored',
    path: rulesPath,
    version: releaseReadyRulesVersion,
  },
};
const run = async (
  mode: string,
  opts: SemgrepOptions = options,
  files = {},
) => {
  await writeFile(modeFile, mode);
  return runSemgrepScan(opts, {
    scope,
    files: { 'src/a.ts': 'export {};\n', ...files },
  });
};
const reset = () => rm(marker, { force: true });
const ran = () =>
  access(marker).then(
    () => true,
    () => false,
  );
const linuxOnly = { skip: process.platform !== 'linux' };

await test('parser keeps rule, CWE, severity, confidence, range, flow locations and remediation', () => {
  const { findings, details, partial } = parseSemgrepReport(json(vulnerable));
  assert.equal(partial, undefined);
  assert.equal(findings.length, 2);
  const eval_ = findings.find((f) => f.path === 'src/a.ts');
  assert.equal(eval_?.ruleId, 'releaseready.js.no-eval');
  assert.equal(eval_.nativeSeverity, 'ERROR');
  assert.deepEqual(eval_.range, {
    startLine: 4,
    startColumn: 3,
    endLine: 4,
    endColumn: 20,
  });
  assert.match(eval_.message, /^Vulnerability: .*\(CWE-95\)$/);
  const d = details[eval_.fingerprint];
  assert.equal(d.kind, 'vulnerability');
  assert.equal(d.confidence, 'HIGH');
  assert.deepEqual(d.cwe, ['CWE-95']);
  assert.deepEqual(d.dataflow, {
    source: { path: 'src/a.ts', line: 2 },
    intermediateCount: 1,
    sink: { path: 'src/a.ts', line: 4 },
  });
  assert.equal(d.remediation, 'Replace dynamic evaluation with a lookup.');
  assert.doesNotMatch(
    JSON.stringify({ findings, details }),
    /dummy-not-real|apiKey/,
  );
});

await test('low-confidence findings are review-required hotspots, not vulnerabilities', () => {
  const { findings, details } = parseSemgrepReport(json(vulnerable));
  const hotspot = findings.find((f) => f.path === 'src/b.ts');
  assert.match(hotspot?.message ?? '', /^Review required: /);
  assert.equal(
    details[hotspot?.fingerprint ?? ''].kind,
    'review-required-hotspot',
  );
  assert.deepEqual(details[hotspot?.fingerprint ?? ''].cwe, ['CWE-829']);
  // No stated confidence must not be promoted to a vulnerability.
  const bare = parseSemgrepReport(
    json({
      results: [
        {
          check_id: 'x.y',
          path: 'a.ts',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 2 },
          extra: { message: 'm', severity: 'INFO' },
        },
      ],
    }),
  );
  assert.equal(Object.values(bare.details)[0]?.kind, 'review-required-hotspot');
});

await test('safe report yields no findings; unusable or partial reports are flagged', () => {
  assert.deepEqual(parseSemgrepReport(json(safe)), {
    findings: [],
    details: {},
  });
  assert.throws(() => parseSemgrepReport('not json'));
  assert.throws(() => parseSemgrepReport('{"results": 3}'));
  assert.equal(
    parseSemgrepReport(json({ ...safe, errors: [{ type: 'x' }] })).partial,
    'engine-error',
  );
  const bad = parseSemgrepReport(
    json({
      results: [
        {
          check_id: 'x',
          path: '../../etc/passwd',
          start: { line: 1 },
          end: { line: 1 },
          extra: { severity: 'ERROR' },
        },
      ],
    }),
  );
  assert.equal(bad.findings.length, 0);
  assert.equal(bad.partial, 'invalid-output');
});

await test('adapter pins version and fixes a local-config allowlist with no caller args', () => {
  const adapter = createSemgrepAdapter(options);
  assert.equal(adapter.engine.version, '1.185.0');
  assert.deepEqual(adapter.fixedArgs, expectedArgs);
  assert.deepEqual(adapter.allowedArgs, []);
  assert.doesNotMatch(adapter.fixedArgs.join(' '), /\bauto\b|\bp\/|https?:/);
});

await test(
  'registry and non-local configs are rejected before the engine runs',
  linuxOnly,
  async () => {
    await reset();
    for (const path of [
      'auto',
      'p/default',
      'r/javascript.lang',
      'https://semgrep.dev/c/p/ci',
      '--config=auto',
      'relative/rules',
      '/rules/../etc',
      '',
    ]) {
      assert.equal(isLocalRulesPath(path), false, path);
      const result = await run('safe', {
        ...options,
        ruleset: { ...options.ruleset, path },
      });
      assert.equal(result.refusal, 'registry-config', path);
      assert.equal(result.envelope.status, 'skipped');
      assert.equal(result.envelope.reason, 'customer-config-rejected');
      assert.deepEqual(result.envelope.findings, []);
    }
    assert.equal(await ran(), false);
  },
);

await test(
  'internal-only ruleset is refused unless the scope is explicitly internal',
  linuxOnly,
  async () => {
    await reset();
    const internal: SemgrepOptions = {
      ...options,
      ruleset: { ...options.ruleset, source: 'semgrep-maintained-snapshot' },
    };
    for (const audience of [undefined, 'customer', 'Internal', true] as const) {
      const result = await run('vulnerable', {
        ...internal,
        audience: audience as never,
      });
      assert.equal(result.refusal, 'internal-only-ruleset');
      assert.equal(result.envelope.status, 'skipped');
      assert.deepEqual(result.envelope.findings, []);
    }
    assert.equal(await ran(), false);
    const allowed = await run('safe', { ...internal, audience: 'internal' });
    assert.equal(allowed.refusal, undefined);
    assert.equal(allowed.envelope.status, 'completed');
    assert.equal(
      allowed.envelope.rulesetVersion,
      `semgrep-maintained-snapshot-${releaseReadyRulesVersion}`,
    );
  },
);

await test(
  'unapproved ruleset sources are skipped, never substituted',
  linuxOnly,
  async () => {
    await reset();
    for (const source of ['codeql', 'sonar', 'third-party-pack', '']) {
      const result = await run('safe', {
        ...options,
        ruleset: { ...options.ruleset, source: source as never },
      });
      assert.equal(result.refusal, 'unapproved-ruleset');
      assert.equal(result.envelope.status, 'skipped');
    }
    assert.equal(await ran(), false);
  },
);

await test(
  'unsupported languages are skipped with an explicit reason and listed',
  linuxOnly,
  async () => {
    await reset();
    const result = await runSemgrepScan(options, {
      scope,
      files: { 'main.py': 'x = 1\n', 'Main.java': 'class A {}' },
    });
    assert.equal(result.refusal, 'unsupported-language');
    assert.equal(result.envelope.status, 'skipped');
    assert.equal(result.envelope.reason, 'no-supported-files');
    assert.deepEqual(
      result.unsupportedFiles.sort((a, b) => a.localeCompare(b, 'en')),
      ['Main.java', 'main.py'],
    );
    assert.equal(await ran(), false);
    const mixed = await run('safe', options, { 'main.py': 'x = 1\n' });
    assert.equal(mixed.envelope.status, 'completed');
    assert.ok(mixed.unsupportedFiles.includes('main.py'));
  },
);

await test(
  'vulnerable fixture produces findings with details; safe fixture is clean',
  linuxOnly,
  async () => {
    const vuln = await run('vulnerable');
    assert.equal(vuln.envelope.status, 'completed');
    assert.equal(vuln.envelope.provenance, 'adapter-executed');
    assert.equal(vuln.envelope.findings.length, 2);
    assert.equal(Object.keys(vuln.details).length, 2);
    assert.match(vuln.notice, /not a Sonar-equivalent/i);
    const clean = await run('safe');
    assert.equal(clean.envelope.status, 'completed');
    assert.deepEqual(clean.envelope.findings, []);
  },
);

await test(
  'engine errors array makes the run incomplete, keeping its findings',
  linuxOnly,
  async () => {
    const result = await run('partial');
    assert.equal(result.envelope.status, 'incomplete');
    assert.equal(result.envelope.reason, 'engine-error');
    assert.equal(result.envelope.findings.length, 2);
  },
);

await test(
  'parse failure, crash and version drift fail with a reason and no findings',
  linuxOnly,
  async () => {
    const garbage = await run('garbage');
    assert.equal(garbage.envelope.status, 'failed');
    assert.equal(garbage.envelope.reason, 'invalid-output');
    assert.deepEqual(garbage.details, {});
    const crash = await run('crash');
    assert.equal(crash.envelope.reason, 'engine-error');
    const old = await run('old');
    assert.equal(old.envelope.status, 'failed');
    assert.equal(old.envelope.reason, 'engine-version-mismatch');
  },
);

await test('starter rule files are valid YAML with required fields', async () => {
  const rulesDir = new URL('../../rules/semgrep/', import.meta.url);
  const files = (await readdir(rulesDir))
    .filter((f) => f.endsWith('.yaml'))
    .sort((a, b) => a.localeCompare(b, 'en'));
  assert.ok(
    files.length >= 5 && files.length <= 8,
    `rule count ${String(files.length)}`,
  );
  const ids = new Set<string>();
  for (const file of files) {
    const source = await readFile(new URL(file, rulesDir), 'utf8');
    assert.match(source, /^# Copyright \(c\) 2026 ReleaseReady/, file);
    assert.match(
      source,
      new RegExp(`# Ruleset version: ${releaseReadyRulesVersion}`),
      file,
    );
    assert.doesNotMatch(
      source,
      /semgrep\.dev|\bp\/[a-z]|registry\.semgrep/i,
      file,
    );
    const doc = parse(source) as { rules?: Record<string, unknown>[] };
    assert.ok(Array.isArray(doc.rules) && doc.rules.length === 1, file);
    const rule = doc.rules[0] ?? {};
    const id = String(rule.id);
    assert.match(id, /^releaseready\.js\.[a-z0-9-]+$/, file);
    assert.ok(!ids.has(id), `duplicate ${id}`);
    ids.add(id);
    assert.ok(Array.isArray(rule.languages) && rule.languages.length > 0, file);
    assert.ok(
      ['ERROR', 'WARNING', 'INFO'].includes(String(rule.severity)),
      file,
    );
    assert.ok(
      typeof rule.message === 'string' && rule.message.length > 10,
      file,
    );
    assert.ok(
      ['pattern', 'patterns', 'pattern-either', 'pattern-regex'].some(
        (k) => k in rule,
      ),
      file,
    );
    const meta = (rule.metadata ?? {}) as Record<string, unknown>;
    assert.match(String(meta.cwe), /^CWE-\d+/, file);
    assert.ok(
      ['HIGH', 'MEDIUM', 'LOW'].includes(String(meta.confidence)),
      file,
    );
    assert.ok(
      ['vulnerability', 'hotspot'].includes(String(meta['finding-type'])),
      file,
    );
    assert.equal(meta['ruleset-version'], releaseReadyRulesVersion, file);
    for (const key of ['version', 'license', 'author', 'remediation'])
      assert.ok(meta[key], `${file} metadata.${key}`);
  }
});
