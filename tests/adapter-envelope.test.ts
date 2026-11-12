/*
Test classification: contract
Review status: Not Reviewed
Evidence: synthetic
Scope: Validates the versioned adapter result envelope and runAdapter isolation, limits and cancellation against fake executables; does not run real scanner binaries.
*/
import assert from 'node:assert/strict';
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  type EnvelopeScope,
  envelopeLimits,
  findingFingerprint,
  hasControl,
  redactMessage,
  validateEnvelope,
} from '../src/adapter-envelope.js';
import { parseEslintFindings } from '../src/eslint-import.js';
import { type ScannerAdapter, runAdapter } from '../src/scanner-adapter.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'a'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const finding = () => {
  const base = {
    ruleId: 'no-undef',
    nativeSeverity: 'error',
    path: 'src/a.ts',
    range: { startLine: 1, startColumn: 2, endLine: 1, endColumn: 5 },
    message: 'x is not defined',
  };
  return { ...base, fingerprint: findingFingerprint('eslint', base) };
};
const envelope = (over: Record<string, unknown> = {}): unknown => ({
  schemaVersion: 1,
  provenance: 'imported-unverified',
  ...scope,
  engine: { id: 'eslint', version: '10.13.0' },
  rulesetVersion: 'rules-1',
  configVersion: 'config-1',
  status: 'completed',
  findings: [finding()],
  ...over,
});

await test('valid envelope round-trips and enforces expected scope', () => {
  const ok = validateEnvelope(JSON.stringify(envelope()), scope);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.ok && ok.envelope, envelope());
});

await test('cross-scope ids are denied field by field', () => {
  for (const [key, value] of [
    ['tenantId', 'tenant-b'],
    ['projectId', 'project-2'],
    ['repository', 'acme/other'],
    ['commitSha', 'b'.repeat(40)],
    ['sourceId', 'source-2'],
    ['jobId', 'job-2'],
    ['attemptId', 'attempt-2'],
  ] as const) {
    const result = validateEnvelope(envelope({ [key]: value }), scope);
    assert.deepEqual(result, { ok: false, error: `cross-scope:${key}` });
  }
});

await test('malformed commits, ids, versions and paths fail closed', () => {
  const bad: Record<string, unknown>[] = [
    { commitSha: 'A'.repeat(40) },
    { commitSha: 'a'.repeat(39) },
    { commitSha: 'a'.repeat(41) },
    { tenantId: '' },
    { tenantId: '../x' },
    { repository: 'a/b/c/d' },
    { schemaVersion: 2 },
    { provenance: 'trusted' },
    { status: 'done' },
    { rulesetVersion: 'v 1' },
    { extra: 1 },
    { engine: { id: 'eslint' } },
    { findings: {} },
  ];
  for (const over of bad)
    assert.equal(
      validateEnvelope(envelope(over)).ok,
      false,
      JSON.stringify(over),
    );
  for (const path of [
    '/etc/passwd',
    '../x',
    'a/../b',
    'a\\b',
    'C:x',
    'a//b',
    '',
  ])
    assert.equal(
      validateEnvelope(envelope({ findings: [{ ...finding(), path }] })).ok,
      false,
      path,
    );
});

await test('status, reason and findings must agree', () => {
  assert.equal(validateEnvelope(envelope({ status: 'failed' })).ok, false);
  assert.equal(
    validateEnvelope(envelope({ reason: 'timeout' })).ok,
    false,
    'reason on completed',
  );
  assert.equal(
    validateEnvelope(envelope({ status: 'failed', reason: 'engine-error' })).ok,
    false,
    'failed with findings',
  );
  assert.equal(
    validateEnvelope(
      envelope({ status: 'skipped', reason: 'cancelled', findings: [] }),
    ).ok,
    true,
  );
  assert.equal(
    validateEnvelope(envelope({ status: 'incomplete', reason: 'timeout' })).ok,
    true,
    'partial findings stay allowed when incomplete',
  );
  assert.equal(
    validateEnvelope(envelope({ status: 'incomplete', reason: 'bogus' })).ok,
    false,
  );
});

await test('size limits and prototype keys are enforced', () => {
  const big = JSON.stringify(
    envelope({ pad: 'x'.repeat(envelopeLimits.rawBytes) }),
  );
  assert.deepEqual(validateEnvelope(big), { ok: false, error: 'oversize' });
  const many = Array.from({ length: envelopeLimits.findings + 1 }, (_, i) => {
    const base = { ...finding(), message: `m${i}` };
    return { ...base, fingerprint: findingFingerprint('eslint', base) };
  });
  assert.equal(validateEnvelope(envelope({ findings: many })).ok, false);
  assert.equal(
    validateEnvelope(envelope({ findings: [finding(), finding()] })).ok,
    false,
    'duplicate fingerprints',
  );
  assert.equal(validateEnvelope('{"__proto__":{"x":1}}').ok, false);
  assert.equal(validateEnvelope('{').ok, false);
  const long = {
    ...finding(),
    message: 'y'.repeat(envelopeLimits.messageChars + 1),
  };
  assert.equal(validateEnvelope(envelope({ findings: [long] })).ok, false);
});

await test('messages are redacted, bounded and control-free', () => {
  const text = redactMessage(
    'token=abc123 Bearer abcdefghijkl ghp_abcdefghijklmnop AKIAABCDEFGHIJKLMNOP /home/u/secret/x.ts\u0000\n' +
      'q'.repeat(400),
  );
  for (const leaked of ['abc123', 'abcdefghijkl', 'ghp_', 'AKIA', '/home/u'])
    assert.equal(text.includes(leaked), false, leaked);
  assert.equal(text.length <= envelopeLimits.messageChars, true);
  assert.equal(hasControl(text), false);
});

// ---- ESLint detailed import -------------------------------------------------
const report = (filePath: string, messages: unknown[]) => [
  {
    filePath,
    messages,
    suppressedMessages: [],
    errorCount: messages.filter(
      (m) => (m as { severity: number }).severity === 2,
    ).length,
    warningCount: messages.filter(
      (m) => (m as { severity: number }).severity === 1,
    ).length,
    fatalErrorCount: 0,
    fixableErrorCount: 0,
    fixableWarningCount: 0,
  },
];
const context = {
  ...scope,
  engineVersion: '10.13.0',
  rulesetVersion: 'rules-1',
  configVersion: 'config-1',
  pathRoot: '/work/repo',
};
const msg = (over: object = {}) => ({
  ruleId: 'no-undef',
  severity: 2,
  message: 'x is not defined',
  line: 3,
  column: 4,
  ...over,
});

await test('ESLint import yields detailed, stable, validated findings', () => {
  const raw = JSON.stringify(
    report('/work/repo/src/a.ts', [
      msg({ endLine: 3, endColumn: 9 }),
      msg({ ruleId: null, severity: 1, message: 'token=hunter2hunter2' }),
      msg(),
      msg(),
    ]),
  );
  const first = parseEslintFindings(raw, context);
  assert.equal(first.status, 'parsed');
  if (first.status !== 'parsed') return;
  const e = first.envelope;
  assert.equal(e.status, 'completed');
  assert.equal(e.provenance, 'imported-unverified');
  assert.equal(e.findings.length, 4);
  assert.equal(new Set(e.findings.map((f) => f.fingerprint)).size, 4);
  assert.equal(JSON.stringify(e).includes('hunter2'), false);
  assert.equal(
    e.findings.some(
      (f) => f.ruleId === '(no-rule)' && f.nativeSeverity === 'warn',
    ),
    true,
  );
  assert.deepEqual(parseEslintFindings(raw, context), first, 'deterministic');
  assert.equal(validateEnvelope(JSON.stringify(e), scope).ok, true);
});

await test('ESLint import reports dropped findings as incomplete, never complete', () => {
  const outside = parseEslintFindings(
    JSON.stringify([
      ...report('/work/repo/src/a.ts', [msg()]),
      ...report('/elsewhere/b.ts', [msg()]),
    ]),
    context,
  );
  assert.equal(
    outside.status === 'parsed' && outside.envelope.status,
    'incomplete',
  );
  assert.equal(
    outside.status === 'parsed' && outside.envelope.reason,
    'path-outside-root',
  );
  assert.equal(
    outside.status === 'parsed' && outside.envelope.findings.length,
    1,
  );
  const badLocation = parseEslintFindings(
    JSON.stringify(report('/work/repo/a.ts', [msg({ line: 0 })])),
    context,
  );
  assert.equal(
    badLocation.status === 'parsed' && badLocation.envelope.reason,
    'invalid-output',
  );
  const over = parseEslintFindings(
    JSON.stringify(
      report(
        '/work/repo/a.ts',
        Array.from({ length: envelopeLimits.findings + 1 }, (_, i) => ({
          severity: 2,
          line: i + 1,
          column: 1,
        })),
      ),
    ),
    context,
  );
  assert.equal(
    over.status === 'parsed' && over.envelope.reason,
    'finding-limit',
  );
  assert.equal(
    over.status === 'parsed' && over.envelope.findings.length,
    envelopeLimits.findings,
  );
});

await test('ESLint import rejects oversize input, bad scope and relative roots', () => {
  assert.equal(
    parseEslintFindings('x'.repeat(262145), context).status,
    'invalid',
  );
  assert.equal(parseEslintFindings('[', context).status, 'invalid');
  const ok = JSON.stringify(report('/work/repo/a.ts', [msg()]));
  assert.equal(
    parseEslintFindings(ok, { ...context, commitSha: 'zz' }).status,
    'invalid',
  );
  assert.equal(
    parseEslintFindings(ok, { ...context, tenantId: '../t' }).status,
    'invalid',
  );
  assert.equal(
    parseEslintFindings(ok, { ...context, pathRoot: 'rel' }).status,
    'invalid',
  );
  // Inconsistent counts are still rejected by the count validator.
  const lie = report('/work/repo/a.ts', [msg()]);
  lie[0].errorCount = 0;
  assert.equal(
    parseEslintFindings(JSON.stringify(lie), context).status,
    'invalid',
  );
});

// ---- Adapter runner ---------------------------------------------------------
const fakeSource = `#!${process.execPath}
const [, , ...args] = process.argv;
if (args[0] === '--version') { console.log('fake-engine 1.0.0'); process.exit(0); }
const fs = require('node:fs');
const mode = (args.find((a) => a.startsWith('--mode=')) ?? '').slice(7);
if (mode === 'ok') {
  console.log(JSON.stringify([{ ruleId: 'r1', path: fs.readdirSync('.')[0], line: 1, column: 1, message: 'password=hunter2hunter2' }]));
} else if (mode === 'partial') {
  console.log(JSON.stringify({ partial: true, findings: [{ ruleId: 'r1', path: 'a.ts', line: 1, column: 1, message: 'm' }] }));
} else if (mode === 'hang') { setInterval(() => {}, 1000); fs.writeFileSync('started', '1'); }
else if (mode === 'garbage') console.log('{not json');
else if (mode === 'huge') setInterval(() => process.stdout.write('x'.repeat(65536)), 1);
else if (mode === 'crash') process.exit(7);
else if (mode === 'env') console.log(JSON.stringify([{ ruleId: 'r1', path: 'a.ts', line: 1, column: 1, message: Object.keys(process.env).sort().join(',') }]));
else if (mode === 'badpath') console.log(JSON.stringify([{ ruleId: 'r1', path: '../../etc/passwd', line: 1, column: 1, message: 'm' }]));
`;
const parseFake = (stdout: string) => {
  const value = JSON.parse(stdout) as unknown;
  const list = Array.isArray(value)
    ? value
    : (value as { findings: unknown[] }).findings;
  const partial = !Array.isArray(value);
  return {
    partial: partial ? ('engine-error' as const) : undefined,
    findings: (list as Record<string, unknown>[]).map((f) => {
      const base = {
        ruleId: String(f.ruleId),
        nativeSeverity: 'error',
        path: String(f.path),
        range: {
          startLine: Number(f.line),
          startColumn: Number(f.column),
          endLine: Number(f.line),
          endColumn: Number(f.column),
        },
        message: redactMessage(f.message),
      };
      return { ...base, fingerprint: findingFingerprint('fake', base) };
    }),
  };
};
const dir = await mkdtemp(join(tmpdir(), 'adapter-test-'));
const executable = join(dir, 'fake-engine');
await writeFile(executable, fakeSource);
await chmod(executable, 0o755);
// Adapter workspaces go to os.tmpdir(); a private TMPDIR keeps the cleanup
// checks below independent of other test files running concurrently.
const privateTmp = join(dir, 'tmp');
await mkdir(privateTmp);
process.env.TMPDIR = privateTmp;
const adapter: ScannerAdapter = {
  engine: { id: 'fake', version: '1.0.0' },
  rulesetVersion: 'rules-1',
  configVersion: 'config-1',
  executable,
  versionArgs: ['--version'],
  versionOutput: 'fake-engine 1.0.0',
  fixedArgs: [],
  allowedArgs: [
    '--mode=ok',
    '--mode=partial',
    '--mode=hang',
    '--mode=garbage',
    '--mode=huge',
    '--mode=crash',
    '--mode=env',
    '--mode=badpath',
  ],
  successExitCodes: [0],
  parse: parseFake,
};
const files = { 'a.ts': 'const x = 1;\n' };
const run = (mode: string, extra: object = {}) =>
  runAdapter(adapter, { scope, files, args: [`--mode=${mode}`], ...extra });
const tempEntries = async () =>
  (await readdir(privateTmp)).filter((n) => n.startsWith('adapter-'));
const linux = process.platform === 'linux';

await test(
  'adapter runs pinned engine and returns a validated envelope',
  { skip: !linux },
  async () => {
    const before = await tempEntries();
    const result = await run('ok');
    assert.equal(result.status, 'completed');
    assert.equal(result.provenance, 'adapter-executed');
    assert.equal(result.findings.length, 1);
    assert.equal(JSON.stringify(result).includes('hunter2'), false);
    assert.deepEqual(await tempEntries(), before, 'workspace removed');
    assert.equal(validateEnvelope(JSON.stringify(result), scope).ok, true);
  },
);

await test(
  'adapter environment carries no credentials, proxies or PATH',
  { skip: !linux },
  async () => {
    process.env.AWS_SECRET_ACCESS_KEY = 'leak';
    process.env.HTTPS_PROXY = 'http://proxy';
    try {
      const result = await run('env');
      const names = result.findings[0]?.message ?? '';
      for (const forbidden of ['AWS', 'PROXY', 'PATH', 'NPM', 'TOKEN'])
        assert.equal(names.includes(forbidden), false, forbidden);
    } finally {
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.HTTPS_PROXY;
    }
  },
);

await test(
  'argument allowlist, files and timeouts are enforced before execution',
  { skip: !linux },
  async () => {
    for (const args of [
      ['--install'],
      ['install'],
      ['--mode=ok', '-c', 'x'],
      ['--mode=ok\0'],
    ]) {
      const r = await runAdapter(adapter, { scope, files, args });
      assert.deepEqual(
        [r.status, r.reason, r.findings.length],
        ['skipped', 'invalid-request', 0],
      );
    }
    const hostile: Record<string, string>[] = [
      { '../x': 'y' },
      { '/abs': 'y' },
      { 'a/../../b': 'y' },
    ];
    for (const bad of hostile) {
      const r = await runAdapter(adapter, {
        scope,
        files: bad,
        args: ['--mode=ok'],
      });
      assert.equal(r.reason, 'invalid-request');
    }
    assert.equal((await run('ok', { timeoutMs: 0 })).reason, 'invalid-request');
    assert.equal(
      (await run('ok', { timeoutMs: 999999 })).reason,
      'invalid-request',
    );
    await assert.rejects(
      runAdapter(adapter, { scope: { ...scope, commitSha: 'x' }, files }),
      TypeError,
    );
    await assert.rejects(
      runAdapter({ ...adapter, executable: '/usr/bin/npm' }, { scope, files }),
      TypeError,
    );
    await assert.rejects(
      runAdapter({ ...adapter, executable: 'relative' }, { scope, files }),
      TypeError,
    );
  },
);

await test(
  'wrong engine version is refused before scanning',
  { skip: !linux },
  async () => {
    const r = await runAdapter(
      { ...adapter, versionOutput: 'fake-engine 9.9.9' },
      { scope, files, args: ['--mode=ok'] },
    );
    assert.deepEqual(
      [r.status, r.reason, r.findings.length],
      ['failed', 'engine-version-mismatch', 0],
    );
  },
);

await test(
  'hostile outputs yield honest failed or incomplete results',
  { skip: !linux },
  async () => {
    const cases: [string, string, string | undefined, number][] = [
      ['garbage', 'failed', 'invalid-output', 0],
      ['crash', 'failed', 'engine-error', 0],
      ['badpath', 'failed', 'invalid-output', 0],
      ['huge', 'incomplete', 'output-limit', 0],
      ['partial', 'incomplete', 'engine-error', 1],
    ];
    for (const [mode, status, reason, count] of cases) {
      const r = await run(mode);
      assert.deepEqual(
        [r.status, r.reason, r.findings.length],
        [status, reason, count],
        mode,
      );
    }
    const t = await run('hang', { timeoutMs: 300 });
    assert.deepEqual(
      [t.status, t.reason, t.findings.length],
      ['incomplete', 'timeout', 0],
    );
  },
);

await test(
  'cancellation stops the engine and discards output',
  { skip: !linux },
  async () => {
    const pre = new AbortController();
    pre.abort();
    const early = await run('ok', { signal: pre.signal });
    assert.deepEqual([early.status, early.reason], ['skipped', 'cancelled']);
    const live = new AbortController();
    const pending = run('hang', { signal: live.signal, timeoutMs: 60000 });
    setTimeout(() => live.abort(), 400);
    const started = Date.now();
    const r = await pending;
    assert.deepEqual(
      [r.status, r.reason, r.findings.length],
      ['incomplete', 'cancelled', 0],
    );
    assert.equal(Date.now() - started < 10000, true);
    assert.deepEqual(await tempEntries(), [], 'workspace removed');
  },
);

await test('cleanup of test fixtures', async () => {
  await rm(dir, { recursive: true, force: true });
});
