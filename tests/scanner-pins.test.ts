/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves the shared pins, executable SHA-256 refusal, version-pin refusal and jscpd file-output wiring by running fake executables through runAdapter; does not run any real pinned engine or download one.
*/
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { access } from 'node:fs/promises';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { EnvelopeScope } from '../src/adapter-envelope.js';
import { jscpdAdapter, jscpdPin } from '../src/duplication.js';
import { parseExternalReport } from '../src/external-scanners.js';
import {
  createGitleaksAdapter,
  gitleaksVersion,
} from '../src/gitleaks-adapter.js';
import { osvAdapterEngine, runOsvScan } from '../src/osv-adapter.js';
import { parseOsvReport } from '../src/osv-scanner.js';
import { runAdapter } from '../src/scanner-adapter.js';
import { externalPins, osvPin } from '../src/scanner-pins.js';

const scope: EnvelopeScope = {
  tenantId: 'tenant-a',
  projectId: 'project-1',
  repository: 'acme/app',
  commitSha: 'b'.repeat(40),
  sourceId: 'source-1',
  jobId: 'job-1',
  attemptId: 'attempt-1',
};
const linux = { skip: process.platform !== 'linux' };
const dir = await mkdtemp(join(tmpdir(), 'scanner-pins-test-'));
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const fake = async (name: string, body: string) => {
  const path = join(dir, name);
  const source = `#!${process.execPath}\n${body}`;
  await writeFile(path, source);
  await chmod(path, 0o755);
  return { path, sha256: sha(source) };
};
const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

await test('adapters read their versions from the shared pins', () => {
  assert.equal(gitleaksVersion, externalPins.gitleaks.version);
  assert.equal(jscpdPin.version, externalPins.jscpd.version);
  assert.equal(osvAdapterEngine.version, osvPin.version);
  const g = createGitleaksAdapter({
    executable: '/opt/gitleaks',
    configPath: '/opt/c.toml',
    ignorePath: '/opt/ignore',
    mode: 'working-tree',
  }).adapter;
  assert.equal(g.executableSha256, externalPins.gitleaks.sha256);
  assert.equal(
    jscpdAdapter('/opt/jscpd').executableSha256,
    externalPins.jscpd.sha256,
  );
});

await test(
  'an executable that does not match the pinned sha256 is refused unrun',
  linux,
  async () => {
    const marker = join(dir, 'ran-marker');
    const exe = await fake(
      'wrong-sha',
      `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x');console.log('8.30.1')`,
    );
    const adapter = jscpdAdapter(exe.path); // default = pinned sha256
    const envelope = await runAdapter(adapter, {
      scope,
      files: { 'a.ts': 'x' },
    });
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
    assert.equal(envelope.findings.length, 0);
    assert.equal(await exists(marker), false, 'the executable must not run');
  },
);

await test(
  'a missing executable is refused when a sha256 is pinned',
  linux,
  async () => {
    const envelope = await runAdapter(jscpdAdapter(join(dir, 'absent')), {
      scope,
      files: {},
    });
    assert.equal(envelope.status, 'failed');
    assert.equal(envelope.reason, 'engine-version-mismatch');
  },
);

await test('a malformed sha256 declaration never executes', async () => {
  const adapter = { ...jscpdAdapter('/opt/jscpd'), executableSha256: 'ABC' };
  await assert.rejects(runAdapter(adapter, { scope, files: {} }), TypeError);
});

await test(
  'gitleaks and osv: a matching sha256 runs, a wrong declared version is refused',
  linux,
  async () => {
    const g = await fake(
      'gl',
      `if (process.argv[2] === 'version') {console.log('${gitleaksVersion}');process.exit(0)}console.log('[]')`,
    );
    const adapter = createGitleaksAdapter({
      executable: g.path,
      executableSha256: g.sha256,
      configPath: '/opt/c.toml',
      ignorePath: '/opt/ignore',
      mode: 'working-tree',
    }).adapter;
    assert.equal(
      (await runAdapter(adapter, { scope, files: {} })).status,
      'completed',
    );
    // Same binary, but it reports a different version than the pin: refused.
    const old = await fake(
      'gl-old',
      `if (process.argv[2] === 'version') {console.log('8.0.0');process.exit(0)}console.log('[]')`,
    );
    const refused = await runAdapter(
      { ...adapter, executable: old.path, executableSha256: old.sha256 },
      { scope, files: {} },
    );
    assert.equal(refused.reason, 'engine-version-mismatch');

    const osv = await fake(
      'osv',
      `console.log('osv-scanner ${osvPin.version}')`,
    );
    const base = { executable: osv.path, executableSha256: osv.sha256 };
    const request = {
      scope,
      artefactPath: 'package-lock.json',
      artefactContent: '{}',
    };
    const bad = await runOsvScan(
      { ...base, versionOutput: 'osv-scanner 2.0.0' },
      request,
    );
    assert.equal(bad.envelope.status, 'skipped');
    assert.equal(bad.disclosure.outcome, 'invalid-request');
    const wrongSha = await runOsvScan(
      {
        ...base,
        executableSha256: 'f'.repeat(64),
        versionOutput: `osv-scanner ${osvPin.version}`,
      },
      request,
    );
    assert.equal(wrongSha.envelope.status, 'failed');
    assert.equal(wrongSha.envelope.reason, 'engine-version-mismatch');
  },
);

const report = (root: string) =>
  JSON.stringify({
    statistics: {
      formats: {
        typescript: { lines: 60, sources: 2, clones: 1 },
      },
      total: { lines: 60, sources: 2, clones: 1 },
    },
    duplicates: [
      {
        format: 'typescript',
        lines: 10,
        tokens: 80,
        firstFile: {
          name: `${root}a.ts`,
          startLoc: { line: 1 },
          endLoc: { line: 10 },
        },
        secondFile: {
          name: `${root}b.ts`,
          startLoc: { line: 11 },
          endLoc: { line: 20 },
        },
      },
    ],
  });
// The report carries no per-file lines; the snapshot files supply them.
const thirty = 'x\n'.repeat(30);
// Fake jscpd: prints the pinned version, writes the report FILE into --output
// (relative to its cwd, as the real reporter does) and nothing on stdout.
const jscpdFake = (write: string) =>
  fake(
    `jscpd-${sha(write).slice(0, 8)}`,
    `const fs = require('node:fs');const a = process.argv.slice(2);
if (a[0] === '--version') {console.log('${jscpdPin.version}');process.exit(0)}
const out = a[a.indexOf('--output') + 1];
${write}
process.exit(42);`,
  );

await test(
  'jscpd report is read from its output file, not stdout',
  linux,
  async () => {
    const exe = await jscpdFake(
      `fs.writeFileSync(out + '/jscpd-report.json', ${JSON.stringify(report(''))});`,
    );
    const envelope = await runAdapter(jscpdAdapter(exe.path, exe.sha256), {
      scope,
      files: { 'a.ts': thirty, 'b.ts': thirty },
    });
    assert.equal(envelope.status, 'completed');
    assert.equal(envelope.findings.length, 2);
    assert.equal(envelope.findings[0]?.path, 'a.ts');
  },
);

await test(
  'jscpd output-file guards: absent, stdout-only and oversized fail closed',
  linux,
  async () => {
    const run = async (write: string) => {
      const exe = await jscpdFake(write);
      return runAdapter(jscpdAdapter(exe.path, exe.sha256), {
        scope,
        files: { 'a.ts': 'x' },
      });
    };
    for (const write of [
      '', // no file written
      `console.log(${JSON.stringify(report(''))});`, // report only on stdout
      `fs.writeFileSync(out + '/jscpd-report.json', 'x'.repeat(8388609));`, // over the bound
      `fs.symlinkSync('/etc/passwd', out + '/jscpd-report.json');`, // symlink refused
    ]) {
      const envelope = await run(write);
      assert.equal(envelope.status, 'failed');
      assert.equal(envelope.reason, 'invalid-output');
      assert.equal(envelope.findings.length, 0);
    }
  },
);

await test('declared output files must stay inside the workspace', async () => {
  for (const path of ['/etc/x', '../x', 'report.json', 'source/x/y.json']) {
    const adapter = {
      ...jscpdAdapter('/opt/jscpd'),
      outputFile: { path, maxBytes: 10 },
    };
    await assert.rejects(
      runAdapter(adapter, { scope, files: {} }),
      TypeError,
      path,
    );
  }
});

await test('customer-scan parsers reuse the adapter parsers and relativize paths', () => {
  const root = '/snap/src';
  const gl = Buffer.from(
    JSON.stringify([
      {
        RuleID: 'aws-access-token',
        StartLine: 2,
        EndLine: 2,
        File: `${root}/a/b.ts`,
        Secret: 'REDACTED',
      },
    ]),
  );
  const g = parseExternalReport('gitleaks', gl, root);
  assert.equal(g?.findingCount, 1);
  assert.equal(g.findings[0]?.path, 'a/b.ts');
  // Entries the shared parser would skip make the whole count report invalid.
  assert.equal(parseExternalReport('gitleaks', gl, '/other'), null);
  const snap = mkdtempSync(join(tmpdir(), 'jscpd-pins-'));
  writeFileSync(join(snap, 'a.ts'), thirty);
  writeFileSync(join(snap, 'b.ts'), thirty);
  const j = parseExternalReport('jscpd', Buffer.from(report('')), snap);
  rmSync(snap, { recursive: true, force: true });
  assert.equal(j?.findingCount, 1);
  assert.equal(j.coveredFileCount, 2);
  assert.equal(j.findings[0]?.path, 'a.ts');
  const osvRaw = Buffer.from(
    JSON.stringify({
      results: [
        {
          source: { type: 'lockfile', path: `${root}/package-lock.json` },
          packages: [
            {
              package: { name: 'left-pad', version: '1.0.0', ecosystem: 'npm' },
              vulnerabilities: [
                { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2020-0001'] },
              ],
            },
          ],
        },
      ],
    }),
  );
  const o = parseOsvReport(osvRaw, [`${root}/package-lock.json`], root);
  assert.equal(o?.findingCount, 1);
  assert.equal(o.findings[0]?.path, 'package-lock.json');
  assert.equal(o.findings[0]?.ruleId, 'GHSA-aaaa-bbbb-cccc');
});

process.on('exit', () => {
  void rm(dir, { recursive: true, force: true });
});
