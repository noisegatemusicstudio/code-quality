/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves the pinned-asset install refusal, bounded file reading, slot-to-result mapping and the reusable workflow's static policy (read-only permissions, SHA-pinned actions, no secrets) using temp directories, fake downloads and the workflow text; runs no scanner engine and downloads nothing.
*/
import assert from 'node:assert/strict';
import {
  access,
  mkdtemp,
  mkdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { ExecutionSlot } from '../src/customer-scan.js';
import type { EngineResult } from '../src/quality-scan.js';
import {
  applyOmitted,
  fromSlot,
  installEngine,
  readBoundedFiles,
  scopeFromEnvironment,
  withParseFailures,
} from '../src/quality-scan-run.js';
import { isIacCandidate } from '../src/trivy-adapter.js';
import {
  externalPins,
  osvPin,
  releaseAssets,
  detektPin,
  ktlintPin,
  swiftlintPin,
  ruffPin,
  semgrepPin,
  trivyPin,
} from '../src/scanner-pins.js';
import { semgrepVersion } from '../src/semgrep-adapter.js';
import { trivyAdapterEngine } from '../src/trivy-adapter.js';

const scope = scopeFromEnvironment({}, 'a'.repeat(40));

await test('install refuses an asset whose sha256 differs from the pin and writes nothing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qs-install-'));
  try {
    for (const id of [
      'gitleaks',
      'trivy',
      'osv',
      'jscpd',
      'ruff',
      'pmd',
      'checkstyle',
      'detekt',
      'ktlint',
      'swiftlint',
    ] as const) {
      await assert.rejects(
        installEngine(id, join(dir, id), () =>
          Promise.resolve(new TextEncoder().encode('tampered')),
        ),
        /asset sha256 mismatch/,
      );
      await assert.rejects(access(join(dir, id, id)));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('release assets agree with the engine pins and upstream versions', () => {
  assert.equal(
    releaseAssets.gitleaks.binarySha256,
    externalPins.gitleaks.sha256,
  );
  assert.equal(releaseAssets.jscpd.binarySha256, externalPins.jscpd.sha256);
  assert.equal(releaseAssets.osv.binarySha256, osvPin.sha256);
  assert.equal(releaseAssets.trivy.binarySha256, trivyPin.sha256);
  assert.equal(releaseAssets.ruff.binarySha256, ruffPin.sha256);
  assert.ok(releaseAssets.ruff.url.includes(`/${ruffPin.version}/`));
  assert.equal(releaseAssets.detekt.binarySha256, detektPin.sha256);
  assert.ok(releaseAssets.detekt.url.includes(`v${detektPin.version}/`));
  assert.equal(releaseAssets.ktlint.binarySha256, ktlintPin.sha256);
  assert.ok(releaseAssets.ktlint.url.includes(`/${ktlintPin.version}/`));
  assert.equal(releaseAssets.swiftlint.binarySha256, swiftlintPin.sha256);
  assert.ok(releaseAssets.swiftlint.url.includes(`/${swiftlintPin.version}/`));
  assert.equal(trivyPin.version, trivyAdapterEngine.version);
  assert.equal(semgrepPin.version, semgrepVersion);
  for (const [id, asset] of Object.entries(releaseAssets)) {
    assert.match(asset.assetSha256, /^[a-f0-9]{64}$/, id);
    assert.ok(asset.url.startsWith('https://'), id);
  }
  assert.ok(releaseAssets.gitleaks.url.includes(externalPins.gitleaks.version));
  assert.ok(releaseAssets.trivy.url.includes(trivyPin.version));
  assert.ok(releaseAssets.osv.url.includes(osvPin.version));
  assert.ok(releaseAssets.jscpd.url.includes(externalPins.jscpd.version));
});

await test('semgrep requirements are hash-locked to the pinned version and wheel', async () => {
  const text = await readFile(
    new URL('../../scanners/semgrep-requirements.txt', import.meta.url),
    'utf8',
  );
  assert.match(
    text,
    new RegExp(
      `^semgrep==${semgrepPin.version.replaceAll('.', '\\.')} \\\\`,
      'm',
    ),
  );
  assert.ok(text.includes(`--hash=sha256:${semgrepPin.wheelSha256}`));
  const blocks = text.split(/\n(?=[A-Za-z0-9_.-]+==)/);
  assert.ok(blocks.length > 10);
  for (const block of blocks)
    assert.ok(block.includes('--hash=sha256:'), block.slice(0, 40));
});

await test('bounded reading omits symlinks, non-UTF-8 files and files past the limit instead of hiding them', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'qs-files-'));
  try {
    await mkdir(join(dir, 'src'));
    await writeFile(join(dir, 'src/a.ts'), 'export const a = 1;\n');
    await writeFile(join(dir, 'src/bin.ts'), Buffer.from([0xff, 0xfe, 0x00]));
    await writeFile(join(dir, 'src/big.ts'), 'x'.repeat(1048577));
    await symlink('/etc/passwd', join(dir, 'src/link.ts'));
    const read = await readBoundedFiles(
      dir,
      [
        'src/a.ts',
        'src/bin.ts',
        'src/big.ts',
        'src/link.ts',
        'README.md',
        'src/missing.ts',
      ],
      (p) => p.endsWith('.ts'),
    );
    assert.deepEqual(Object.keys(read.files), ['src/a.ts']);
    assert.equal(read.omitted, 4);
    assert.deepEqual(read.causes, {
      'not-utf8': 1,
      'file-too-large': 1,
      'not-regular-file': 1,
      unreadable: 1,
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('omitted files turn a completed engine into incomplete, never clean', () => {
  const done: EngineResult = {
    engine: 'semgrep',
    status: 'completed',
    findings: [],
  };
  assert.equal(applyOmitted({ ...done }, 0).status, 'completed');
  const partial = applyOmitted({ ...done }, 3);
  assert.equal(partial.status, 'incomplete');
  assert.match(partial.reason ?? '', /3 file/);
  // A failure stays a failure.
  assert.equal(
    applyOmitted(
      { engine: 'semgrep', status: 'failed', findings: [], reason: 'x' },
      3,
    ).status,
    'failed',
  );
});

await test('snapshot slots map to engine results: limited is incomplete, source errors fail', () => {
  const slot = (
    state: ExecutionSlot['state'],
    extra: Partial<ExecutionSlot> = {},
  ): ExecutionSlot => ({
    id: 'gitleaks',
    state,
    evidence: state === 'completed' ? 'executed' : 'none',
    coverage: 'committed-text-default-rules',
    ...extra,
  });
  const ok = fromSlot(
    'gitleaks',
    slot('completed', { findings: [] }),
    undefined,
    scope,
  );
  assert.equal(ok.status, 'completed');
  assert.equal(ok.envelope?.status, 'completed');
  const limited = fromSlot(
    'gitleaks',
    slot('limited', { reason: 'source-suppression-file' }),
    undefined,
    scope,
  );
  assert.equal(limited.status, 'incomplete');
  assert.equal(limited.reason, 'source-suppression-file');
  assert.equal(
    fromSlot('jscpd', slot('timed-out'), undefined, scope).status,
    'failed',
  );
  assert.equal(
    fromSlot('jscpd', slot('missing'), undefined, scope).status,
    'failed',
  );
  const noSource = fromSlot(
    'gitleaks',
    slot('completed', { findings: [] }),
    'source-unavailable',
    scope,
  );
  assert.equal(noSource.status, 'failed');
  assert.match(noSource.reason ?? '', /source-unavailable/);
});

await test('envelope scope comes from the Actions environment and falls back safely', () => {
  const s = scopeFromEnvironment(
    {
      GITHUB_REPOSITORY: 'acme/app',
      GITHUB_RUN_ID: '123',
      GITHUB_RUN_ATTEMPT: '2',
    },
    'd'.repeat(40),
  );
  assert.equal(s.repository, 'acme/app');
  assert.equal(s.jobId, '123');
  assert.equal(s.attemptId, '2');
  assert.equal(
    scopeFromEnvironment({ GITHUB_REPOSITORY: 'bad repo!' }, 'e'.repeat(40))
      .repository,
    'local/repository',
  );
  assert.throws(() => scopeFromEnvironment({}, 'not-a-sha'));
});

const workflowDirectory = new URL('../../.github/workflows/', import.meta.url);
await test('reusable workflow: workflow_call, read-only permissions, no secrets, SHA-pinned actions', async () => {
  const text = await readFile(
    new URL('quality-scan.yml', workflowDirectory),
    'utf8',
  );
  assert.match(text, /^on:\n {2}workflow_call:/m);
  assert.match(text, /^permissions:\n {2}contents: read\n/m);
  assert.equal(text.includes('secrets.'), false);
  assert.equal(/^\s+secrets:/m.test(text), false);
  assert.equal(/\bwrite\b/.test(text.replace(/--write/g, '')), false);
  for (const input of [
    'enforce',
    'node-version',
    'scanners',
    'code-quality-ref',
    'osv-mode',
  ])
    assert.match(text, new RegExp(`^ {6}${input}:`, 'm'));
  assert.match(text, /enforce:[\s\S]*?default: false/);
  assert.match(text, /node-version:[\s\S]*?default: 22\.23\.4/);
  assert.match(text, /osv-mode:[\s\S]*?default: online/);
  assert.match(
    text,
    /name: code-quality-results\n\s+path: .*\n\s+retention-days: 90/,
  );
  assert.equal(/name: quality-scan\b/.test(text), false);
  const uses = [...text.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 3);
  for (const u of uses) assert.match(u, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, u);
  // Inputs reach shell steps only through env, never interpolated into scripts.
  assert.equal(/run:[^\n]*\$\{\{\s*inputs\./.test(text), false);
});

await test('dogfood workflow calls the reusable one in advisory mode on every push and pull_request', async () => {
  const text = await readFile(
    new URL('quality.yml', workflowDirectory),
    'utf8',
  );
  assert.match(text, /^on:\n {2}push:\n {2}pull_request:\n/m);
  assert.equal(text.includes('branches:'), false);
  assert.match(text, /uses: \.\/\.github\/workflows\/quality-scan\.yml/);
  assert.match(text, /enforce: false/);
  assert.match(text, /code-quality-ref: \$\{\{ github\.sha \}\}/);
  assert.match(text, /^permissions:\n {2}contents: read\n/m);
});

await test('trivy candidate selection keeps IaC and drops lockfiles, manifests and vendored data', () => {
  for (const keep of [
    'main.tf',
    'infra/vars.tfvars',
    'k8s/deploy.yaml',
    'cfn/template.json',
    'Dockerfile',
    'docker/Dockerfile.prod',
    'compose.yml',
  ])
    assert.equal(isIacCandidate(keep), true, keep);
  for (const drop of [
    'package.json',
    'web/package-lock.json',
    'pnpm-lock.yaml',
    'tsconfig.build.json',
    'apps/a/jsconfig.json',
    '.eslintrc.json',
    'dist/bundle.json',
    'node_modules/x/k8s.yaml',
    'trivy.yaml',
    'README.md',
    'src/App.tsx',
  ])
    assert.equal(isIacCandidate(drop), false, drop);
});

await test('omission causes are named in the incomplete reason without paths', () => {
  const done: EngineResult = {
    engine: 'trivy',
    status: 'completed',
    findings: [],
  };
  const partial = applyOmitted(done, 3, {
    'file-count-limit': 2,
    'not-utf8': 1,
  });
  assert.equal(partial.status, 'incomplete');
  assert.match(partial.reason ?? '', /file-count-limit: 2, not-utf8: 1/);
});

await test('eslint parse failures are listed by name and cap the list', () => {
  const base: EngineResult = {
    engine: 'eslint',
    status: 'incomplete',
    reason: 'parse-failure',
    findings: [],
  };
  const named = withParseFailures(base, {
    parseFailures: ['a.vue.js', 'b.ts'],
    truncated: false,
  });
  assert.match(
    named.reason ?? '',
    /parse-failure: 2 file\(s\).*a\.vue\.js, b\.ts/,
  );
  const names = Array.from({ length: 30 }, (_, i) => `f${String(i)}.js`);
  const capped = withParseFailures(base, {
    parseFailures: names,
    truncated: true,
  });
  assert.match(capped.reason ?? '', /f19\.js, and more/);
  assert.ok(!(capped.reason ?? '').includes('f20.js'));
  assert.equal(
    withParseFailures(base, { parseFailures: [], truncated: false }),
    base,
  );
});
