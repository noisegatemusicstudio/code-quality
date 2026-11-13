/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Builds the portal manifest from synthetic GITHUB_* environments and proves strict validation, the osv-mode input parser and gitleaks exception handling (exact match, expiry, 90-day cap); runs no scanner and touches no network.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ManifestError,
  buildManifest,
  manifestApplies,
} from '../src/quality-manifest.js';
import { findingFingerprint } from '../src/adapter-envelope.js';
import type { AdapterEnvelope } from '../src/adapter-envelope.js';
import { parseOsvMode, type EngineResult } from '../src/quality-scan.js';
import {
  applyGitleaksExceptions,
  mergeEnvelopes,
  parseExceptions,
} from '../src/quality-scan-run.js';

const sha = 'a'.repeat(40);
const pushEnvironment = {
  GITHUB_REPOSITORY: 'acme/widgets',
  GITHUB_SHA: sha,
  GITHUB_REF: 'refs/heads/feature/x',
  GITHUB_EVENT_NAME: 'push',
  GITHUB_RUN_ID: '123456789',
  GITHUB_RUN_ATTEMPT: '2',
  GITHUB_WORKFLOW_REF:
    'acme/widgets/.github/workflows/quality.yml@refs/heads/feature/x',
};
const results: EngineResult[] = [
  { engine: 'eslint', status: 'completed', version: 'bundled', findings: [] },
  {
    engine: 'osv',
    status: 'skipped',
    skipKind: 'unavailable',
    reason: 'bad\u0000reason',
    findings: [],
  },
];
const input = {
  commitSha: sha,
  codeQualityRef: 'b'.repeat(40),
  results,
  envelopeFiles: new Map([['eslint', 'envelopes/eslint.json']]),
};

await test('manifest: push event carries identity, null pull request and per-engine entries', () => {
  const m = buildManifest(pushEnvironment, input);
  assert.equal(m.schemaVersion, 1);
  assert.equal(m.repository, 'acme/widgets');
  assert.equal(m.event, 'push');
  assert.equal(m.pullRequest, null);
  assert.equal(m.runId, 123456789);
  assert.equal(m.runAttempt, 2);
  assert.equal(m.codeQualityRef, 'b'.repeat(40));
  assert.deepEqual(m.engines[0], {
    id: 'eslint',
    version: 'bundled',
    status: 'completed',
    reason: null,
    findingCount: 0,
    exceptedCount: 0,
    envelope: 'envelopes/eslint.json',
  });
  assert.equal(m.engines[1]?.envelope, null);
  assert.equal(m.engines[1]?.reason, 'bad reason');
});

await test('manifest: pull_request event derives the PR number from the merge ref', () => {
  const m = buildManifest(
    {
      ...pushEnvironment,
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_REF: 'refs/pull/42/merge',
    },
    input,
  );
  assert.equal(m.event, 'pull_request');
  assert.equal(m.pullRequest, 42);
});

await test('manifest: every malformed or missing value is rejected, never defaulted', () => {
  const bad: Record<string, string | undefined>[] = [
    { GITHUB_REPOSITORY: 'no-slash' },
    { GITHUB_REPOSITORY: undefined },
    { GITHUB_SHA: 'b'.repeat(40) },
    { GITHUB_SHA: 'abc' },
    { GITHUB_EVENT_NAME: 'workflow_dispatch' },
    { GITHUB_REF: 'refs/pull/1/merge' },
    { GITHUB_REF: 'refs/heads/x y' },
    { GITHUB_RUN_ID: '0' },
    { GITHUB_RUN_ID: '12a' },
    { GITHUB_RUN_ATTEMPT: '' },
    { GITHUB_WORKFLOW_REF: 'acme/widgets@refs/heads/main' },
    { GITHUB_EVENT_NAME: 'pull_request', GITHUB_REF: 'refs/heads/main' },
    { GITHUB_EVENT_NAME: 'pull_request', GITHUB_REF: 'refs/pull/0/merge' },
  ];
  for (const override of bad)
    assert.throws(
      () => buildManifest({ ...pushEnvironment, ...override }, input),
      ManifestError,
      JSON.stringify(override),
    );
  assert.throws(
    () => buildManifest(pushEnvironment, { ...input, codeQualityRef: 'main' }),
    ManifestError,
  );
  assert.throws(
    () => buildManifest(pushEnvironment, { ...input, commitSha: 'HEAD' }),
    ManifestError,
  );
});

await test('osv-mode input: default online, three valid values, everything else rejected', () => {
  assert.equal(parseOsvMode(undefined), 'online');
  assert.equal(parseOsvMode(''), 'online');
  assert.equal(parseOsvMode('online'), 'online');
  assert.equal(parseOsvMode(' Offline '), 'offline');
  assert.equal(parseOsvMode('off'), 'off');
  for (const value of ['on', 'true', 'online,off', 'none'])
    assert.equal(parseOsvMode(value), undefined, value);
});

const scope = {
  tenantId: 't',
  projectId: 'p',
  repository: 'acme/widgets',
  commitSha: sha,
  sourceId: 's',
  jobId: 'j',
  attemptId: '1',
};
const finding = (path: string) => {
  const base = {
    ruleId: 'aws-access-token',
    nativeSeverity: 'secret',
    path,
    range: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 20 },
    message: 'Potential secret detected by rule aws-access-token',
  };
  return { ...base, fingerprint: findingFingerprint('gitleaks', base) };
};
const gitleaksResult = (...paths: string[]): EngineResult => {
  const findings = paths.map(finding);
  const envelope: AdapterEnvelope = {
    schemaVersion: 1,
    provenance: 'adapter-executed',
    ...scope,
    engine: { id: 'gitleaks', version: '8.30.1' },
    rulesetVersion: 'r',
    configVersion: 'c',
    status: 'completed',
    findings,
  };
  return { engine: 'gitleaks', status: 'completed', findings, envelope };
};
const exceptionFor = (path: string, over: Record<string, string> = {}) => ({
  fingerprint: finding(path).fingerprint,
  ruleId: 'aws-access-token',
  path,
  reviewedBy: 'owner',
  reviewedAt: '2026-11-12',
  expiresAt: '2027-02-10',
  reason: 'synthetic fixture',
  ...over,
});
const now = new Date('2026-11-13T00:00:00Z');

await test('gitleaks exceptions remove only the exact reviewed finding and keep the envelope whole', () => {
  const result = applyGitleaksExceptions(
    gitleaksResult('tests/a.ts', 'src/real.ts'),
    [exceptionFor('tests/a.ts')],
    now,
  );
  assert.deepEqual(
    result.findings.map((f) => f.path),
    ['src/real.ts'],
  );
  assert.equal(result.excepted, 1);
  assert.equal(result.envelope?.findings.length, 2);
});

await test('gitleaks exceptions that are expired, over 90 days, wrong-path or malformed never apply', () => {
  const unexcepted = [
    exceptionFor('tests/a.ts', { expiresAt: '2026-11-12' }),
    exceptionFor('tests/a.ts', { expiresAt: '2027-02-11' }),
    exceptionFor('tests/other.ts'),
    exceptionFor('tests/a.ts', { reason: ' ' }),
    exceptionFor('tests/a.ts', { fingerprint: 'sha256:short' }),
  ];
  for (const e of unexcepted) {
    const result = applyGitleaksExceptions(
      gitleaksResult('tests/a.ts'),
      [e],
      now,
    );
    assert.equal(result.findings.length, 1, JSON.stringify(e));
    assert.equal(result.excepted, undefined);
  }
});

await test('exceptions file parsing fails closed on anything but a gitleaks array', () => {
  assert.equal(parseExceptions('{"gitleaks":[]}').length, 0);
  assert.throws(() => parseExceptions('{}'));
  assert.throws(() => parseExceptions('[]'));
  assert.throws(() => parseExceptions('not json'));
});

await test('OSV envelope merge: worst status wins and findings concatenate', () => {
  const ok = gitleaksResult('a.ts').envelope;
  assert.ok(ok);
  const skippedEnvelope: AdapterEnvelope = {
    ...ok,
    status: 'skipped',
    reason: 'invalid-request',
    findings: [],
  };
  assert.equal(mergeEnvelopes([ok]).status, 'completed');
  const merged = mergeEnvelopes([ok, skippedEnvelope]);
  assert.equal(merged.status, 'incomplete');
  assert.equal(merged.findings.length, 1);
  assert.equal(mergeEnvelopes([ok, ok]).reason, undefined);
});

await test('manifestApplies exempts only a manual workflow_dispatch run; buildManifest still refuses it', () => {
  assert.equal(
    manifestApplies({
      ...pushEnvironment,
      GITHUB_EVENT_NAME: 'workflow_dispatch',
    }),
    false,
  );
  for (const event of ['push', 'pull_request', 'schedule', undefined])
    assert.equal(
      manifestApplies({ ...pushEnvironment, GITHUB_EVENT_NAME: event }),
      true,
      String(event),
    );
  assert.throws(
    () =>
      buildManifest(
        { ...pushEnvironment, GITHUB_EVENT_NAME: 'workflow_dispatch' },
        input,
      ),
    ManifestError,
  );
});
