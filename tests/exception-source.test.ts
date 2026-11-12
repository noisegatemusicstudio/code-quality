/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves, with in-memory file readers and a synthetic pull_request event, that exceptions come from the PR base commit only (a PR-added exception does not suppress a finding), that pending ones are listed in the summary, and that push events read the pushed commit; runs no scanner, git or workflow.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findingFingerprint } from '../src/adapter-envelope.js';
import type { AdapterEnvelope } from '../src/adapter-envelope.js';
import {
  decide,
  renderSummary,
  type EngineResult,
} from '../src/quality-scan.js';
import {
  ExceptionSourceError,
  applyGitleaksExceptions,
  loadExceptions,
} from '../src/quality-scan-run.js';

const base = 'b'.repeat(40);
const scope = {
  tenantId: 't',
  projectId: 'p',
  repository: 'acme/widgets',
  commitSha: 'a'.repeat(40),
  sourceId: 's',
  jobId: 'j',
  attemptId: '1',
};
const raw = {
  ruleId: 'aws-access-token',
  nativeSeverity: 'secret',
  path: 'tests/a.ts',
  range: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 20 },
  message: 'Potential secret detected by rule aws-access-token',
};
const finding = { ...raw, fingerprint: findingFingerprint('gitleaks', raw) };
const envelope: AdapterEnvelope = {
  schemaVersion: 1,
  provenance: 'adapter-executed',
  ...scope,
  engine: { id: 'gitleaks', version: '8.30.1' },
  rulesetVersion: 'r',
  configVersion: 'c',
  status: 'completed',
  findings: [finding],
};
const gitleaks: EngineResult = {
  engine: 'gitleaks',
  status: 'completed',
  findings: [finding],
  envelope,
};
const exception = (over: Record<string, string> = {}) => ({
  fingerprint: finding.fingerprint,
  ruleId: 'aws-access-token',
  path: 'tests/a.ts',
  reviewedBy: 'owner',
  reviewedAt: '2026-11-12',
  expiresAt: '2027-02-10',
  reason: 'synthetic fixture',
  ...over,
});
const file = (...list: object[]) => JSON.stringify({ gitleaks: list });
const now = new Date('2026-11-13T00:00:00Z');
const prEnvironment = {
  GITHUB_EVENT_NAME: 'pull_request',
  GITHUB_EVENT_PATH: '/event.json',
};
const event = JSON.stringify({ pull_request: { base: { sha: base } } });
const load = (
  environment: Record<string, string>,
  head: string | undefined,
  atBase: string | undefined,
  readEvent: string = event,
) =>
  loadExceptions({
    environment,
    readHead: () => Promise.resolve(head),
    readBase: (sha) => {
      assert.equal(sha, base);
      return Promise.resolve(atBase);
    },
    readEvent: () => Promise.resolve(readEvent),
  });

await test('an exception added by the pull request does not suppress its finding', async () => {
  const loaded = await load(prEnvironment, file(exception()), file());
  assert.equal(loaded.source, 'base-commit');
  assert.deepEqual(loaded.exceptions, []);
  assert.equal(loaded.pending.length, 1);
  const result = applyGitleaksExceptions(gitleaks, loaded.exceptions, now);
  assert.equal(result.findings.length, 1);
  assert.equal(result.excepted, undefined);
  // The finding still counts, so enforce mode fails the check.
  assert.equal(
    decide([result], { enforce: true, failOnSeverity: 'high' }).exitCode,
    1,
  );
});

await test('a PR that creates the exceptions file, or edits an entry, gains nothing', async () => {
  const created = await load(prEnvironment, file(exception()), undefined);
  assert.deepEqual(created.exceptions, []);
  const edited = await load(
    prEnvironment,
    file(exception({ expiresAt: '2027-02-09' })),
    file(exception({ expiresAt: '2026-11-01' })),
  );
  assert.equal(edited.exceptions.length, 1);
  assert.equal(edited.exceptions[0]?.expiresAt, '2026-11-01');
  assert.equal(edited.pending.length, 1);
  // The base entry is expired, so the finding is still reported.
  const result = applyGitleaksExceptions(gitleaks, edited.exceptions, now);
  assert.equal(result.findings.length, 1);
});

await test('exceptions already merged to the base still apply and are not pending', async () => {
  const loaded = await load(
    prEnvironment,
    file(exception()),
    file(exception()),
  );
  assert.equal(loaded.pending.length, 0);
  const result = applyGitleaksExceptions(gitleaks, loaded.exceptions, now);
  assert.equal(result.findings.length, 0);
  assert.equal(result.excepted, 1);
});

await test('push events read the pushed commit', async () => {
  const loaded = await loadExceptions({
    environment: { GITHUB_EVENT_NAME: 'push' },
    readHead: () => Promise.resolve(file(exception())),
    readBase: () => Promise.reject(new Error('push must not read a base')),
    readEvent: () => Promise.reject(new Error('push must not read events')),
  });
  assert.equal(loaded.source, 'scanned-commit');
  assert.equal(loaded.exceptions.length, 1);
  assert.equal(loaded.pending.length, 0);
});

await test('a pull request with an unknown base fails closed', async () => {
  for (const bad of ['{}', 'not json', '{"pull_request":{"base":{"sha":"x"}}}'])
    await assert.rejects(
      load(prEnvironment, file(exception()), file(), bad),
      ExceptionSourceError,
    );
  await assert.rejects(
    loadExceptions({
      environment: prEnvironment,
      readHead: () => Promise.resolve(file()),
      readBase: () => Promise.resolve('{ malformed'),
      readEvent: () => Promise.resolve(event),
    }),
    ExceptionSourceError,
  );
});

await test('a malformed head file is reported but does not widen what is in force', async () => {
  const loaded = await load(prEnvironment, '{ broken', file(exception()));
  assert.equal(loaded.exceptions.length, 1);
  assert.match(loaded.pendingError ?? '', /malformed/);
});

await test('the summary lists pending exceptions and says they apply after merge', async () => {
  const loaded = await load(prEnvironment, file(exception()), file());
  const results = [applyGitleaksExceptions(gitleaks, loaded.exceptions, now)];
  const summary = renderSummary({
    commitSha: 'a'.repeat(40),
    results,
    decision: decide(results, { enforce: false, failOnSeverity: 'high' }),
    baseline: null,
    exceptions: loaded,
  });
  assert.match(summary, /### Exceptions pending review/);
  assert.match(summary, /aws-access-token/);
  assert.match(summary, /take effect after merge/);
  const push = renderSummary({
    commitSha: 'a'.repeat(40),
    results,
    decision: decide(results, { enforce: false, failOnSeverity: 'high' }),
    baseline: null,
    exceptions: { source: 'scanned-commit', pending: [] },
  });
  assert.doesNotMatch(push, /pending review/);
});
