/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Proves that an envelope's repository comes from the validated local repository override (with the fallback kept) and that every engine's manifest version equals its envelope's engine.version, using synthetic envelopes; runs no scanner and no CLI.
*/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AdapterEnvelope } from '../src/adapter-envelope.js';
import type { ExecutionSlot } from '../src/customer-scan.js';
import { engineIds } from '../src/quality-scan.js';
import {
  fromEnvelope,
  fromSlot,
  scopeFromEnvironment,
} from '../src/quality-scan-run.js';
import { externalPins } from '../src/scanner-pins.js';

const sha = 'a'.repeat(40);

await test('a valid repository override names the envelope scope, over GITHUB_REPOSITORY', () => {
  const scope = scopeFromEnvironment(
    { GITHUB_REPOSITORY: 'env-owner/env-repo' },
    sha,
    'acme/widgets',
  );
  assert.equal(scope.repository, 'acme/widgets');
  assert.equal(scope.projectId, 'widgets');
});

await test('without an override the environment repository is used, then the local fallback', () => {
  assert.equal(
    scopeFromEnvironment({ GITHUB_REPOSITORY: 'acme/widgets' }, sha).repository,
    'acme/widgets',
  );
  assert.equal(scopeFromEnvironment({}, sha).repository, 'local/repository');
});

await test('an override that fails the repository pattern is never used', () => {
  for (const bad of ['no-slash', 'a/b/c', 'a b/c', '', `${'x'.repeat(101)}/y`])
    assert.equal(
      scopeFromEnvironment({}, sha, bad).repository,
      'local/repository',
      bad,
    );
});

const slot: ExecutionSlot = {
  id: 'gitleaks',
  state: 'completed',
  evidence: 'executed',
  coverage: 'committed-text-default-rules',
  findings: [],
};

await test('every engine takes its manifest version from the envelope engine.version', () => {
  const scope = scopeFromEnvironment({}, sha, 'acme/widgets');
  for (const id of engineIds) {
    const envelope: AdapterEnvelope = {
      schemaVersion: 1,
      provenance: 'adapter-executed',
      ...scope,
      engine: { id, version: `9.9.9-${id}` },
      rulesetVersion: 'r1',
      configVersion: 'c1',
      status: 'completed',
      findings: [],
    };
    const result = fromEnvelope(id, envelope);
    assert.equal(result.version, envelope.engine.version, id);
    assert.equal(result.envelope, envelope, id);
  }
});

await test('slot-based engines also report the version their envelope carries', () => {
  const scope = scopeFromEnvironment({}, sha, 'acme/widgets');
  for (const id of ['gitleaks', 'jscpd'] as const) {
    const result = fromSlot(id, { ...slot, id }, undefined, scope);
    assert.ok(result.envelope, id);
    assert.equal(result.version, result.envelope.engine.version, id);
    assert.equal(result.version, externalPins[id].version, id);
  }
});
