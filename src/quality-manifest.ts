import { hasControl } from './adapter-envelope.js';
import type { EngineResult } from './quality-scan.js';

/** One engine entry of `manifest.json`. */
export interface ManifestEngine {
  id: string;
  version: string | null;
  status: EngineResult['status'];
  reason: string | null;
  findingCount: number;
  /** Findings dropped from `findingCount` by a reviewed, unexpired exception. */
  exceptedCount: number;
  /** Artifact-relative path of the engine envelope, or null if none was written. */
  envelope: string | null;
}

/** `manifest.json` at the root of the `code-quality-results` artifact. */
export interface QualityManifest {
  schemaVersion: 1;
  repository: string;
  commitSha: string;
  ref: string;
  event: 'push' | 'pull_request';
  pullRequest: number | null;
  runId: number;
  runAttempt: number;
  workflowRef: string;
  codeQualityRef: string;
  engines: ManifestEngine[];
  /** New-code measures; null when the CLI computed none. */
  measures: ManifestMeasure[] | null;
}
export interface ManifestMeasure {
  id: string;
  state: 'known' | 'unknown';
  percent: number | null;
  numerator: number | null;
  denominator: number | null;
  /** Fixed reason token when unknown. */
  reason: string | null;
}

export class ManifestError extends Error {}

const sha = /^[0-9a-f]{40}$/;
const repository = /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/;
const refName = /^refs\/(?:heads|tags)\/\S{1,250}$/;
const pullRef = /^refs\/pull\/([1-9]\d{0,8})\/merge$/;
const workflowRef =
  /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}\/\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml@refs\/(?:heads|tags|pull)\/\S{1,250}$/;
const counter = /^[1-9]\d{0,14}$/;
const reasonLimit = 500;

const need = (
  environment: Record<string, string | undefined>,
  name: string,
  pattern: RegExp,
): string => {
  const value = environment[name];
  if (value === undefined || hasControl(value) || !pattern.test(value))
    throw new ManifestError(`${name} is missing or malformed`);
  return value;
};

/**
 * Build the portal manifest from the GitHub Actions environment. Every field
 * is validated against a strict pattern and nothing is guessed or defaulted:
 * a missing or malformed value throws, so the portal never ingests a manifest
 * whose identity it cannot trust.
 */
export function buildManifest(
  environment: Record<string, string | undefined>,
  input: {
    commitSha: string;
    codeQualityRef: string;
    results: readonly EngineResult[];
    /** Artifact-relative envelope paths that were actually written. */
    envelopeFiles: ReadonlyMap<string, string>;
    measures?: readonly {
      id: string;
      state: string;
      percent?: number;
      numerator?: number;
      denominator?: number;
      reason?: string;
    }[];
  },
): QualityManifest {
  if (!sha.test(input.commitSha))
    throw new ManifestError('commit SHA is not a full 40-character SHA');
  if (!sha.test(input.codeQualityRef))
    throw new ManifestError('code-quality-ref is not a full 40-character SHA');
  const eventName = environment.GITHUB_EVENT_NAME;
  if (eventName !== 'push' && eventName !== 'pull_request')
    throw new ManifestError('GITHUB_EVENT_NAME must be push or pull_request');
  if (need(environment, 'GITHUB_SHA', sha) !== input.commitSha)
    throw new ManifestError('GITHUB_SHA does not match the scanned commit');
  const ref = need(
    environment,
    'GITHUB_REF',
    eventName === 'push' ? refName : pullRef,
  );
  const pullRequest =
    eventName === 'pull_request' ? Number(pullRef.exec(ref)?.[1]) : null;
  return {
    schemaVersion: 1,
    repository: need(environment, 'GITHUB_REPOSITORY', repository),
    commitSha: input.commitSha,
    ref,
    event: eventName,
    pullRequest,
    runId: Number(need(environment, 'GITHUB_RUN_ID', counter)),
    runAttempt: Number(need(environment, 'GITHUB_RUN_ATTEMPT', counter)),
    workflowRef: need(environment, 'GITHUB_WORKFLOW_REF', workflowRef),
    codeQualityRef: input.codeQualityRef,
    engines: input.results.map((r) => ({
      id: r.engine,
      version: r.version ?? null,
      status: r.status,
      reason: r.reason ? stripControl(r.reason).slice(0, reasonLimit) : null,
      findingCount: r.findings.length,
      exceptedCount: r.excepted ?? 0,
      envelope: input.envelopeFiles.get(r.engine) ?? null,
    })),
    measures: input.measures
      ? input.measures.map((m) => ({
          id: m.id,
          state: m.state === 'known' ? 'known' : 'unknown',
          percent: m.percent ?? null,
          numerator: m.numerator ?? null,
          denominator: m.denominator ?? null,
          reason: m.reason ?? null,
        }))
      : null,
  };
}

const stripControl = (value: string): string =>
  Array.from(value)
    .map((c) => {
      const code = c.codePointAt(0) ?? 0;
      return code < 32 || code === 127 ? ' ' : c;
    })
    .join('');
