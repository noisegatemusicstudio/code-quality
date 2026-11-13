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

const localWorkflowRef = 'local:releaseready-dev';
const localWorkflowPattern = /^local:releaseready-dev$/;

const need = (
  label: string,
  value: string | undefined,
  pattern: RegExp,
): string => {
  if (value === undefined || hasControl(value) || !pattern.test(value))
    throw new ManifestError(`${label} is missing or malformed`);
  return value;
};

/** Raw, unvalidated identity values plus the names to blame in errors. */
interface IdentitySource {
  values: {
    event: string | undefined;
    sha?: string | undefined;
    ref: string | undefined;
    repository: string | undefined;
    runId: string | undefined;
    runAttempt: string | undefined;
    workflowRef: string | undefined;
  };
  /** `sha` is set only when the source carries a SHA to cross-check. */
  labels: Record<
    'event' | 'ref' | 'repository' | 'runId' | 'runAttempt' | 'workflowRef',
    string
  > & { sha?: string };
  workflowPattern: RegExp;
}

type Identity = Pick<
  QualityManifest,
  | 'repository'
  | 'ref'
  | 'event'
  | 'pullRequest'
  | 'runId'
  | 'runAttempt'
  | 'workflowRef'
>;

/** The single identity validator shared by the GitHub Actions and local paths. */
function validateIdentity(source: IdentitySource, commitSha: string): Identity {
  const { values, labels } = source;
  const eventName = values.event;
  if (eventName !== 'push' && eventName !== 'pull_request')
    throw new ManifestError(`${labels.event} must be push or pull_request`);
  if (
    labels.sha !== undefined &&
    need(labels.sha, values.sha, sha) !== commitSha
  )
    throw new ManifestError(`${labels.sha} does not match the scanned commit`);
  const ref = need(
    labels.ref,
    values.ref,
    eventName === 'push' ? refName : pullRef,
  );
  return {
    repository: need(labels.repository, values.repository, repository),
    ref,
    event: eventName,
    pullRequest:
      eventName === 'pull_request' ? Number(pullRef.exec(ref)?.[1]) : null,
    runId: Number(need(labels.runId, values.runId, counter)),
    runAttempt: Number(need(labels.runAttempt, values.runAttempt, counter)),
    workflowRef: need(
      labels.workflowRef,
      values.workflowRef,
      source.workflowPattern,
    ),
  };
}

const environmentSource = (
  environment: Record<string, string | undefined>,
): IdentitySource => ({
  values: {
    event: environment.GITHUB_EVENT_NAME,
    sha: environment.GITHUB_SHA,
    ref: environment.GITHUB_REF,
    repository: environment.GITHUB_REPOSITORY,
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    workflowRef: environment.GITHUB_WORKFLOW_REF,
  },
  labels: {
    event: 'GITHUB_EVENT_NAME',
    sha: 'GITHUB_SHA',
    ref: 'GITHUB_REF',
    repository: 'GITHUB_REPOSITORY',
    runId: 'GITHUB_RUN_ID',
    runAttempt: 'GITHUB_RUN_ATTEMPT',
    workflowRef: 'GITHUB_WORKFLOW_REF',
  },
  workflowPattern: workflowRef,
});

/** Explicit identity of a local (non-Actions) scan, from `run` flags. */
export interface LocalIdentityFlags {
  repository?: string | undefined;
  ref?: string | undefined;
  event?: string | undefined;
  runId?: string | undefined;
  /** Defaults to 1 when the flag is absent. */
  runAttempt?: string | undefined;
}

const localSource = (flags: LocalIdentityFlags): IdentitySource => ({
  values: {
    event: flags.event,
    ref: flags.ref,
    repository: flags.repository,
    runId: flags.runId,
    runAttempt: flags.runAttempt ?? '1',
    workflowRef: localWorkflowRef,
  },
  labels: {
    event: '--event',
    ref: '--ref',
    repository: '--repository',
    runId: '--run-id',
    runAttempt: '--run-attempt',
    workflowRef: 'workflowRef',
  },
  workflowPattern: localWorkflowPattern,
});

/**
 * Validate a local identity with the same rules as the environment path. Throws
 * ManifestError; the commit SHA is never an input (it comes from git).
 */
export const validateLocalIdentity = (flags: LocalIdentityFlags): Identity =>
  validateIdentity(localSource(flags), '');

/**
 * Whether the portal manifest applies to this GitHub Actions run. A manual
 * `workflow_dispatch` run carries no push or pull_request identity the portal
 * can trust, so it writes no manifest and the job reports the gate result only.
 * Every other event still goes through `buildManifest`, which stays strict and
 * keeps rejecting anything but push and pull_request.
 */
export const manifestApplies = (
  environment: Record<string, string | undefined>,
): boolean => environment.GITHUB_EVENT_NAME !== 'workflow_dispatch';

type ManifestInput = Parameters<typeof buildManifest>[1];

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
  checkRefs(input);
  return assemble(
    validateIdentity(environmentSource(environment), input.commitSha),
    input,
  );
}

/** Build the manifest for a local scan from explicit, validated flags. */
export function buildLocalManifest(
  flags: LocalIdentityFlags,
  input: ManifestInput,
): QualityManifest {
  checkRefs(input);
  return assemble(validateLocalIdentity(flags), input);
}

function checkRefs(input: ManifestInput): void {
  if (!sha.test(input.commitSha))
    throw new ManifestError('commit SHA is not a full 40-character SHA');
  if (!sha.test(input.codeQualityRef))
    throw new ManifestError('code-quality-ref is not a full 40-character SHA');
}

function assemble(identity: Identity, input: ManifestInput): QualityManifest {
  return {
    schemaVersion: 1,
    repository: identity.repository,
    commitSha: input.commitSha,
    ref: identity.ref,
    event: identity.event,
    pullRequest: identity.pullRequest,
    runId: identity.runId,
    runAttempt: identity.runAttempt,
    workflowRef: identity.workflowRef,
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
