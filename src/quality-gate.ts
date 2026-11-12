import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  isSeverity,
  newFindings,
  normaliseSeverity,
  severityLevels,
  type Baseline,
  type Decision,
  type EngineResult,
  type Severity,
} from './quality-scan.js';

/** Missing measures never pass silently: `fail` blocks, `report` is shown but does not block. */
export type OnUnknown = 'fail' | 'report';
export interface QualityGate {
  schemaVersion: 1;
  name: string;
  version: string;
  basis: string;
  newIssues: { failOnSeverity: Severity };
  secrets: { maxFindings: number };
  requiredEnginesMustComplete: boolean;
  newCodeCoverage: { minPercent: number; onUnknown: OnUnknown };
  newCodeDuplication: { maxPercent: number; onUnknown: OnUnknown };
}

/** Measured new-code percentages; `null` means the workflow did not measure it. */
export interface GateMeasures {
  newCodeCoveragePercent: number | null;
  newCodeDuplicationPercent: number | null;
}
export const noMeasures: GateMeasures = {
  newCodeCoveragePercent: null,
  newCodeDuplicationPercent: null,
};

const fail = (message: string): never => {
  throw new Error(`invalid quality gate: ${message}`);
};
const record = (value: unknown, name: string): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fail(`${name} must be an object`);
const exactKeys = (
  value: Record<string, unknown>,
  keys: readonly string[],
  name: string,
): void => {
  for (const key of Object.keys(value))
    if (!keys.includes(key)) fail(`unknown key ${name}.${key}`);
  for (const key of keys)
    if (!(key in value)) fail(`missing key ${name}.${key}`);
};
const percent = (value: unknown, name: string): number =>
  typeof value === 'number' && value >= 0 && value <= 100
    ? value
    : fail(`${name} must be a number from 0 to 100`);
const onUnknown = (value: unknown, name: string): OnUnknown =>
  value === 'fail' || value === 'report'
    ? value
    : fail(`${name} must be "fail" or "report"`);
const text = (value: unknown, name: string): string =>
  typeof value === 'string' && value !== ''
    ? value
    : fail(`${name} must be a non-empty string`);

/** Strict parser: unknown or missing keys and out-of-range values are rejected, never defaulted. */
export function parseGate(source: string): QualityGate {
  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch {
    return fail('not valid JSON');
  }
  const top = record(raw, 'gate');
  exactKeys(
    top,
    [
      'schemaVersion',
      'name',
      'version',
      'basis',
      'newIssues',
      'secrets',
      'requiredEnginesMustComplete',
      'newCodeCoverage',
      'newCodeDuplication',
    ],
    'gate',
  );
  if (top.schemaVersion !== 1) fail('schemaVersion must be 1');
  const issues = record(top.newIssues, 'newIssues');
  exactKeys(issues, ['failOnSeverity'], 'newIssues');
  const severity = issues.failOnSeverity;
  if (typeof severity !== 'string' || !isSeverity(severity))
    fail(
      `newIssues.failOnSeverity must be one of ${severityLevels.join(', ')}`,
    );
  const secrets = record(top.secrets, 'secrets');
  exactKeys(secrets, ['maxFindings'], 'secrets');
  if (
    !Number.isInteger(secrets.maxFindings) ||
    (secrets.maxFindings as number) < 0
  )
    fail('secrets.maxFindings must be a non-negative integer');
  if (typeof top.requiredEnginesMustComplete !== 'boolean')
    fail('requiredEnginesMustComplete must be a boolean');
  const coverage = record(top.newCodeCoverage, 'newCodeCoverage');
  exactKeys(coverage, ['minPercent', 'onUnknown'], 'newCodeCoverage');
  const duplication = record(top.newCodeDuplication, 'newCodeDuplication');
  exactKeys(duplication, ['maxPercent', 'onUnknown'], 'newCodeDuplication');
  return {
    schemaVersion: 1,
    name: text(top.name, 'name'),
    version: text(top.version, 'version'),
    basis: text(top.basis, 'basis'),
    newIssues: { failOnSeverity: severity as Severity },
    secrets: { maxFindings: secrets.maxFindings as number },
    requiredEnginesMustComplete: top.requiredEnginesMustComplete as boolean,
    newCodeCoverage: {
      minPercent: percent(coverage.minPercent, 'newCodeCoverage.minPercent'),
      onUnknown: onUnknown(coverage.onUnknown, 'newCodeCoverage.onUnknown'),
    },
    newCodeDuplication: {
      maxPercent: percent(
        duplication.maxPercent,
        'newCodeDuplication.maxPercent',
      ),
      onUnknown: onUnknown(
        duplication.onUnknown,
        'newCodeDuplication.onUnknown',
      ),
    },
  };
}

/** The gate shipped next to the compiled tooling (`dist/src` -> repository root). */
export const defaultGatePath = join(
  import.meta.dirname,
  '..',
  '..',
  'gates',
  'default.json',
);
export async function loadGate(path = defaultGatePath): Promise<QualityGate> {
  return parseGate(await readFile(path, 'utf8'));
}

const rank = (severity: Severity): number => severityLevels.indexOf(severity);

export interface GateDecision extends Decision {
  gate: { name: string; version: string };
}

/**
 * Evaluate the gate. With a comparable baseline only findings absent from it
 * count as new; without one every finding counts (fail closed). Engines that
 * are failed or incomplete block, and skipped engines are not clean results
 * but are not required engines either.
 */
export function decideWithGate(
  results: readonly EngineResult[],
  options: {
    enforce: boolean;
    gate: QualityGate;
    baseline?: Baseline | null;
    measures?: GateMeasures;
  },
): GateDecision {
  const { gate } = options;
  const measures = options.measures ?? noMeasures;
  const reasons: string[] = [];
  const broken = results
    .filter((r) => r.status === 'failed' || r.status === 'incomplete')
    .map((r) => r.engine);
  if (gate.requiredEnginesMustComplete && broken.length)
    reasons.push(`failed or incomplete: ${broken.join(', ')}`);
  let blocking = 0;
  let secrets = 0;
  for (const result of results) {
    if (result.status !== 'completed' && result.status !== 'incomplete')
      continue;
    const fresh =
      newFindings(result, options.baseline ?? null) ?? result.findings;
    if (result.engine === 'gitleaks') secrets += fresh.length;
    for (const finding of fresh)
      if (
        rank(normaliseSeverity(result.engine, finding.nativeSeverity)) >=
        rank(gate.newIssues.failOnSeverity)
      )
        blocking += 1;
  }
  if (blocking)
    reasons.push(
      `${blocking} new finding(s) at or above ${gate.newIssues.failOnSeverity}`,
    );
  if (secrets > gate.secrets.maxFindings)
    reasons.push(
      `${secrets} secret finding(s), allowed ${gate.secrets.maxFindings}`,
    );
  const measure = (
    label: string,
    value: number | null,
    ok: (n: number) => boolean,
    rule: string,
    unknown: OnUnknown,
  ): void => {
    if (value === null) {
      if (unknown === 'fail') reasons.push(`${label} not measured`);
    } else if (!ok(value)) reasons.push(`${label} ${value}%, required ${rule}`);
  };
  measure(
    'new-code coverage',
    measures.newCodeCoveragePercent,
    (n) => n >= gate.newCodeCoverage.minPercent,
    `>= ${gate.newCodeCoverage.minPercent}%`,
    gate.newCodeCoverage.onUnknown,
  );
  measure(
    'new-code duplication',
    measures.newCodeDuplicationPercent,
    (n) => n <= gate.newCodeDuplication.maxPercent,
    `<= ${gate.newCodeDuplication.maxPercent}%`,
    gate.newCodeDuplication.onUnknown,
  );
  const wouldFail = reasons.length > 0;
  return {
    mode: options.enforce ? 'enforce' : 'advisory',
    threshold: gate.newIssues.failOnSeverity,
    broken,
    blocking,
    wouldFail,
    exitCode: options.enforce && wouldFail ? 1 : 0,
    reasons,
    gate: { name: gate.name, version: gate.version },
  };
}
