import { fileURLToPath } from 'node:url';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { immutableMetadata } from './scan-metadata.js';
import { validateDeclarationBundle } from './declaration-bundle.js';
import {
  externalPins,
  runExternalScanner,
  type ExternalResult,
} from './external-scanners.js';
import {
  parseCoverageSummary,
  type CoverageImport,
} from './coverage-import.js';
import {
  runOfflineOsv,
  osvPin,
  type OsvDatabaseInput,
  type OsvExecutionResult,
} from './osv-scanner.js';
import { OSV_SCHEMA_METADATA } from './osv-database.js';
import {
  createCommittedSnapshot,
  omittedTotal,
  type SkippedBinary,
  snapshotBounds,
  type SnapshotOmissions,
  SnapshotError,
  type Snapshot,
} from './committed-snapshot.js';
import { runScannerProcess } from './scanner-process.js';
import type { AdapterFinding } from './adapter-envelope.js';
import {
  aggregateScanReport,
  scannerIds,
  type ScannerId,
} from './scan-report.js';

export interface ExecutionSlot {
  id: ScannerId;
  state: 'completed' | 'failed' | 'timed-out' | 'missing' | 'limited';
  evidence: 'executed' | 'none' | 'imported-unverified';
  coverage:
    | 'bundled-syntax-rules'
    | 'fixed-semantic-profile'
    | 'not-run'
    | 'committed-text-default-rules'
    | 'native-supported-formats'
    | 'declared-only'
    | 'npm-package-lock-only';
  coveredFileCount?: number;
  unresolvedDependencyCount?: number;
  sourceSuppressionCount?: number;
  findingCount?: number;
  /** Detailed findings (gitleaks, jscpd, osv) when `detailedFindings` is set. */
  findings?: AdapterFinding[];
  toolVersion?: string;
  config?: string;
  /** Fixed token naming which bound or cause produced `reason` (never content). */
  detail?: string;
  reason?:
    | ExternalResult['reason']
    | OsvExecutionResult['reason']
    | 'invalid-declaration-bundle'
    | 'unverified-input'
    | 'snapshot-entries-omitted'
    | 'invalid-import';
  binarySha256?: string;
  database?: OsvExecutionResult['database'];
  packageCount?: number;
  unsupportedManifestCount?: number;
}
export interface ExecutionReport {
  schemaVersion: 2;
  commitSha: string | null;
  provenance: 'committed-tree-snapshot' | 'unavailable';
  source: {
    manifestSha256: string;
    fileCount: number;
    byteCount: number;
    /** Tree entries never materialised (symlinks, submodules, oversized, non-ASCII). */
    omitted: SnapshotOmissions;
    /** Binary blobs (by content) skipped and not text-scanned; counted, never hidden. */
    skippedBinary: SkippedBinary;
    /** Size of the largest `oversized-blob` omission (0 when none); diagnostic only. */
    largestOversizedBytes: number;
    checkoutIncluded: false;
    dependencyInputs: 'none' | 'declaration-bundle';
    declarationBundle?: {
      sha256: string;
      fileCount: number;
      byteCount: number;
    };
  } | null;
  status: 'incomplete';
  sourceError?: 'source-unavailable' | 'cleanup-failed' | 'cleanup-uncertain';
  /** Fixed token naming the guard that made the snapshot unavailable. */
  sourceDetail?: string;
  cleanup: 'not-needed' | 'completed' | 'uncertain-retained' | 'failed';
  projectTypeCheck: 'not-performed' | 'fixed-profile-only';
  runtime: { nodeVersion: string; gitVersion?: string };
  manifest: typeof executionManifest;
  scanners: ExecutionSlot[];
  importedCoverage?: CoverageImport;
}
export const executionManifest = immutableMetadata({
  schemaVersion: 1,
  trustBoundary:
    'Trusted installed runtime and Git; not a hostile-code sandbox',
  platform:
    'Linux supervisor/resource limits; native binaries pinned for Linux x64; no platform fallback',
  databaseRights:
    'Engine and schema licenses do not grant advisory database or commercial service rights; caller must provide permitted data',
  source:
    'Committed tree only; checkout modifications and untracked files excluded',
  snapshotBounds: {
    ...snapshotBounds,
    historyRead:
      'Entire bounded object store copied and fsck validates ancestry; unsupported shallow/alternate/worktree object stores rejected',
  },
  eslint: {
    version: '10.13.0',
    license: 'MIT',
    rules: '@eslint/js@10.0.1 + typescript-eslint@8.72.1 recommended (MIT)',
  },
  typescript: {
    version: '5.9.3',
    license: 'Apache-2.0',
    coverage:
      'Fixed strict ES2022/Bundler semantic profile with pinned standard libs; optional explicit declaration-only bundle; no project config, plugins, scripts or filesystem fallback',
  },
  externalScanners: externalPins,
  osv: osvPin,
  osvSchema: OSV_SCHEMA_METADATA,
  imports:
    'Tests and coverage remain declared and unverified; never execution proof or a verified quality gate',
  suppressionPolicy:
    'Source bytes are preserved. Conservative lexical TS @ts-nocheck/@ts-ignore/@ts-expect-error detection and jscpd ignore markers cause limited coverage; marker-like strings may also be limited.',
});

/** Additive execution API. Intentionally incomplete until all required engines,
 * project type checking and source-bound tests/coverage have real evidence.
 */
export async function scanCommittedSource(options: {
  gitExecutable: string;
  gitDirectory: string;
  commitSha: string;
  tools?: { gitleaks?: string; jscpd?: string; osv?: string };
  /** Also attach detailed envelope findings to each external slot. */
  detailedFindings?: boolean;
  osvDatabase?: OsvDatabaseInput;
  declarationBundle?: unknown;
  imports?: unknown;
  coverageSummary?: unknown;
}): Promise<ExecutionReport> {
  const scanners: ExecutionSlot[] = scannerIds.map((id) => ({
    id,
    state: 'missing',
    evidence: 'none',
    coverage: 'not-run',
  }));
  const report: ExecutionReport = {
    schemaVersion: 2,
    commitSha:
      typeof options.commitSha === 'string' &&
      options.commitSha.length === 40 &&
      /^[a-f0-9]{40}$/.test(options.commitSha)
        ? options.commitSha
        : null,
    provenance: 'unavailable',
    source: null,
    status: 'incomplete',
    cleanup: 'not-needed',
    projectTypeCheck: 'not-performed',
    runtime: { nodeVersion: process.version },
    manifest: executionManifest,
    scanners,
  };
  let snapshot: Snapshot;
  try {
    snapshot = await createCommittedSnapshot(options);
  } catch (error) {
    report.sourceError =
      error instanceof SnapshotError ? error.code : 'source-unavailable';
    if (error instanceof SnapshotError && error.detail)
      report.sourceDetail = error.detail;
    if (report.sourceError === 'cleanup-uncertain')
      report.cleanup = 'uncertain-retained';
    else if (report.sourceError === 'cleanup-failed') report.cleanup = 'failed';
    return report;
  }
  report.provenance = 'committed-tree-snapshot';
  report.source = {
    manifestSha256: snapshot.manifestSha256,
    fileCount: snapshot.fileCount,
    byteCount: snapshot.byteCount,
    omitted: snapshot.omitted,
    skippedBinary: snapshot.skippedBinary,
    largestOversizedBytes: snapshot.largestOversizedBytes,
    checkoutIncluded: false,
    dependencyInputs: 'none',
  };
  report.runtime.gitVersion = snapshot.gitVersion;
  let bundleDirectory = '';
  let bundlePath = '';
  let invalidBundle = false;
  try {
    if (options.declarationBundle !== undefined) {
      const bundle = validateDeclarationBundle(options.declarationBundle);
      if (bundle === null) invalidBundle = true;
      else {
        bundleDirectory = await mkdtemp(
          join(tmpdir(), 'code-quality-declarations-'),
        );
        bundlePath = join(bundleDirectory, 'bundle.json');
        await writeFile(bundlePath, JSON.stringify({ files: bundle.files }), {
          flag: 'wx',
          mode: 0o600,
        });
        report.source.dependencyInputs = 'declaration-bundle';
        report.source.declarationBundle = {
          sha256: bundle.sha256,
          fileCount: bundle.fileCount,
          byteCount: bundle.byteCount,
        };
      }
    }
    for (const id of ['eslint', 'typescript'] as const) {
      const slot = slotFor(scanners, id);
      if (id === 'typescript' && invalidBundle) {
        slot.state = 'failed';
        slot.reason = 'invalid-declaration-bundle';
        continue;
      }
      const result = await runScannerProcess({
        executable: process.execPath,
        args: [
          '--max-old-space-size=256',
          fileURLToPath(new URL('./scanner-worker.js', import.meta.url)),
          id,
          snapshot.directory,
          ...(id === 'typescript' && bundlePath ? [bundlePath] : []),
        ],
        cwd: snapshot.directory,
        timeoutMs: 30000,
        outputLimit: 262144,
      });
      slot.state = result.state === 'timed-out' ? 'timed-out' : 'failed';
      if (result.state === 'cleanup-uncertain') {
        slot.reason = 'cleanup-uncertain';
        report.cleanup = 'uncertain-retained';
        break;
      }
      if (result.state !== 'exited' || result.code !== 0) continue;
      try {
        const parsed: unknown = JSON.parse(result.stdout.toString('utf8'));
        if (
          typeof parsed !== 'object' ||
          parsed === null ||
          !('protocol' in parsed) ||
          parsed.protocol !== 1 ||
          !('id' in parsed) ||
          parsed.id !== id ||
          !('findings' in parsed) ||
          typeof parsed.findings !== 'number' ||
          !Number.isSafeInteger(parsed.findings) ||
          parsed.findings < 0 ||
          !('fileCount' in parsed) ||
          typeof parsed.fileCount !== 'number' ||
          !Number.isSafeInteger(parsed.fileCount) ||
          parsed.fileCount < 0 ||
          parsed.fileCount > snapshot.fileCount ||
          !('unresolved' in parsed) ||
          typeof parsed.unresolved !== 'number' ||
          !Number.isSafeInteger(parsed.unresolved) ||
          parsed.unresolved < 0 ||
          !('suppressionCount' in parsed) ||
          typeof parsed.suppressionCount !== 'number' ||
          !Number.isSafeInteger(parsed.suppressionCount) ||
          parsed.suppressionCount < 0
        )
          continue;
        Object.assign(slot, {
          state:
            parsed.unresolved > 0 ||
            parsed.fileCount === 0 ||
            parsed.suppressionCount > 0
              ? 'limited'
              : 'completed',
          evidence: 'executed',
          coverage:
            id === 'eslint' ? 'bundled-syntax-rules' : 'fixed-semantic-profile',
          coveredFileCount: parsed.fileCount,
          unresolvedDependencyCount: parsed.unresolved,
          sourceSuppressionCount: parsed.suppressionCount,
          reason:
            parsed.suppressionCount > 0
              ? 'source-suppression-directive'
              : undefined,
          findingCount: parsed.findings,
          toolVersion: executionManifest[id].version,
          config: 'bundled-v1-no-project-config',
        });
        if (id === 'typescript') report.projectTypeCheck = 'fixed-profile-only';
      } catch {
        /* No raw subprocess data is published. */
      }
    }
    if (report.cleanup !== 'uncertain-retained') {
      for (const id of ['gitleaks', 'jscpd'] as const) {
        const result = await runExternalScanner(
          id,
          snapshot.directory,
          options.tools?.[id],
          options.detailedFindings === true,
        );
        Object.assign(slotFor(scanners, id), result, {
          coverage:
            result.evidence === 'executed'
              ? id === 'gitleaks'
                ? 'committed-text-default-rules'
                : 'native-supported-formats'
              : 'not-run',
        });
        if (result.reason === 'cleanup-uncertain') {
          report.cleanup = 'uncertain-retained';
          break;
        }
      }
    }
    if (report.cleanup !== 'uncertain-retained') {
      const result = await runOfflineOsv(
        snapshot.directory,
        options.tools?.osv,
        options.osvDatabase,
        options.detailedFindings === true,
      );
      Object.assign(slotFor(scanners, 'osv'), result);
      if (result.reason === 'cleanup-uncertain')
        report.cleanup = 'uncertain-retained';
    }
    // Entries that were never materialised were not scanned: no scanner may
    // present a complete result over a partial tree.
    if (omittedTotal(snapshot.omitted) > 0)
      for (const slot of scanners)
        if (slot.state === 'completed') {
          slot.state = 'limited';
          slot.reason = 'snapshot-entries-omitted';
        }
    if (options.imports !== undefined) {
      const imported = aggregateScanReport(snapshot.commitSha, options.imports);
      for (const id of ['tests', 'coverage'] as const) {
        const claim = slotFor(imported.scanners, id);
        const slot = slotFor(scanners, id);
        if (claim.state === 'missing') continue;
        slot.evidence = 'imported-unverified';
        slot.coverage = 'declared-only';
        slot.reason =
          claim.state === 'invalid' ? 'invalid-import' : 'unverified-input';
        slot.state =
          claim.state === 'completed'
            ? 'limited'
            : claim.state === 'invalid'
              ? 'failed'
              : claim.state;
        if (claim.findingCount !== undefined)
          slot.findingCount = claim.findingCount;
        if (id === 'coverage' && options.coverageSummary !== undefined) {
          report.importedCoverage = parseCoverageSummary(
            options.coverageSummary,
          );
          if (report.importedCoverage.status === 'invalid') {
            slot.state = 'failed';
            slot.reason = 'invalid-import';
          }
        }
      }
    }
  } catch {
    // Unexpected runner failure cannot be assumed to have settled its children.
    report.cleanup = 'uncertain-retained';
  } finally {
    if (report.cleanup !== 'uncertain-retained') {
      try {
        await snapshot.dispose();
        if (bundleDirectory)
          await rm(bundleDirectory, { recursive: true, force: true });
        report.cleanup = 'completed';
      } catch {
        report.cleanup = 'failed';
      }
    }
  }
  return report;
}

/** Looks up a scanner slot that the report always contains for every id. */
function slotFor<T extends { id: string }>(slots: readonly T[], id: string): T {
  const slot = slots.find((candidate) => candidate.id === id);
  if (slot === undefined) throw new Error(`missing scanner slot: ${id}`);
  return slot;
}
