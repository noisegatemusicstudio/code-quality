import { createHash } from 'node:crypto';
import {
  mkdtemp,
  mkdir,
  writeFile,
  rm,
  readdir,
  realpath,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';
import { readBoundedRegular } from './external-scanners.js';
import type { ValidatedOsvDatabase } from './osv-database.js';
import { fileURLToPath } from 'node:url';
import { runScannerProcess } from './scanner-process.js';
import { immutableMetadata } from './scan-metadata.js';

export const osvPin = immutableMetadata({
  version: '2.7.1',
  license: 'Apache-2.0',
  sha256: 'fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8',
  coverage:
    'npm package-lock only; source resolution, call analysis, queries, downloads and updates disabled; caller database completeness/freshness unverified',
  databaseLimits: {
    compressedBytes: 67108864,
    expandedBytes: 134217728,
    entries: 50000,
    workerV8OldSpaceMiB: 256,
    bufferMemory:
      'Separately bounded archive/entry/expanded byte limits; V8 old-space is not a total RSS cap',
    validationTimeoutMs: 15000,
    officialFullArchiveCompatibility:
      'unverified; large full-ecosystem archives may exceed supported bounds',
  },
});
export interface OsvDatabaseInput {
  archivePath: string;
  sha256: string;
  asOf: string;
}
export interface OsvExecutionResult {
  id: 'osv';
  state: 'missing' | 'failed' | 'timed-out' | 'limited';
  evidence: 'none' | 'executed';
  reason:
    | 'missing-tool-or-database'
    | 'unsupported-platform'
    | 'invalid-tool-or-database'
    | 'no-supported-lockfiles'
    | 'execution-or-report-failed'
    | 'cleanup-uncertain'
    | 'caller-database-unverified'
    | 'unsupported-dependency-manifests';
  toolVersion: string;
  binarySha256: string;
  coverage: 'npm-package-lock-only';
  findingCount?: number;
  coveredFileCount?: number;
  packageCount?: number;
  unsupportedManifestCount?: number;
  database?: ValidatedOsvDatabase & {
    asOf: string;
    provenance: 'caller-declared';
    freshness: 'unverified';
    completeness: 'unverified';
  };
}
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
export function parseOsvReport(raw: Buffer, lockfiles: readonly string[]) {
  if (raw.length > 1048576) return null;
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    return null;
  }
  if (
    !record(value) ||
    !Array.isArray(value.results) ||
    !value.results.length ||
    value.results.length > 1000
  )
    return null;
  let findingCount = 0;
  let packageCount = 0;
  const covered = new Set<string>();
  for (const source of value.results) {
    if (
      !record(source) ||
      !record(source.source) ||
      source.source.type !== 'lockfile' ||
      typeof source.source.path !== 'string' ||
      !lockfiles.includes(source.source.path) ||
      !Array.isArray(source.packages) ||
      !source.packages.length
    )
      return null;
    covered.add(source.source.path);
    for (const item of source.packages) {
      if (
        ++packageCount > 10000 ||
        !record(item) ||
        !record(item.package) ||
        item.package.ecosystem !== 'npm' ||
        typeof item.package.name !== 'string' ||
        !item.package.name ||
        typeof item.package.version !== 'string' ||
        !item.package.version
      )
        return null;
      if (item.vulnerabilities !== undefined) {
        if (!Array.isArray(item.vulnerabilities)) return null;
        for (const vulnerability of item.vulnerabilities) {
          if (
            !record(vulnerability) ||
            typeof vulnerability.id !== 'string' ||
            !vulnerability.id ||
            ++findingCount > 10000
          )
            return null;
        }
      }
    }
  }
  if (covered.size !== lockfiles.length) return null;
  return { findingCount, packageCount, coveredFileCount: covered.size };
}

async function runOfflineOsvInner(
  sourceDirectory: string,
  executable?: string,
  database?: OsvDatabaseInput,
): Promise<OsvExecutionResult> {
  const result: OsvExecutionResult = {
    id: 'osv',
    state: 'missing',
    evidence: 'none',
    reason: 'missing-tool-or-database',
    toolVersion: osvPin.version,
    binarySha256: osvPin.sha256,
    coverage: 'npm-package-lock-only',
  };
  if (executable === undefined || database === undefined) return result;
  if (process.platform !== 'linux' || process.arch !== 'x64')
    return { ...result, state: 'failed', reason: 'unsupported-platform' };
  let directory = '';
  let uncertain = false;
  let inFlight = false;
  try {
    result.state = 'failed';
    result.reason = 'invalid-tool-or-database';
    if (
      !isAbsolute(executable) ||
      (await realpath(executable)) !== resolve(executable) ||
      !isAbsolute(database.archivePath) ||
      (await realpath(database.archivePath)) !==
        resolve(database.archivePath) ||
      typeof database.sha256 !== 'string' ||
      database.sha256.length !== 64 ||
      !/^[a-f0-9]{64}$/.test(database.sha256) ||
      typeof database.asOf !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(database.asOf) ||
      !Number.isFinite(Date.parse(database.asOf)) ||
      new Date(database.asOf).toISOString().replace('.000Z', 'Z') !==
        database.asOf
    )
      return result;
    const binary = await readBoundedRegular(executable, 67108864);
    if (createHash('sha256').update(binary).digest('hex') !== osvPin.sha256)
      return result;
    const archive = await readBoundedRegular(database.archivePath, 67108864);
    if (createHash('sha256').update(archive).digest('hex') !== database.sha256)
      return result;
    directory = await mkdtemp(join(tmpdir(), 'code-quality-osv-'));
    const tool = join(directory, 'scanner');
    await writeFile(tool, binary, { flag: 'wx', mode: 0o700 });
    const cache = join(directory, 'cache');
    await mkdir(join(cache, 'osv-scalibr/npm'), {
      recursive: true,
      mode: 0o700,
    });
    const archivePath = join(cache, 'osv-scalibr/npm/all.zip');
    await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 });
    inFlight = true;
    const validation = await runScannerProcess({
      executable: process.execPath,
      args: [
        '--max-old-space-size=256',
        fileURLToPath(new URL('./osv-database-worker.js', import.meta.url)),
        archivePath,
      ],
      cwd: directory,
      timeoutMs: 15000,
      outputLimit: 8192,
    });
    inFlight = false;
    if (validation.state === 'cleanup-uncertain') {
      uncertain = true;
      return { ...result, reason: 'cleanup-uncertain' };
    }
    if (validation.state === 'timed-out')
      return { ...result, state: 'timed-out' };
    if (validation.state !== 'exited' || validation.code !== 0) return result;
    const metadata: unknown = JSON.parse(validation.stdout.toString('utf8'));
    if (
      !record(metadata) ||
      metadata.sha256 !== database.sha256 ||
      metadata.schemaVersion !== '1.9.2' ||
      metadata.declaredEcosystem !== 'npm'
    )
      return result;
    for (const field of [
      'compressedBytes',
      'expandedBytes',
      'entryCount',
      'activeCount',
      'withdrawnCount',
      'noAffectedCount',
      'usableCount',
    ]) {
      if (
        typeof metadata[field] !== 'number' ||
        !Number.isSafeInteger(metadata[field]) ||
        metadata[field] < 0
      )
        return result;
    }
    const validated: ValidatedOsvDatabase = {
      sha256: database.sha256,
      schemaVersion: '1.9.2',
      declaredEcosystem: 'npm',
      compressedBytes: metadata.compressedBytes as number,
      expandedBytes: metadata.expandedBytes as number,
      entryCount: metadata.entryCount as number,
      activeCount: metadata.activeCount as number,
      withdrawnCount: metadata.withdrawnCount as number,
      noAffectedCount: metadata.noAffectedCount as number,
      usableCount: metadata.usableCount as number,
    };
    result.database = {
      ...validated,
      asOf: database.asOf,
      provenance: 'caller-declared',
      freshness: 'unverified',
      completeness: 'unverified',
    };
    // Empty/advisory-free datasets cannot establish vulnerability coverage.
    if (validated.usableCount === 0) return result;
    const lockfiles: string[] = [];
    let unsupportedManifestCount = 0;
    const walk = async (path: string): Promise<void> => {
      for (const entry of await readdir(path, { withFileTypes: true })) {
        const target = join(path, entry.name);
        if (entry.isDirectory()) await walk(target);
        else if (!entry.isFile()) throw new Error();
        else if (entry.name === 'package-lock.json') lockfiles.push(target);
        else if (
          /^(?:Cargo\.(?:lock|toml)|go\.(?:mod|sum)|requirements[^/]*\.txt|Pipfile(?:\.lock)?|poetry\.lock|pyproject\.toml|uv\.lock|Gemfile(?:\.lock)?|pom\.xml|build\.gradle(?:\.kts)?|gradle\.lockfile|composer\.(?:json|lock)|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|packages\.(?:lock\.json|config)|.*\.csproj)$/.test(
            entry.name,
          )
        )
          unsupportedManifestCount++;
      }
    };
    await walk(sourceDirectory);
    lockfiles.sort((left, right) => {
      if (left === right) return 0;
      return left < right ? -1 : 1;
    });
    result.unsupportedManifestCount = unsupportedManifestCount;
    if (!lockfiles.length || lockfiles.length > 100)
      return { ...result, state: 'limited', reason: 'no-supported-lockfiles' };
    // Only the immutable owned copy just validated is passed to OSV; caller storage is untouched.
    const config = join(directory, 'config.toml');
    await writeFile(config, '', { flag: 'wx', mode: 0o600 });
    result.reason = 'execution-or-report-failed';
    inFlight = true;
    const execution = await runScannerProcess({
      executable: '/usr/bin/prlimit',
      args: [
        '--as=8589934592:8589934592',
        '--fsize=1048576:1048576',
        '--cpu=30:30',
        '--',
        tool,
        'scan',
        'source',
        '--offline',
        '--no-resolve',
        '--no-call-analysis=go,rust',
        '--format=json',
        '--all-packages',
        '--config',
        config,
        '--local-db-path',
        cache,
        ...lockfiles.flatMap((path) => ['--lockfile', path]),
      ],
      cwd: directory,
      timeoutMs: 30000,
      outputLimit: 1048576,
    });
    inFlight = false;
    if (execution.state === 'cleanup-uncertain') {
      uncertain = true;
      return { ...result, reason: 'cleanup-uncertain' };
    }
    if (execution.state === 'timed-out')
      return { ...result, state: 'timed-out' };
    if (
      execution.state !== 'exited' ||
      (execution.code !== 0 && execution.code !== 1)
    )
      return result;
    const parsed = parseOsvReport(execution.stdout, lockfiles);
    if (
      parsed === null ||
      (execution.code === 0) !== (parsed.findingCount === 0)
    )
      return result;
    return {
      ...result,
      ...parsed,
      state: 'limited',
      evidence: 'executed',
      reason: unsupportedManifestCount
        ? 'unsupported-dependency-manifests'
        : 'caller-database-unverified',
    };
  } catch {
    if (inFlight) uncertain = true;
    return {
      ...result,
      state: 'failed',
      reason: uncertain ? 'cleanup-uncertain' : result.reason,
    };
  } finally {
    if (directory && !uncertain) {
      await rm(directory, { recursive: true, force: true });
    }
  }
}

export async function runOfflineOsv(
  sourceDirectory: string,
  executable?: string,
  database?: OsvDatabaseInput,
): Promise<OsvExecutionResult> {
  try {
    return await runOfflineOsvInner(sourceDirectory, executable, database);
  } catch {
    return {
      id: 'osv',
      state: 'failed',
      evidence: 'none',
      reason: 'cleanup-uncertain',
      toolVersion: osvPin.version,
      binarySha256: osvPin.sha256,
      coverage: 'npm-package-lock-only',
    };
  }
}
