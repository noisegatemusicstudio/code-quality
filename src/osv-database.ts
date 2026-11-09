import { createHash } from 'node:crypto';
import { crc32 } from 'node:zlib';
import { Ajv2020 } from 'ajv/dist/2020.js';
import formats from 'ajv-formats';
import {
  fromBufferPromise,
  parseExtraFields,
  type Entry,
  type ZipFile,
} from 'yauzl';
import schema from './osv-schema-v1.9.2.json' with { type: 'json' };

export const OSV_SCHEMA_METADATA = Object.freeze({
  version: '1.9.2',
  source:
    'https://raw.githubusercontent.com/ossf/osv-schema/v1.9.2/validation/schema.json',
  sha256: '15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653',
  license: 'Apache-2.0',
});

export const OSV_DATABASE_LIMITS = Object.freeze({
  compressedBytes: 64 * 1024 * 1024,
  entryBytes: 8 * 1024 * 1024,
  expandedBytes: 128 * 1024 * 1024,
  entries: 50_000,
});

export interface ValidatedOsvDatabase {
  sha256: string;
  compressedBytes: number;
  expandedBytes: number;
  entryCount: number;
  activeCount: number;
  usableCount: number;
  withdrawnCount: number;
  noAffectedCount: number;
  schemaVersion: '1.9.2';
  declaredEcosystem: 'npm';
}

const ajv = new Ajv2020({
  strict: false,
  allErrors: false,
  validateFormats: true,
});
formats.default(ajv);
// Compile only the pinned local schema, with no remote loader or caller schemas.
const validate = ajv.compile(schema);

function reject(): never {
  throw new Error('Invalid or unsupported offline OSV database');
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function zip32CentralStart(input: Buffer): number {
  // Envelope policy only; yauzl owns ZIP entry parsing and decompression.
  for (
    let end = input.length - 22;
    end >= Math.max(0, input.length - 65_557);
    end--
  ) {
    if (
      input.readUInt32LE(end) !== 0x06054b50 ||
      end + 22 + input.readUInt16LE(end + 20) !== input.length
    )
      continue;
    const start = input.readUInt32LE(end + 16);
    if (
      input.readUInt16LE(end + 4) !== 0 ||
      input.readUInt16LE(end + 6) !== 0 ||
      input.readUInt16LE(end + 8) !== input.readUInt16LE(end + 10) ||
      input.readUInt16LE(end + 10) === 0xffff ||
      start === 0xffffffff ||
      start + input.readUInt32LE(end + 12) !== end ||
      (end >= 20 && input.readUInt32LE(end - 20) === 0x07064b50)
    )
      reject();
    return start;
  }
  return reject();
}

function boundJson(value: unknown): void {
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const item = pending.pop()!;
    if (++nodes > 200_000 || item.depth > 64) reject();
    if (typeof item.value === 'object' && item.value !== null) {
      for (const child of Object.values(item.value)) {
        pending.push({ value: child, depth: item.depth + 1 });
      }
    }
  }
}

function validateEntry(entry: Entry, names: Set<string>): void {
  const unixType = (entry.externalFileAttributes >>> 16) & 0xf000;
  const name = entry.fileName;
  if (
    entry.isEncrypted() ||
    ![0, 8].includes(entry.compressionMethod) ||
    (entry.generalPurposeBitFlag & ~0x80e) !== 0 ||
    entry.extraFields.some((field) => field.id === 1) ||
    entry.versionNeededToExtract > 20 ||
    entry.uncompressedSize > OSV_DATABASE_LIMITS.entryBytes ||
    name.length > 512 ||
    !name.endsWith('.json') ||
    /[\\:]/.test(name) ||
    [...name].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    ) ||
    name.startsWith('/') ||
    name
      .split('/')
      .some((part) => part === '' || part === '.' || part === '..') ||
    names.has(name.toLowerCase()) ||
    (entry.externalFileAttributes & 0x10) !== 0 ||
    (unixType !== 0 && unixType !== 0x8000)
  )
    reject();
  names.add(name.toLowerCase());
}

async function readAdvisory(zip: ZipFile, entry: Entry): Promise<unknown> {
  const stream = await zip.openReadStreamPromise(entry);
  const chunks: Buffer[] = [];
  let size = 0;
  let checksum = 0;
  try {
    for await (const chunk of stream) {
      if (!Buffer.isBuffer(chunk)) reject();
      size += chunk.length;
      if (
        size > entry.uncompressedSize ||
        size > OSV_DATABASE_LIMITS.entryBytes
      )
        reject();
      checksum = crc32(chunk, checksum);
      chunks.push(chunk);
    }
  } finally {
    stream.destroy();
  }
  if (size !== entry.uncompressedSize || checksum !== entry.crc32) reject();
  const value: unknown = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(
      Buffer.concat(chunks, size),
    ),
  );
  boundJson(value);
  if (!validate(value)) reject();
  return value;
}

/**
 * Structural validation only, never a clean bill of health. Provenance,
 * completeness, freshness and advisory licenses remain caller declarations.
 * Empty/withdrawn/no-affected records are valid schema cases, not coverage.
 * Supports bounded single-disk ZIP32 store/deflate, including data descriptors.
 * No files are extracted. Current official archive compatibility is unverified.
 */
export async function validateOsvDatabaseZip(
  archive: Buffer,
  expectedEcosystem: 'npm',
): Promise<ValidatedOsvDatabase> {
  let zip: ZipFile | undefined;
  try {
    if (
      expectedEcosystem !== 'npm' ||
      !Buffer.isBuffer(archive) ||
      archive.length > OSV_DATABASE_LIMITS.compressedBytes
    )
      reject();
    // Own the bytes so callers cannot mutate them during asynchronous streams.
    const input = Buffer.from(archive);
    const centralStart = zip32CentralStart(input);
    zip = await fromBufferPromise(input, {
      lazyEntries: true,
      strictFileNames: true,
      validateEntrySizes: true,
    });
    if (zip.entryCount > OSV_DATABASE_LIMITS.entries) reject();
    const names = new Set<string>();
    const ids = new Set<string>();
    let expandedBytes = 0;
    let entryCount = 0;
    let withdrawnCount = 0;
    let usableCount = 0;
    let noAffectedCount = 0;
    const intervals: { start: number; end: number }[] = [];
    for await (const entry of zip.eachEntry()) {
      if (++entryCount > OSV_DATABASE_LIMITS.entries) reject();
      validateEntry(entry, names);
      expandedBytes += entry.uncompressedSize;
      if (expandedBytes > OSV_DATABASE_LIMITS.expandedBytes) reject();
      const header = await zip.readLocalFileHeaderPromise(entry);
      if (
        header.versionNeededToExtract > 20 ||
        parseExtraFields(header.extraField).some((field) => field.id === 1)
      )
        reject();
      if (
        header.generalPurposeBitFlag !== entry.generalPurposeBitFlag ||
        header.compressionMethod !== entry.compressionMethod ||
        !header.fileName.equals(entry.fileNameRaw)
      )
        reject();
      if (
        (entry.generalPurposeBitFlag & 8) === 0 &&
        (header.crc32 !== entry.crc32 ||
          header.compressedSize !== entry.compressedSize ||
          header.uncompressedSize !== entry.uncompressedSize)
      )
        reject();
      let dataEnd = header.fileDataStart + entry.compressedSize;
      if ((entry.generalPurposeBitFlag & 8) !== 0) {
        // Descriptor values must agree, whether the optional signature is used.
        if (dataEnd + 12 > centralStart) reject();
        if (input.readUInt32LE(dataEnd) === 0x08074b50) dataEnd += 4;
        if (
          dataEnd + 12 > centralStart ||
          input.readUInt32LE(dataEnd) !== entry.crc32 ||
          input.readUInt32LE(dataEnd + 4) !== entry.compressedSize ||
          input.readUInt32LE(dataEnd + 8) !== entry.uncompressedSize
        )
          reject();
        dataEnd += 12;
      }
      if (dataEnd > centralStart) reject();
      intervals.push({
        start: entry.relativeOffsetOfLocalHeader,
        end: dataEnd,
      });
      const advisory = await readAdvisory(zip, entry);
      if (
        !object(advisory) ||
        typeof advisory.id !== 'string' ||
        ids.has(advisory.id)
      )
        reject();
      ids.add(advisory.id);
      if (advisory.withdrawn !== undefined) withdrawnCount++;
      const affected = advisory.affected;
      if (!Array.isArray(affected) || affected.length === 0) noAffectedCount++;
      else {
        const declared = affected.flatMap((item: unknown) =>
          object(item) && object(item.package) ? [item.package.ecosystem] : [],
        );
        if (declared.length > 0 && !declared.includes(expectedEcosystem))
          reject();
        if (declared.length === 0) noAffectedCount++;
        if (
          advisory.withdrawn === undefined &&
          declared.includes(expectedEcosystem)
        )
          usableCount++;
      }
    }
    intervals.sort((a, b) => a.start - b.start);
    if (
      intervals.some(
        (item, index) =>
          item.start !== (index === 0 ? 0 : intervals[index - 1].end),
      ) ||
      (intervals.length ? intervals[intervals.length - 1].end : 0) !==
        centralStart
    )
      reject();
    if (entryCount !== zip.entryCount) reject();
    return {
      sha256: createHash('sha256').update(input).digest('hex'),
      compressedBytes: input.length,
      expandedBytes,
      entryCount,
      activeCount: entryCount - withdrawnCount,
      usableCount,
      withdrawnCount,
      noAffectedCount,
      schemaVersion: '1.9.2',
      declaredEcosystem: expectedEcosystem,
    };
  } catch {
    return reject();
  } finally {
    zip?.close();
  }
}
