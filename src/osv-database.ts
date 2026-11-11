import { createHash } from 'node:crypto';
import { crc32 } from 'node:zlib';
import { constants } from 'node:fs';
import { Readable } from 'node:stream';
import { open } from 'node:fs/promises';
import {
  validateOsvRecord,
  type OsvValidationProfile,
} from './osv-record-validation.js';
import { OSV_CACHE_COMPRESSED_LIMIT } from './osv-cache-copy.js';
import {
  fromBufferPromise,
  fromRandomAccessReaderPromise,
  RandomAccessReader,
  parseExtraFields,
  type Entry,
  type ZipFile,
} from 'yauzl';

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

export const OSV_FILE_DATABASE_LIMITS = Object.freeze({
  compressedBytes: OSV_CACHE_COMPRESSED_LIMIT,
  entryBytes: 8 * 1024 * 1024,
  expandedBytes: 2 * 1024 * 1024 * 1024,
  entries: 500_000,
});

export interface ValidatedOsvDatabase {
  validationProfile: OsvValidationProfile;
  schemaConformance: 'strict' | 'metadata-warnings';
  metadataWarningCounts: {
    records: number;
    referenceUriFormat: number;
    cvssV4TrailingSlash: number;
  };
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

function reject(): never {
  throw new Error('Invalid or unsupported offline OSV database');
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface Envelope {
  start: number;
  size: number;
  count: number;
}
function zipEnvelope(
  tail: Buffer,
  totalBytes: number,
  allowCountZip64: boolean,
): Envelope {
  const offset = totalBytes - tail.length;
  for (let end = tail.length - 22; end >= 0; end--) {
    if (
      tail.readUInt32LE(end) !== 0x06054b50 ||
      end + 22 + tail.readUInt16LE(end + 20) !== tail.length
    )
      continue;
    const start = tail.readUInt32LE(end + 16);
    const size = tail.readUInt32LE(end + 12);
    const count = tail.readUInt16LE(end + 10);
    if (
      tail.readUInt16LE(end + 4) !== 0 ||
      tail.readUInt16LE(end + 6) !== 0 ||
      tail.readUInt16LE(end + 8) !== count ||
      start === 0xffffffff ||
      size === 0xffffffff
    )
      reject();
    if (end >= 20 && tail.readUInt32LE(end - 20) === 0x07064b50) {
      if (!allowCountZip64 || end < 76) reject();
      const record = end - 76;
      const locator = end - 20;
      if (
        tail.readUInt32LE(record) !== 0x06064b50 ||
        tail.readBigUInt64LE(record + 4) !== 44n ||
        tail.readUInt16LE(record + 14) !== 45 ||
        tail.readUInt32LE(record + 16) !== 0 ||
        tail.readUInt32LE(record + 20) !== 0 ||
        tail.readUInt32LE(locator + 4) !== 0 ||
        tail.readUInt32LE(locator + 16) !== 1 ||
        tail.readBigUInt64LE(locator + 8) !== BigInt(offset + record) ||
        tail.readBigUInt64LE(record + 24) !==
          tail.readBigUInt64LE(record + 32) ||
        tail.readBigUInt64LE(record + 32) >
          BigInt(OSV_FILE_DATABASE_LIMITS.entries) ||
        tail.readBigUInt64LE(record + 40) !== BigInt(size) ||
        tail.readBigUInt64LE(record + 48) !== BigInt(start) ||
        start + size !== offset + record
      )
        reject();
      const fullCount = Number(tail.readBigUInt64LE(record + 32));
      if (count !== 0xffff && count !== fullCount) reject();
      return { start, size, count: fullCount };
    }
    if (count === 0xffff || start + size !== offset + end) reject();
    return { start, size, count };
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
  return value;
}

type ReadAt = (position: number, length: number) => Promise<Buffer>;
type Limits = typeof OSV_DATABASE_LIMITS | typeof OSV_FILE_DATABASE_LIMITS;

/** yauzl owns parsing, while the FileHandle remains the only descriptor owner. */
class FileReader extends RandomAccessReader {
  constructor(private readonly readAt: ReadAt) {
    super();
  }
  override _readStreamForRange(start: number, end: number): Readable {
    const readAt = this.readAt;
    return Readable.from(
      (async function* () {
        for (let position = start; position < end; position += 65536)
          yield await readAt(position, Math.min(65536, end - position));
      })(),
      { objectMode: false },
    );
  }
  override read(
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    callback: (error: Error | null) => void,
  ): void {
    void this.readAt(position, length).then(
      (bytes) => {
        bytes.copy(buffer, offset);
        callback(null);
      },
      () => callback(new Error('Invalid offline OSV archive read')),
    );
  }
  // RandomAccessReader.close is a no-op. Only the caller closes its FileHandle.
}

async function validateArchive(
  zip: ZipFile,
  envelope: Envelope,
  readAt: ReadAt,
  limits: Limits,
  profile: OsvValidationProfile,
  expectedEcosystem: 'npm',
): Promise<Omit<ValidatedOsvDatabase, 'sha256' | 'compressedBytes'>> {
  if (profile !== 'strict-schema-v1' && profile !== 'npm-metadata-v1') reject();
  const centralStart = envelope.start;
  if (zip.entryCount !== envelope.count || zip.entryCount > limits.entries)
    reject();
  let centralBytes = 0;
  const metadataWarningCounts = {
    records: 0,
    referenceUriFormat: 0,
    cvssV4TrailingSlash: 0,
  };
  const names = new Set<string>();
  const ids = new Set<string>();
  let expandedBytes = 0;
  let entryCount = 0;
  let withdrawnCount = 0;
  let usableCount = 0;
  let noAffectedCount = 0;
  const intervals: { start: number; end: number }[] = [];
  for await (const entry of zip.eachEntry()) {
    if (++entryCount > limits.entries) reject();
    validateEntry(entry, names);
    if (
      (await readAt(envelope.start + centralBytes + 34, 2)).readUInt16LE(0) !==
      0
    )
      reject();
    centralBytes +=
      46 +
      entry.fileNameLength +
      entry.extraFieldLength +
      entry.fileCommentLength;
    if (centralBytes > envelope.size) reject();
    expandedBytes += entry.uncompressedSize;
    if (expandedBytes > limits.expandedBytes) reject();
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
      const descriptor = await readAt(
        dataEnd,
        Math.min(16, centralStart - dataEnd),
      );
      const descriptorOffset =
        descriptor.readUInt32LE(0) === 0x08074b50 ? 4 : 0;
      dataEnd += descriptorOffset;
      if (
        dataEnd + 12 > centralStart ||
        descriptor.readUInt32LE(descriptorOffset) !== entry.crc32 ||
        descriptor.readUInt32LE(descriptorOffset + 4) !==
          entry.compressedSize ||
        descriptor.readUInt32LE(descriptorOffset + 8) !== entry.uncompressedSize
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
    const warnings = validateOsvRecord(advisory, profile);
    metadataWarningCounts.records += warnings.records;
    metadataWarningCounts.referenceUriFormat += warnings.referenceUriFormat;
    metadataWarningCounts.cvssV4TrailingSlash += warnings.cvssV4TrailingSlash;
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
  if (entryCount !== zip.entryCount || centralBytes !== envelope.size) reject();
  return {
    validationProfile: profile,
    schemaConformance: metadataWarningCounts.records
      ? 'metadata-warnings'
      : 'strict',
    metadataWarningCounts,
    expandedBytes,
    entryCount,
    activeCount: entryCount - withdrawnCount,
    usableCount,
    withdrawnCount,
    noAffectedCount,
    schemaVersion: '1.9.2',
    declaredEcosystem: expectedEcosystem,
  };
}

/** Structural validation only. Buffer API retains bounded ZIP32-only policy. */
export async function validateOsvDatabaseZip(
  archive: Buffer,
  expectedEcosystem: 'npm',
  profile: OsvValidationProfile = 'strict-schema-v1',
): Promise<ValidatedOsvDatabase> {
  let zip: ZipFile | undefined;
  try {
    if (
      expectedEcosystem !== 'npm' ||
      !Buffer.isBuffer(archive) ||
      archive.length > OSV_DATABASE_LIMITS.compressedBytes
    )
      reject();
    const input = Buffer.from(archive);
    const envelope = zipEnvelope(
      input.subarray(Math.max(0, input.length - 65633)),
      input.length,
      false,
    );
    zip = await fromBufferPromise(input, {
      lazyEntries: true,
      strictFileNames: true,
      validateEntrySizes: true,
    });
    const result = await validateArchive(
      zip,
      envelope,
      (position, length) => {
        if (position < 0 || length < 0 || position + length > input.length)
          reject();
        return Promise.resolve(input.subarray(position, position + length));
      },
      OSV_DATABASE_LIMITS,
      profile,
      expectedEcosystem,
    );
    return {
      ...result,
      sha256: createHash('sha256').update(input).digest('hex'),
      compressedBytes: input.length,
    };
  } catch {
    return reject();
  } finally {
    zip?.close();
  }
}

/** Validate one opened regular file, with lazy entry streams and no extraction.
 * The caller must keep this file in its private cache; validation is not a claim
 * about advisory provenance, freshness, completeness or data-use rights.
 */
export async function validateOsvDatabaseFile(
  path: string,
  expectedEcosystem: 'npm',
  profile: OsvValidationProfile = 'strict-schema-v1',
): Promise<ValidatedOsvDatabase> {
  let file: Awaited<ReturnType<typeof open>> | undefined;
  let zip: ZipFile | undefined;
  try {
    if (expectedEcosystem !== 'npm') reject();
    file = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await file.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.size > BigInt(OSV_FILE_DATABASE_LIMITS.compressedBytes)
    )
      reject();
    const size = Number(before.size);
    const handle = file;
    const readAt: ReadAt = async (position, length) => {
      if (position < 0 || length < 0 || position + length > size) reject();
      const buffer = Buffer.alloc(length);
      let offset = 0;
      while (offset < length) {
        const { bytesRead } = await handle.read(
          buffer,
          offset,
          length - offset,
          position + offset,
        );
        if (!bytesRead) reject();
        offset += bytesRead;
      }
      return buffer;
    };
    const tailLength = Math.min(size, 65633);
    const envelope = zipEnvelope(
      await readAt(size - tailLength, tailLength),
      size,
      true,
    );
    zip = await fromRandomAccessReaderPromise(new FileReader(readAt), size, {
      autoClose: false,
      lazyEntries: true,
      strictFileNames: true,
      validateEntrySizes: true,
    });
    const result = await validateArchive(
      zip,
      envelope,
      readAt,
      OSV_FILE_DATABASE_LIMITS,
      profile,
      expectedEcosystem,
    );
    const digest = createHash('sha256');
    for (let position = 0; position < size; position += 65536)
      digest.update(await readAt(position, Math.min(65536, size - position)));
    const after = await file.stat({ bigint: true });
    if (
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    )
      reject();
    return { ...result, sha256: digest.digest('hex'), compressedBytes: size };
  } catch {
    return reject();
  } finally {
    zip?.close();
    await file?.close();
  }
}
