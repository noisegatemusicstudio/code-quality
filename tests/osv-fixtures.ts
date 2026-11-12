import { crc32, deflateRawSync } from 'node:zlib';

export interface SyntheticZipEntry {
  name?: string;
  data?: Buffer;
  advisory?: unknown;
  deflate?: boolean;
  descriptor?: boolean;
  unsignedDescriptor?: boolean;
}

export function syntheticAdvisory(
  id = 'GHSA-2345-6789-cfgh',
): Record<string, unknown> {
  return {
    id,
    modified: '2026-11-01T00:00:00Z',
    affected: [
      {
        package: { name: 'synthetic-package', ecosystem: 'npm' },
        versions: ['1.0.0'],
      },
    ],
  };
}

/** Synthetic bytes only. This helper never reads/downloads a real database. */
export function makeSyntheticOsvZip(entries: SyntheticZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  entries.forEach((entry, index) => {
    const name = Buffer.from(entry.name ?? `synthetic-${String(index)}.json`);
    const raw =
      entry.data ??
      Buffer.from(
        JSON.stringify(
          'advisory' in entry ? entry.advisory : syntheticAdvisory(),
        ),
      );
    const data = entry.deflate ? deflateRawSync(raw) : raw;
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(entry.descriptor ? 8 : 0, 6);
    local.writeUInt16LE(entry.deflate ? 8 : 0, 8);
    if (!entry.descriptor) {
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(data.length, 18);
      local.writeUInt32LE(raw.length, 22);
    }
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    local.copy(central, 8, 6, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    const descriptor = Buffer.alloc(
      entry.descriptor ? (entry.unsignedDescriptor ? 12 : 16) : 0,
    );
    if (entry.descriptor) {
      const start = entry.unsignedDescriptor ? 0 : 4;
      if (start) descriptor.writeUInt32LE(0x08074b50);
      descriptor.writeUInt32LE(crc, start);
      descriptor.writeUInt32LE(data.length, start + 4);
      descriptor.writeUInt32LE(raw.length, start + 8);
    }
    locals.push(local, name, data, descriptor);
    centrals.push(central, name);
    offset += local.length + name.length + data.length + descriptor.length;
  });
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
