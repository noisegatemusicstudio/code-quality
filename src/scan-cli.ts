import { scanCommittedSource, executionManifest } from './customer-scan.js';
import { isAbsolute } from 'node:path';

const invalid = { schemaVersion: 2, status: 'invalid' };
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const absolute = (value: unknown): value is string =>
  typeof value === 'string' &&
  value.length <= 4096 &&
  !value.includes('\0') &&
  isAbsolute(value);
process.stdout.on('error', () => {
  process.exitCode = 2;
});
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write(
      JSON.stringify({
        schemaVersion: 2,
        status: 'help',
        usage: 'node dist/src/scan-cli.js < scan-input.json',
        input: 'UTF-8 JSON stdin only, maximum 262144 bytes',
        required: ['gitExecutable', 'gitDirectory', 'commitSha'],
        optional: [
          'tools.gitleaks',
          'tools.jscpd',
          'tools.osv',
          'osvDatabase.{archivePath,sha256,asOf}',
          'declarationBundle.files',
          'imports',
          'coverageSummary',
        ],
        trust:
          'Explicit trusted absolute executables; scans bounded committed snapshot only, not working tree. Linux x64 native tools only. No hostile-code sandbox, project-config execution, network mode or downloads.',
        completion:
          'All slots are present. Imported tests/coverage and caller database completeness remain unverified, so reports remain incomplete; counts are not a passing quality gate.',
        exitCodes: {
          '0': 'Help',
          '1': 'Incomplete execution report',
          '2': 'Invalid input or I/O',
        },
        manifest: executionManifest,
      }) + '\n',
    );
    return;
  }
  if (args.length) throw new Error();
  let size = 0;
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) {
    if (!(chunk instanceof Uint8Array) || (size += chunk.byteLength) > 262144)
      throw new Error();
    chunks.push(chunk);
  }
  const input: unknown = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
  );
  if (
    !object(input) ||
    Object.keys(input).some(
      (key) =>
        ![
          'gitExecutable',
          'gitDirectory',
          'commitSha',
          'tools',
          'osvDatabase',
          'declarationBundle',
          'imports',
          'coverageSummary',
        ].includes(key),
    ) ||
    !absolute(input.gitExecutable) ||
    !absolute(input.gitDirectory) ||
    typeof input.commitSha !== 'string' ||
    input.commitSha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(input.commitSha)
  )
    throw new Error();
  let tools: { gitleaks?: string; jscpd?: string; osv?: string } | undefined;
  if (input.tools !== undefined) {
    if (
      !object(input.tools) ||
      Object.keys(input.tools).some(
        (key) => !['gitleaks', 'jscpd', 'osv'].includes(key),
      )
    )
      throw new Error();
    tools = {};
    for (const key of ['gitleaks', 'jscpd', 'osv'] as const) {
      const value = input.tools[key];
      if (value !== undefined) {
        if (!absolute(value)) throw new Error();
        tools[key] = value;
      }
    }
  }
  let osvDatabase:
    { archivePath: string; sha256: string; asOf: string } | undefined;
  if (input.osvDatabase !== undefined) {
    const database = input.osvDatabase;
    if (
      !object(database) ||
      !absolute(database.archivePath) ||
      typeof database.sha256 !== 'string' ||
      typeof database.asOf !== 'string'
    )
      throw new Error();
    osvDatabase = {
      archivePath: database.archivePath,
      sha256: database.sha256,
      asOf: database.asOf,
    };
  }
  const report = await scanCommittedSource({
    gitExecutable: input.gitExecutable,
    gitDirectory: input.gitDirectory,
    commitSha: input.commitSha,
    tools,
    osvDatabase,
    declarationBundle: input.declarationBundle,
    imports: input.imports,
    coverageSummary: input.coverageSummary,
  });
  process.exitCode = 1;
  process.stdout.write(JSON.stringify(report) + '\n');
}
main().catch(() => {
  process.exitCode = 2;
  process.stdout.write(JSON.stringify(invalid) + '\n');
});
