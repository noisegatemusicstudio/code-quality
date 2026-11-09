import { aggregateScanReport } from './scan-report.js';
import { parseEslintJson } from './eslint-import.js';
import { parseCoverageSummary } from './coverage-import.js';

// Usage: node dist/src/import-cli.js aggregate|eslint|coverage <declared-commit>
// Input is only stdin. No scanners, repository configuration or files are read.
// Exit 0: parsed import or complete aggregate, never a passing quality gate.
// Exit 1: incomplete aggregate. Exit 2: invalid input, arguments or stdin.
const invalid = { schemaVersion: 1, status: 'invalid' };
const args = process.argv.slice(2);
const [command, commitSha] = args;
// A closed output pipe must not expose an unhandled error or stack trace.
process.stdout.on('error', () => {
  process.exitCode = 2;
});

async function main(): Promise<void> {
  if (args.length === 1 && command === '--help') {
    process.stdout.write(
      JSON.stringify({
        schemaVersion: 1,
        status: 'help',
        usage:
          'node dist/src/import-cli.js aggregate|eslint|coverage <declared-commit>',
        input: 'UTF-8 JSON on stdin only, at most 262144 bytes',
        declaredCommit: 'Exactly 40 lowercase hexadecimal characters',
        provenance: 'imported-unverified',
        meaning:
          'Parsed or complete imported evidence is not a passing quality gate or proof of scanner execution.',
        exitCodes: {
          '0': 'Parsed import or complete aggregate',
          '1': 'Incomplete aggregate',
          '2': 'Invalid arguments, input or I/O',
        },
      }) + '\n',
    );
    return;
  }
  if (
    args.length !== 2 ||
    !['aggregate', 'eslint', 'coverage'].includes(command) ||
    typeof commitSha !== 'string' ||
    commitSha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(commitSha)
  ) {
    process.exitCode = 2;
    process.stdout.write(JSON.stringify(invalid) + '\n');
    return;
  }
  try {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      if (!(chunk instanceof Uint8Array)) throw new Error();
      size += chunk.byteLength;
      if (size > 262144) throw new Error();
      chunks.push(chunk);
    }
    const raw = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(Buffer.concat(chunks));
    if (command === 'aggregate') {
      const input: unknown = JSON.parse(raw);
      const report = aggregateScanReport(commitSha, input);
      process.exitCode = report.status === 'complete' ? 0 : 1;
      process.stdout.write(JSON.stringify(report) + '\n');
    } else {
      const result =
        command === 'eslint' ? parseEslintJson(raw) : parseCoverageSummary(raw);
      process.exitCode = result.status === 'parsed' ? 0 : 2;
      process.stdout.write(
        JSON.stringify({
          schemaVersion: 1,
          commitSha,
          provenance: 'imported-unverified',
          dialect:
            command === 'eslint'
              ? 'eslint-10.13.0-json'
              : 'istanbul-reports-3.1.7-json-summary',
          ...result,
        }) + '\n',
      );
    }
  } catch {
    process.exitCode = 2;
    process.stdout.write(JSON.stringify(invalid) + '\n');
  }
}

await main();
