// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: scanner pipeline pieces against synthetic Git fixtures and real tools; not a hosted-service path.
import { requireSupportedGit } from './git-requirement.js';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtemp,
  mkdir,
  writeFile,
  rm,
  readFile,
  access,
} from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import {
  scanCommittedSource,
  executionManifest,
} from '../src/customer-scan.js';
import { validateDeclarationBundle } from '../src/declaration-bundle.js';
import { acceptExternalReport } from '../src/external-scanners.js';
import { runOfflineOsv, parseOsvReport } from '../src/osv-scanner.js';
import { makeSyntheticOsvZip, syntheticAdvisory } from './osv-fixtures.js';

const root = resolve(import.meta.dirname, '../..');
const installed = async (name: string) => {
  try {
    await access(join(root, '.fixtures/scanner-tools', name));
    return true;
  } catch {
    return false;
  }
};
const allInstalled = (
  await Promise.all(['gitleaks', 'jscpd', 'osv-scanner'].map(installed))
).every(Boolean);
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'integrated-scanner-'));
  const git = (...args: string[]) =>
    execFileSync(requireSupportedGit(), args, {
      cwd: directory,
      encoding: 'utf8',
      env: {
        HOME: directory,
        PATH: '/usr/bin',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
    }).trim();
  git('init', '-q');
  await mkdir(join(directory, 'src'));
  const code = Array.from(
    { length: 30 },
    (_, i) => `export const value${i} = ${i} + 3;`,
  ).join('\n');
  await writeFile(join(directory, 'src/a.ts'), code);
  await writeFile(join(directory, 'src/b.ts'), code);
  const lock = {
    name: 'synthetic',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'synthetic', version: '1.0.0' },
      'node_modules/synthetic-package': {
        version: '1.0.0',
        resolved:
          'https://registry.npmjs.org/synthetic-package/-/synthetic-package-1.0.0.tgz',
      },
    },
  };
  await writeFile(join(directory, 'package-lock.json'), JSON.stringify(lock));
  const commit = () => {
    git('add', '.');
    git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'fixture',
      '--no-verify',
    );
    return git('rev-parse', 'HEAD');
  };
  const commitSha = commit();
  return {
    directory,
    git,
    commit,
    options: {
      gitExecutable: requireSupportedGit(),
      gitDirectory: join(directory, '.git'),
      commitSha,
    },
    dispose: () => rm(directory, { recursive: true, force: true }),
  };
}

await test('exit/report consistency rejects impossible native completion claims', () => {
  const findings = Buffer.from(
    JSON.stringify([
      { RuleID: 'synthetic', StartLine: 1, EndLine: 1, Secret: 'REDACTED' },
    ]),
  );
  assert.equal(acceptExternalReport('gitleaks', 0, findings), null);
  assert.equal(acceptExternalReport('gitleaks', 42, Buffer.from('[]')), null);
  assert.equal(acceptExternalReport('gitleaks', 1, findings), null);
  assert.equal(acceptExternalReport('gitleaks', 0, Buffer.from('[')), null);
  const clones = Buffer.from(
    JSON.stringify({
      duplicates: [{}],
      statistics: {
        total: {
          clones: 1,
          sources: 2,
          lines: 60,
          tokens: 480,
          duplicatedLines: 30,
          duplicatedTokens: 240,
        },
      },
    }),
  );
  assert.equal(acceptExternalReport('jscpd', 0, clones), null);
  assert.deepEqual(acceptExternalReport('jscpd', 42, clones), {
    findingCount: 1,
    coveredFileCount: 2,
  });
  const contradictory = Buffer.from(
    clones.toString().replace('"clones":1', '"clones":0'),
  );
  assert.equal(acceptExternalReport('jscpd', 42, contradictory), null);
  assert.equal(
    parseOsvReport(Buffer.from('{"results":[]}'), [
      '/fixture/package-lock.json',
    ]),
    null,
  );
});

await test('declaration-only bundles resolve real package types and cannot escape or execute metadata', async () => {
  const f = await fixture();
  try {
    await writeFile(
      join(f.directory, 'src/a.ts'),
      'import {value} from "typed-fixture"; export const answer: number = value;\n',
    );
    const options = { ...f.options, commitSha: f.commit() };
    const missing = await scanCommittedSource(options);
    assert.equal(missing.scanners[1].state, 'limited');
    const declarationBundle = {
      files: {
        'typed-fixture/index.d.ts': 'export declare const value: number;',
        'typed-fixture/package.json':
          '{"name":"typed-fixture","version":"1.0.0","types":"index.d.ts"}',
      },
    };
    const supplied = await scanCommittedSource({
      ...options,
      declarationBundle,
    });
    assert.equal(supplied.scanners[1].state, 'completed');
    assert.equal(supplied.scanners[1].unresolvedDependencyCount, 0);
    assert.equal(
      supplied.source?.declarationBundle?.sha256,
      validateDeclarationBundle(declarationBundle)?.sha256,
    );
    assert.equal(
      validateDeclarationBundle({
        files: {
          'typed-fixture/package.json': '{"types":"../../outside.d.ts"}',
        },
      }),
      null,
    );
    assert.equal(
      validateDeclarationBundle({
        files: { 'typed-fixture/run.js': 'throw new Error()' },
      }),
      null,
    );
    assert.equal(
      validateDeclarationBundle({
        files: {
          'typed-fixture/package.json': '{"scripts":{"postinstall":"trap"}}',
        },
      }),
      null,
    );
    assert.equal(
      Reflect.set(supplied.manifest.eslint, 'version', 'corrupted'),
      false,
    );
    assert.equal(executionManifest.eslint.version, '10.13.0');
    const later = await scanCommittedSource(options);
    assert.equal(later.manifest.eslint.version, '10.13.0');
  } finally {
    await f.dispose();
  }
});

await test(
  'all five real engines run against committed synthetic source; imported evidence stays unverified',
  {
    skip: allInstalled
      ? false
      : 'Pinned native development tools absent; no automatic download',
  },
  async () => {
    const f = await fixture();
    const data = await mkdtemp(join(tmpdir(), 'osv-integration-'));
    try {
      const archive = makeSyntheticOsvZip([
        { advisory: syntheticAdvisory(), deflate: true, descriptor: true },
      ]);
      const archivePath = join(data, 'all.zip');
      await writeFile(archivePath, archive);
      const database = {
        archivePath,
        sha256: createHash('sha256').update(archive).digest('hex'),
        asOf: '2026-11-01T00:00:00Z',
      };
      const tools = {
        gitleaks: join(root, '.fixtures/scanner-tools/gitleaks'),
        jscpd: join(root, '.fixtures/scanner-tools/jscpd'),
        osv: join(root, '.fixtures/scanner-tools/osv-scanner'),
      };
      const claim = {
        commitSha: f.options.commitSha,
        state: 'completed',
        findingCount: 0,
      };
      const report = await scanCommittedSource({
        ...f.options,
        tools,
        osvDatabase: database,
        imports: { tests: claim, coverage: claim },
        coverageSummary: JSON.stringify({
          total: Object.fromEntries(
            ['lines', 'statements', 'functions', 'branches'].map((key) => [
              key,
              { total: 4, covered: 2, skipped: 0 },
            ]),
          ),
        }),
      });
      assert.equal(report.cleanup, 'completed');
      assert.equal(report.importedCoverage?.status, 'parsed');
      if (report.importedCoverage?.status === 'parsed')
        assert.equal(report.importedCoverage.metrics.lines.percentage, 50);
      assert.equal(report.status, 'incomplete');
      assert.ok(
        report.scanners
          .slice(0, 5)
          .every((slot) => slot.evidence === 'executed'),
      );
      assert.ok(
        report.scanners
          .slice(5)
          .every(
            (slot) =>
              slot.evidence === 'imported-unverified' &&
              slot.state === 'limited',
          ),
      );
      const osv = report.scanners.find((slot) => slot.id === 'osv')!;
      assert.equal(osv.findingCount, 1);
      assert.equal(osv.database?.completeness, 'unverified');
      assert.equal(osv.database?.sha256, database.sha256);
      assert.equal(osv.coveredFileCount, 1);
      assert.equal(osv.state, 'limited');
      assert.ok(!JSON.stringify(report).includes('synthetic-package'));
      assert.ok(!JSON.stringify(report).includes(f.directory));
      assert.deepEqual(await readFile(archivePath), archive);
      await writeFile(
        join(f.directory, 'requirements.txt'),
        'synthetic==1.0\n',
      );
      const unsupported = await runOfflineOsv(f.directory, tools.osv, database);
      assert.equal(unsupported.reason, 'unsupported-dependency-manifests');
      assert.equal(unsupported.unsupportedManifestCount, 1);
      const malformed = makeSyntheticOsvZip([{ data: Buffer.from('{broken') }]);
      await writeFile(archivePath, malformed);
      const rejected = await runOfflineOsv(f.directory, tools.osv, {
        ...database,
        sha256: createHash('sha256').update(malformed).digest('hex'),
      });
      assert.equal(rejected.state, 'failed');
      assert.equal(rejected.evidence, 'none');
      await writeFile(archivePath, archive);
      assert.equal(
        (
          await runOfflineOsv(f.directory, tools.osv, {
            ...database,
            asOf: '2026-02-30T00:00:00Z',
          })
        ).state,
        'failed',
      );
      assert.equal(
        (await runOfflineOsv(f.directory, tools.osv)).state,
        'missing',
      );
    } finally {
      await f.dispose();
      await rm(data, { recursive: true, force: true });
    }
  },
);

await test('usable stdin-only scan CLI reports source failures without paths or payloads', () => {
  const cli = join(root, 'dist/src/scan-cli.js');
  const call = (input: string, args: string[] = []) =>
    spawnSync(process.execPath, [cli, ...args], {
      input,
      encoding: 'utf8',
      timeout: 30000,
      env: { LANG: 'C' },
    });
  const help = call('', ['--help']);
  assert.equal(help.status, 0);
  assert.ok(help.stdout.includes('committed snapshot'));
  const report = call(
    JSON.stringify({
      gitExecutable: '/SECRET_EXEC',
      gitDirectory: '/SECRET_STORE',
      commitSha: 'a'.repeat(40),
    }),
  );
  assert.equal(report.status, 1);
  assert.ok(!report.stdout.includes('SECRET'));
  assert.equal(report.stderr, '');
  const parsed = JSON.parse(report.stdout) as { scanners: unknown[] };
  assert.equal(parsed.scanners.length, 7);
  for (const input of ['{broken', 'x'.repeat(262145)]) {
    const result = call(input);
    assert.equal(result.status, 2);
    assert.equal(result.stderr, '');
  }
});
