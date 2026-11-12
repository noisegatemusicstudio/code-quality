// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: npm pack of an allowlisted copy of the package consumed offline from a temp node_modules; not a registry install.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  mkdtemp,
  mkdir,
  cp,
  copyFile,
  readFile,
  rm,
  rename,
  writeFile,
} from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { OSV_SCHEMA_METADATA } from '../src/osv-database.js';

await test('packed consumer receives exact schema/notices and public scan API without README access', async () => {
  const root = resolve(import.meta.dirname, '../..');
  await mkdir(join(root, '.fixtures'), { recursive: true });
  const directory = await mkdtemp(join(root, '.fixtures/scanner-package-'));
  try {
    // Explicit allowlist: never copy/read repository README or unrelated files.
    // npm 10 runs `prepare` during `npm pack` even with --ignore-scripts. In this
    // fixture that would run tsc, which walks up to the repository tsconfig.json and
    // rewrites the real dist/ (briefly corrupting the pinned schema JSON). The packed
    // manifest therefore carries no lifecycle scripts; everything else is unchanged.
    const manifest = JSON.parse(
      await readFile(join(root, 'package.json'), 'utf8'),
    ) as { scripts?: unknown };
    delete manifest.scripts;
    await writeFile(
      join(directory, 'package.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    await mkdir(join(directory, 'dist'), { recursive: true });
    await cp(join(root, 'dist/src'), join(directory, 'dist/src'), {
      recursive: true,
    });
    await mkdir(join(directory, 'src'));
    for (const name of ['osv-schema-LICENSE.txt', 'osv-schema-NOTICE.txt'])
      await copyFile(join(root, 'src', name), join(directory, 'src', name));
    const digest = createHash('sha256')
      .update(
        await readFile(join(directory, 'dist/src/osv-schema-v1.9.2.json')),
      )
      .digest('hex');
    assert.equal(digest, OSV_SCHEMA_METADATA.sha256);
    await writeFile(join(directory, 'user.npmrc'), '');
    await writeFile(join(directory, 'global.npmrc'), '');
    const environment = {
      PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
      HOME: directory,
      LANG: 'C',
      npm_config_userconfig: join(directory, 'user.npmrc'),
      npm_config_globalconfig: join(directory, 'global.npmrc'),
      npm_config_cache: join(directory, 'npm-cache'),
      npm_config_offline: 'true',
    };
    const packed = spawnSync(
      join(dirname(process.execPath), 'npm'),
      ['pack', '--ignore-scripts', '--json'],
      {
        cwd: directory,
        env: environment,
        encoding: 'utf8',
        timeout: 30000,
        maxBuffer: 1048576,
      },
    );
    assert.equal(packed.status, 0, packed.stderr);
    const listing = JSON.parse(packed.stdout) as {
      filename: string;
      files: { path: string }[];
    }[];
    const paths = listing[0].files.map((item) => item.path);
    for (const path of [
      'dist/src/osv-schema-v1.9.2.json',
      'src/osv-schema-LICENSE.txt',
      'src/osv-schema-NOTICE.txt',
      'dist/src/scan-cli.js',
      'dist/src/customer-scan.js',
    ])
      assert.ok(paths.includes(path), path);
    assert.ok(!paths.some((path) => /readme/i.test(path)));
    const archive = join(directory, listing[0].filename);
    const unpacked = join(directory, 'unpacked');
    await mkdir(unpacked);
    const extracted = spawnSync(
      '/usr/bin/tar',
      [
        '--extract',
        '--gzip',
        '--file',
        archive,
        '--directory',
        unpacked,
        '--no-same-owner',
        '--no-same-permissions',
      ],
      { env: environment, encoding: 'utf8', timeout: 30000 },
    );
    assert.equal(extracted.status, 0, extracted.stderr);
    const consumerRoot = join(directory, 'consumer');
    const consumerPackage = join(
      consumerRoot,
      'node_modules/@releaseready/code-quality',
    );
    await mkdir(dirname(consumerPackage), { recursive: true });
    await rename(join(unpacked, 'package'), consumerPackage);
    for (const path of [
      'dist/src/osv-schema-v1.9.2.json',
      'src/osv-schema-LICENSE.txt',
      'src/osv-schema-NOTICE.txt',
      'dist/src/scan-cli.js',
      'dist/src/customer-scan.js',
    ]) {
      const payload = spawnSync(
        '/usr/bin/tar',
        ['-xOzf', archive, `package/${path}`],
        { env: environment, timeout: 30000, maxBuffer: 1048576 },
      );
      assert.equal(payload.status, 0);
      const hash = (bytes: Buffer) =>
        createHash('sha256').update(bytes).digest('hex');
      assert.equal(
        hash(await readFile(join(consumerPackage, path))),
        hash(payload.stdout),
      );
      assert.equal(
        hash(payload.stdout),
        hash(await readFile(join(directory, path))),
      );
    }
    const consumer = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import {scanCommittedSource} from '@releaseready/code-quality/customer-scan'; const report=await scanCommittedSource({gitExecutable:'/missing',gitDirectory:'/missing',commitSha:'a'.repeat(40)}); if(report.schemaVersion!==2 || report.scanners.length!==7) process.exit(1);`,
      ],
      { cwd: consumerRoot, env: environment, encoding: 'utf8', timeout: 30000 },
    );
    assert.equal(consumer.status, 0, consumer.stderr);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
