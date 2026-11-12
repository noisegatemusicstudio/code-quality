// Test classification: integration
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: committed-snapshot scanning against synthetic local Git fixtures with real Git, ESLint and TypeScript; not a hosted-service path.
import { requireSupportedGit } from './git-requirement.js';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import {
  mkdtemp,
  writeFile,
  readFile,
  rm,
  symlink,
  access,
  readdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCommittedSnapshot } from '../src/committed-snapshot.js';
import { scanCommittedSource } from '../src/customer-scan.js';
import { runScannerProcess } from '../src/scanner-process.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'scanner-fixture-'));
  const git = (...args: string[]) =>
    execFileSync(requireSupportedGit(), args, {
      cwd: root,
      encoding: 'utf8',
      env: {
        PATH: '/usr/bin',
        HOME: root,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
    }).trim();
  git('init', '-q');
  await writeFile(join(root, 'source.ts'), 'const value: number = 1;\n');
  await writeFile(
    join(root, 'eslint.config.mjs'),
    'throw new Error("CONFIG_MUST_NOT_RUN");',
  );
  await writeFile(
    join(root, 'tsconfig.json'),
    '{"extends":"/SECRET-OUTSIDE-CONFIG","compilerOptions":{"plugins":[{"name":"trap"}]}}',
  );
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
  const options = {
    gitExecutable: requireSupportedGit(),
    gitDirectory: join(root, '.git'),
    commitSha: git('rev-parse', 'HEAD'),
  };
  return {
    root,
    git,
    options,
    dispose: () => rm(root, { recursive: true, force: true }),
  };
}

await test('real bounded processes scrub credentials and reject failure, timeout and oversized output', async () => {
  const base = {
    executable: process.execPath,
    cwd: tmpdir(),
    timeoutMs: 2000,
    outputLimit: 1024,
  };
  process.env.SCANNER_TEST_CREDENTIAL = 'SECRET_TRAP';
  try {
    const result = await runScannerProcess({
      ...base,
      args: [
        '-e',
        'console.log(process.env.SCANNER_TEST_CREDENTIAL ?? "absent")',
      ],
    });
    assert.equal(result.state, 'exited');
    if (result.state === 'exited')
      assert.equal(result.stdout.toString(), 'absent\n');
  } finally {
    delete process.env.SCANNER_TEST_CREDENTIAL;
  }
  assert.equal(
    (
      await runScannerProcess({
        ...base,
        executable: '/missing-scanner',
        args: [],
      })
    ).state,
    'failed',
  );
  assert.equal(
    (await runScannerProcess({ ...base, executable: 'node', args: [] })).state,
    'failed',
  );
  assert.equal(
    (
      await runScannerProcess({
        ...base,
        timeoutMs: 30,
        args: ['-e', 'setInterval(()=>{},1000)'],
      })
    ).state,
    'timed-out',
  );
  assert.equal(
    (
      await runScannerProcess({
        ...base,
        args: ['-e', 'process.stderr.write("SECRET".repeat(1000))'],
      })
    ).state,
    'output-limit',
  );
  const nonzero = await runScannerProcess({
    ...base,
    args: ['-e', 'process.exit(9)'],
  });
  assert.equal(nonzero.state === 'exited' && nonzero.code, 9);
});

await test('source failures return sanitized all-slot reports; early supervisor death stops the pipeline and retains data', async () => {
  const invalid = await scanCommittedSource({
    gitExecutable: '/SECRET_MISSING_GIT',
    gitDirectory: '/SECRET_MISSING_STORE',
    commitSha: 'a'.repeat(40),
  });
  assert.equal(invalid.status, 'incomplete');
  assert.equal(invalid.sourceError, 'source-unavailable');
  assert.equal(invalid.scanners.length, 7);
  assert.ok(invalid.scanners.every((slot) => slot.evidence === 'none'));
  assert.ok(!JSON.stringify(invalid).includes('SECRET'));
  const f = await fixture();
  const oldTmp = process.env.TMPDIR;
  try {
    const marker = join(f.root, 'called');
    const executable = join(f.root, 'anchor-death');
    await writeFile(
      executable,
      `#!/bin/sh\nprintf x >> ${JSON.stringify(marker)}\nkill -KILL "$PPID"\nexit 0\n`,
      { mode: 0o700 },
    );
    process.env.TMPDIR = f.root;
    const report = await scanCommittedSource({
      ...f.options,
      gitExecutable: executable,
    });
    assert.equal(report.sourceError, 'cleanup-uncertain');
    assert.equal(report.cleanup, 'uncertain-retained');
    assert.equal(await readFile(marker, 'utf8'), 'x');
    assert.ok(report.scanners.every((slot) => slot.evidence === 'none'));
    assert.ok(
      (await readdir(f.root)).some((name) =>
        name.startsWith('code-quality-snapshot-'),
      ),
    );
    assert.ok(!JSON.stringify(report).includes(f.root));
  } finally {
    if (oldTmp === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = oldTmp;
    await f.dispose();
  }
});

await test('snapshot reads immutable blobs, ignores checkout changes and cleans up', async () => {
  const f = await fixture();
  try {
    await writeFile(join(f.root, 'source.ts'), 'DIRTY_SECRET');
    await writeFile(join(f.root, 'untracked.ts'), 'UNTRACKED_SECRET');
    const snapshot = await createCommittedSnapshot(f.options);
    assert.equal(
      await readFile(join(snapshot.directory, 'source.ts'), 'utf8'),
      'const value: number = 1;\n',
    );
    await assert.rejects(access(join(snapshot.directory, 'untracked.ts')));
    assert.equal(snapshot.fileCount, 3);
    assert.match(snapshot.manifestSha256, /^[a-f0-9]{64}$/);
    await snapshot.dispose();
    await assert.rejects(access(snapshot.directory));
    await assert.rejects(
      createCommittedSnapshot({ ...f.options, commitSha: 'a'.repeat(40) }),
      /Committed snapshot unavailable/,
    );
  } finally {
    await f.dispose();
  }
});

await test('snapshot rejects commit and blob bytes that do not match Git object IDs', async () => {
  const f = await fixture();
  try {
    for (const type of ['commit', 'blob']) {
      const executable = join(f.root, `alter-${type}`);
      await writeFile(
        executable,
        `#!/bin/sh\nif [ "$4:$5" = 'cat-file:${type}' ]; then\n  printf 'altered object bytes'\nelse\n  exec /usr/bin/git "$@"\nfi\n`,
        { mode: 0o700 },
      );
      await assert.rejects(
        createCommittedSnapshot({ ...f.options, gitExecutable: executable }),
        /Committed snapshot unavailable/,
      );
    }
  } finally {
    await f.dispose();
  }
});

await test('symlink tree entries and external object alternates fail closed', async () => {
  const f = await fixture();
  try {
    await symlink('/outside-secret', join(f.root, 'link'));
    f.git('add', 'link');
    f.git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'link',
      '--no-verify',
    );
    await assert.rejects(
      createCommittedSnapshot({
        ...f.options,
        commitSha: f.git('rev-parse', 'HEAD'),
      }),
    );
    await writeFile(
      join(f.root, '.git/objects/info/alternates'),
      '/outside-object-store\n',
    );
    await assert.rejects(createCommittedSnapshot(f.options));
  } finally {
    await f.dispose();
  }
});

await test('real ESLint and TypeScript executions never load project configs or certify full coverage', async () => {
  const f = await fixture();
  try {
    const report = await scanCommittedSource(f.options);
    assert.equal(report.status, 'incomplete');
    assert.equal(report.projectTypeCheck, 'fixed-profile-only');
    assert.equal(report.source?.checkoutIncluded, false);
    assert.equal(report.scanners.length, 7);
    assert.equal(report.scanners[0].state, 'completed');
    assert.equal(report.scanners[1].state, 'completed');
    assert.equal(report.scanners[1].coverage, 'fixed-semantic-profile');
    assert.equal(report.scanners[0].evidence, 'executed');
    assert.ok(
      report.scanners.slice(2).every((slot) => slot.state === 'missing'),
    );
    assert.ok(!JSON.stringify(report).includes(f.root));
    assert.ok(!JSON.stringify(report).includes('SECRET'));
  } finally {
    await f.dispose();
  }
});

await test('isolated Git ignores original config includes and replacement refs', async () => {
  const f = await fixture();
  try {
    await writeFile(join(f.root, 'source.ts'), 'REPLACEMENT_SECRET');
    f.git('add', 'source.ts');
    f.git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'replacement',
      '--no-verify',
    );
    f.git('replace', f.options.commitSha, f.git('rev-parse', 'HEAD'));
    await writeFile(
      join(f.root, 'broken-config'),
      'THIS IS INVALID GIT CONFIG',
    );
    await writeFile(
      join(f.root, '.git/config'),
      `[include]\npath = ${join(f.root, 'broken-config')}\n`,
    );
    const snapshot = await createCommittedSnapshot(f.options);
    try {
      assert.equal(
        await readFile(join(snapshot.directory, 'source.ts'), 'utf8'),
        'const value: number = 1;\n',
      );
    } finally {
      await snapshot.dispose();
    }
  } finally {
    await f.dispose();
  }
});

await test('symlinked object data is rejected before Git can read it', async () => {
  const f = await fixture();
  try {
    const oid = f.git('hash-object', 'source.ts');
    const object = join(f.root, '.git/objects', oid.slice(0, 2), oid.slice(2));
    await rm(object);
    await symlink(join(f.root, 'source.ts'), object);
    await assert.rejects(
      createCommittedSnapshot(f.options),
      /Committed snapshot unavailable/,
    );
  } finally {
    await f.dispose();
  }
});

await test('semantic type errors are found; unresolved imports cannot claim completed coverage', async () => {
  const f = await fixture();
  try {
    await writeFile(
      join(f.root, 'source.ts'),
      'export const value: number = "wrong";\n',
    );
    f.git('add', 'source.ts');
    f.git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'type error',
      '--no-verify',
    );
    let report = await scanCommittedSource({
      ...f.options,
      commitSha: f.git('rev-parse', 'HEAD'),
    });
    assert.equal(report.scanners[1].state, 'completed');
    assert.ok((report.scanners[1].findingCount ?? 0) > 0);
    await writeFile(
      join(f.root, 'source.ts'),
      'import {value} from "missing-package"; export {value};\n',
    );
    f.git('add', 'source.ts');
    f.git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'missing dependency',
      '--no-verify',
    );
    report = await scanCommittedSource({
      ...f.options,
      commitSha: f.git('rev-parse', 'HEAD'),
    });
    assert.equal(report.scanners[1].state, 'limited');
    assert.ok((report.scanners[1].unresolvedDependencyCount ?? 0) > 0);
  } finally {
    await f.dispose();
  }
});

await test('owned live supervisor cleans descendants even when tool exits first', async () => {
  const result = await runScannerProcess({
    executable: process.execPath,
    cwd: tmpdir(),
    timeoutMs: 2000,
    outputLimit: 1024,
    args: [
      '-e',
      `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'}); console.log(child.pid); child.unref();`,
    ],
  });
  assert.equal(result.state, 'exited');
  if (result.state === 'exited') {
    const pid = Number(result.stdout.toString().trim());
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    try {
      const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
      assert.equal(stat.split(') ')[1]?.charAt(0), 'Z');
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !('code' in error) ||
        error.code !== 'ENOENT'
      )
        throw error;
    }
  }
});

await test('early supervisor exit with inherited pipe settles uncertain without signaling a reaped anchor', async () => {
  const started = Date.now();
  const result = await runScannerProcess({
    executable: process.execPath,
    cwd: tmpdir(),
    timeoutMs: 100,
    outputLimit: 1024,
    args: [
      '-e',
      `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e','setTimeout(()=>{},3000)'],{stdio:'inherit'}); child.unref(); process.kill(process.ppid,'SIGKILL'); process.exit(0);`,
    ],
  });
  assert.equal(result.state, 'cleanup-uncertain');
  assert.ok(Date.now() - started < 4500);
  // The deliberately escaped test descendant naturally expires; no global/PID kill.
  await new Promise((resolve) => setTimeout(resolve, 1200));
});

await test('TypeScript source suppressions stay limited while ESLint inline disabling is ignored', async () => {
  const f = await fixture();
  try {
    await writeFile(
      join(f.root, 'source.ts'),
      '// @ts-nocheck\n/* eslint-disable */\nconst unused: number = "wrong";\n',
    );
    f.git('add', 'source.ts');
    f.git(
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      'commit',
      '-qm',
      'suppression',
      '--no-verify',
    );
    const report = await scanCommittedSource({
      ...f.options,
      commitSha: f.git('rev-parse', 'HEAD'),
    });
    assert.ok((report.scanners[0].findingCount ?? 0) > 0);
    assert.equal(report.scanners[1].state, 'limited');
    assert.equal(report.scanners[1].reason, 'source-suppression-directive');
    assert.equal(report.scanners[1].sourceSuppressionCount, 1);
  } finally {
    await f.dispose();
  }
});
