import assert from 'node:assert/strict';
import sharedPrettier from '../src/prettier.js';
import { test } from 'node:test';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  copyFileSync,
  rmSync,
  unlinkSync,
  chmodSync,
  existsSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '../..');
const fixtureRoot = join(root, '.fixtures');
mkdirSync(fixtureRoot, { recursive: true });
const good = "export const greeting = 'hello';\n";
const bad = 'export const greeting="hello"\n';

// Preserve registry transport settings without inheriting user npm configuration.
const registryEnvironment = Object.fromEntries(
  [
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'no_proxy',
    'NPM_CONFIG_PROXY',
    'NPM_CONFIG_HTTPS_PROXY',
    'NPM_CONFIG_NOPROXY',
    'npm_config_proxy',
    'npm_config_https_proxy',
    'npm_config_noproxy',
    'NODE_EXTRA_CA_CERTS',
    'SSL_CERT_FILE',
  ].flatMap((key) => {
    const value = process.env[key];
    return value === undefined ? [] : [[key, value]];
  }),
);

function command(cwd: string, executable: string, args: string[]) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: 'utf8',
    timeout: executable === 'npm' ? 120_000 : 30_000,
    env: {
      ...(executable === 'npm' ? registryEnvironment : {}),
      PATH: `${dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin`,
      HOME: cwd,
      XDG_CONFIG_HOME: join(cwd, '.config'),
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_AUTHOR_NAME: 'Synthetic Quality Test',
      GIT_AUTHOR_EMAIL: 'quality@example.invalid',
      GIT_COMMITTER_NAME: 'Synthetic Quality Test',
      GIT_COMMITTER_EMAIL: 'quality@example.invalid',
      npm_config_offline: 'true',
      npm_config_cache: join(cwd, '.git/npm-cache'),
    },
  });
  assert.ifError(result.error);
  return { status: result.status, output: result.stdout + result.stderr };
}
function must(cwd: string, executable: string, args: string[]) {
  const result = command(cwd, executable, args);
  assert.equal(result.status, 0, result.output);
  return result.output;
}
function fixture(run: (dir: string) => void) {
  const dir = mkdtempSync(join(fixtureRoot, 'commit-'));
  try {
    must(dir, 'git', ['init', '--quiet']);
    symlinkSync(join(root, 'node_modules'), join(dir, 'node_modules'), 'dir');
    mkdirSync(join(dir, '.husky'));
    mkdirSync(join(dir, 'src'));
    copyFileSync(join(root, 'quality.ignore'), join(dir, 'quality.ignore'));

    copyFileSync(
      join(root, 'hooks/pre-commit'),
      join(dir, '.husky/pre-commit'),
    );
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.config/\n');
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify(
        {
          private: true,
          type: 'module',
          scripts: {
            'check:staged': `node "${join(root, 'dist/src/check-paths.js')}" && node node_modules/lint-staged/bin/lint-staged.js --hide-unstaged --config "${join(root, 'dist/src/lint-staged.js')}"`,
          },
          prettier: join(root, 'dist/src/prettier.js'),
        },
        null,
        2,
      ) + '\n',
    );
    writeFileSync(
      join(dir, 'tsconfig.json'),
      JSON.stringify(
        {
          compilerOptions: {
            strict: true,
            target: 'ES2022',
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
          },
          include: ['src/**/*.ts'],
        },
        null,
        2,
      ) + '\n',
    );
    writeFileSync(
      join(dir, 'eslint.config.ts'),
      `import { qualityConfig } from '${join(root, 'dist/src/eslint.js')}';\nexport default qualityConfig(import.meta.dirname);\n`,
    );
    writeFileSync(join(dir, 'src/value.ts'), good);
    must(dir, 'node', [
      join(root, 'node_modules/prettier/bin/prettier.cjs'),
      '--write',
      'package.json',
      'tsconfig.json',
      'eslint.config.ts',
    ]);
    must(dir, 'node', [join(root, 'node_modules/husky/bin.js')]);
    must(dir, 'git', ['add', '.']);
    must(dir, 'git', [
      'commit',
      '-m',
      'Given a formatted synthetic repository',
    ]);
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
function stage(dir: string, content: string) {
  writeFileSync(join(dir, 'src/value.ts'), content);
  must(dir, 'git', ['add', 'src/value.ts']);
}
function rejectCommit(dir: string, reason: string) {
  const before = must(dir, 'git', ['rev-parse', 'HEAD']);
  const result = command(dir, 'git', [
    'commit',
    '-m',
    'When an invalid change is committed',
  ]);
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, new RegExp(reason));
  assert.equal(must(dir, 'git', ['rev-parse', 'HEAD']), before);
}

await test('Given unformatted staged code, when committed, then formatting rejects it without rewriting it', () => {
  fixture((dir) => {
    stage(dir, bad);
    rejectCommit(dir, 'prettier');
    assert.equal(readFileSync(join(dir, 'src/value.ts'), 'utf8'), bad);
    assert.equal(must(dir, 'git', ['show', ':src/value.ts']), bad);
  });
});
await test('Given formatted staged code and dirty unstaged code, when committed, then only staged code passes and the working change returns', () => {
  fixture((dir) => {
    const staged = "export const greeting = 'updated';\n";
    stage(dir, staged);
    writeFileSync(join(dir, 'src/value.ts'), bad);
    must(dir, 'git', [
      'commit',
      '-m',
      'When only formatted staged content is committed',
    ]);
    assert.equal(must(dir, 'git', ['show', 'HEAD:src/value.ts']), staged);
    assert.equal(readFileSync(join(dir, 'src/value.ts'), 'utf8'), bad);
    assert.equal(must(dir, 'git', ['stash', 'list']), '');
  });
});
await test('Given bad staged code and clean working code, when committed, then the index fails and both versions are preserved', () => {
  fixture((dir) => {
    stage(dir, bad);
    writeFileSync(join(dir, 'src/value.ts'), good);
    rejectCommit(dir, 'prettier');
    assert.equal(must(dir, 'git', ['show', ':src/value.ts']), bad);
    assert.equal(readFileSync(join(dir, 'src/value.ts'), 'utf8'), good);
    assert.equal(must(dir, 'git', ['stash', 'list']), '');
  });
});
await test('Given a formatted floating promise, when committed, then the type-aware rule rejects it', () => {
  fixture((dir) => {
    stage(dir, "Promise.resolve('synthetic');\n");
    rejectCommit(dir, 'no-floating-promises');
  });
});
await test('Given renamed Unicode and spaced paths and a deletion, when committed, then exact paths are checked', () => {
  fixture((dir) => {
    must(dir, 'git', ['mv', 'src/value.ts', 'src/hello 世界.ts']);
    writeFileSync(join(dir, 'src/another name.ts'), good);
    must(dir, 'git', ['add', 'src/another name.ts']);
    must(dir, 'git', ['commit', '-m', 'When paths are renamed and added']);
    assert.equal(must(dir, 'git', ['show', 'HEAD:src/hello 世界.ts']), good);
    must(dir, 'git', ['rm', 'src/another name.ts']);
    must(dir, 'git', ['commit', '-m', 'When a source is deleted']);
    assert.equal(must(dir, 'git', ['status', '--porcelain']), '');
  });
});
await test('Given no selected source changes, when an empty commit is requested, then the hook succeeds', () => {
  fixture((dir) => {
    must(dir, 'git', [
      'commit',
      '--allow-empty',
      '-m',
      'When no files require checking',
    ]);
    assert.equal(must(dir, 'git', ['status', '--porcelain']), '');
  });
});
await test('Given missing local dependencies, when committed, then the hook fails without downloading a tool', () => {
  fixture((dir) => {
    stage(dir, good.replace('hello', 'changed'));
    unlinkSync(join(dir, 'node_modules'));
    rejectCommit(dir, 'MODULE_NOT_FOUND');
    assert.equal(
      must(dir, 'git', ['show', ':src/value.ts']),
      good.replace('hello', 'changed'),
    );
  });
});

await test('Given an unstaged imported helper hides a floating promise, when committed, then the staged program fails and both helper versions return', () => {
  fixture((dir) => {
    const promised =
      'export function work(): Promise<void> {\n  return Promise.resolve();\n}\n';
    const synchronous = 'export function work(): void {}\n';
    writeFileSync(join(dir, 'src/helper.ts'), promised);
    must(dir, 'git', ['add', 'src/helper.ts']);
    must(dir, 'git', [
      'commit',
      '-m',
      'Given a reviewed promise-returning helper',
    ]);
    stage(dir, "import { work } from './helper.js';\nwork();\n");
    writeFileSync(join(dir, 'src/helper.ts'), synchronous);
    rejectCommit(dir, 'no-floating-promises');
    assert.equal(must(dir, 'git', ['show', ':src/helper.ts']), promised);
    assert.equal(readFileSync(join(dir, 'src/helper.ts'), 'utf8'), synchronous);
    assert.equal(must(dir, 'git', ['stash', 'list']), '');
  });
});
await test('Given generated output and authored code, when committed, then generated paths are excluded but authored violations still fail', () => {
  fixture((dir) => {
    mkdirSync(join(dir, 'dist'));
    writeFileSync(join(dir, 'dist/generated.ts'), bad);
    must(dir, 'git', ['add', 'dist/generated.ts']);
    must(dir, 'git', ['commit', '-m', 'When generated output is committed']);
    assert.equal(must(dir, 'git', ['show', 'HEAD:dist/generated.ts']), bad);
    must(dir, 'node', [
      join(root, 'node_modules/prettier/bin/prettier.cjs'),
      '--check',
      '--ignore-path',
      'quality.ignore',
      '.',
    ]);
    stage(dir, bad);
    rejectCommit(dir, 'prettier');
  });
});

await test('Given quoted filenames, when committed, then their exact contents are checked', () => {
  fixture((dir) => {
    const names = [
      'src/double"quote.ts',
      "src/single'quote.ts",
      'src/both\'"quotes.ts',
    ];
    for (const name of names) writeFileSync(join(dir, name), good);
    must(dir, 'git', ['add', '--', ...names]);
    must(dir, 'git', ['commit', '-m', 'When unusual filenames are formatted']);
    writeFileSync(join(dir, names[0]), bad);
    must(dir, 'git', ['add', '--', names[0]]);
    rejectCommit(dir, 'prettier');
    assert.equal(must(dir, 'git', ['show', `:${names[0]}`]), bad);
  });
});
await test('Given CRLF, comments and blank ignore lines, when checked, then generated files stay excluded and authored code stays checked', () => {
  fixture((dir) => {
    const policy =
      '# Generated outputs\r\n\r\n' +
      readFileSync(join(dir, 'quality.ignore'), 'utf8').replaceAll(
        '\n',
        '\r\n',
      );
    writeFileSync(join(dir, 'quality.ignore'), policy);
    mkdirSync(join(dir, 'dist'));
    writeFileSync(join(dir, 'dist/generated.ts'), bad);
    must(dir, 'git', ['add', 'quality.ignore', 'dist/generated.ts']);
    must(dir, 'git', [
      'commit',
      '-m',
      'When an ignore file uses Windows lines',
    ]);
    must(dir, 'node', [
      join(root, 'node_modules/eslint/bin/eslint.js'),
      '.',
      '--max-warnings',
      '0',
    ]);
    must(dir, 'node', [
      join(root, 'node_modules/prettier/bin/prettier.cjs'),
      '--check',
      '--ignore-path',
      'quality.ignore',
      '.',
    ]);
    stage(dir, bad);
    rejectCommit(dir, 'prettier');
  });
});

await test('Given a literal backslash filename, when committed, then it is rejected without changing the index or working copy', () => {
  fixture((dir) => {
    const name = 'src/back\\slash.ts';
    writeFileSync(join(dir, name), good);
    must(dir, 'git', ['add', '--', name]);
    rejectCommit(dir, 'Literal backslashes');
    assert.equal(must(dir, 'git', ['show', `:${name}`]), good);
    assert.equal(readFileSync(join(dir, name), 'utf8'), good);
    assert.equal(must(dir, 'git', ['stash', 'list']), '');
  });
});
await test('Given a fresh clone, when developer setup runs, then build-only installation becomes a working commit hook', () => {
  const dir = mkdtempSync(join(fixtureRoot, 'clone-'));
  try {
    must(root, 'git', ['clone', '--quiet', '--no-hardlinks', root, dir]);
    must(dir, 'npm', ['ci', '--offline=false', '--no-audit', '--no-fund']);
    assert.equal(
      command(dir, 'git', ['config', '--local', '--get', 'core.hooksPath'])
        .status,
      1,
    );
    must(dir, 'npm', ['run', 'setup:dev']);
    assert.equal(
      must(dir, 'git', ['config', '--local', '--get', 'core.hooksPath']).trim(),
      '.husky/_',
    );
    stage(dir, bad);
    rejectCommit(dir, 'prettier');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
await test('Given an immutable Git dependency, when installed, then exports build without installing consumer hooks', () => {
  const dir = mkdtempSync(join(fixtureRoot, 'dependency-'));
  try {
    must(dir, 'git', ['init', '--quiet']);
    writeFileSync(join(dir, 'package.json'), '{"private":true}\n');
    const revision = must(root, 'git', ['rev-parse', 'HEAD']).trim();
    must(dir, 'npm', [
      'install',
      '--offline=false',
      '--no-audit',
      '--no-fund',
      `git+file://${root}#${revision}`,
    ]);
    assert.equal(
      command(dir, 'git', ['config', '--local', '--get', 'core.hooksPath'])
        .status,
      1,
    );
    assert.ok(
      readFileSync(join(dir, 'package-lock.json'), 'utf8').includes(revision),
    );
    assert.ok(
      readFileSync(
        join(dir, 'node_modules/@releaseready/code-quality/dist/src/eslint.js'),
        'utf8',
      ).includes('qualityConfig'),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await test('Given EditorConfig indentation, when CLI-formatted code is staged, then the hook agrees while explicit shared defaults remain', () => {
  fixture((dir) => {
    writeFileSync(
      join(dir, '.editorconfig'),
      'root = true\n[*.ts]\nindent_style = space\nindent_size = 4\n',
    );
    stage(dir, 'export const greeting = {\nmessage: "hello",\n};\n');
    must(dir, 'node', [
      join(root, 'node_modules/prettier/bin/prettier.cjs'),
      '--write',
      'src/value.ts',
    ]);
    const formatted = "export const greeting = {\n    message: 'hello',\n};\n";
    assert.equal(readFileSync(join(dir, 'src/value.ts'), 'utf8'), formatted);
    must(dir, 'git', ['add', '.editorconfig', 'src/value.ts']);
    must(dir, 'git', ['commit', '-m', 'When CLI and staged formatting agree']);
    stage(dir, formatted.replace('    message', '  message'));
    rejectCommit(dir, 'prettier');
    const pkg = JSON.parse(
      readFileSync(join(dir, 'package.json'), 'utf8'),
    ) as Record<string, unknown>;
    pkg.prettier = { ...sharedPrettier, tabWidth: 2 };
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify(pkg, null, 2) + '\n',
    );
    must(dir, 'node', [
      join(root, 'node_modules/prettier/bin/prettier.cjs'),
      '--write',
      'src/value.ts',
      'package.json',
    ]);
    assert.equal(
      readFileSync(join(dir, 'src/value.ts'), 'utf8'),
      formatted.replace('    message', '  message'),
    );
    must(dir, 'git', ['add', 'package.json', 'src/value.ts']);
    must(dir, 'git', [
      'commit',
      '-m',
      'When explicit Prettier options override EditorConfig',
    ]);
  });
});

await test('Given a poisoned PATH, the filename guard uses system Git and preserves staged and unstaged content', () => {
  fixture((dir) => {
    const fakeBin = join(dir, 'fake-bin');
    mkdirSync(fakeBin);
    const marker = join(dir, 'untrusted-git-ran');
    const fakeGit = join(fakeBin, 'git');
    writeFileSync(fakeGit, `#!/bin/sh\nprintf ran > "${marker}"\nexit 0\n`);
    chmodSync(fakeGit, 0o755);
    const name = 'src/back\\slash.ts';
    writeFileSync(join(dir, name), good);
    must(dir, 'git', ['add', '--', name]);
    writeFileSync(join(dir, name), bad);
    const before = must(dir, 'git', ['diff', '--cached', '--binary']);
    for (const path of [fakeBin, '', `.:${fakeBin}:/usr/bin`]) {
      const result = spawnSync(
        process.execPath,
        [join(root, 'dist/src/check-paths.js')],
        {
          cwd: dir,
          encoding: 'utf8',
          env: { ...process.env, PATH: path },
        },
      );
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.match(result.stderr, /Literal backslashes/);
      assert.equal(existsSync(marker), false);
    }
    assert.equal(must(dir, 'git', ['diff', '--cached', '--binary']), before);
    assert.equal(readFileSync(join(dir, name), 'utf8'), bad);
    assert.equal(must(dir, 'git', ['stash', 'list']), '');
  });
});

await test('Given valid staged names and untrusted PATH values, the filename guard succeeds without changing the index', () => {
  fixture((dir) => {
    const names = ['src/hello 世界.ts', 'src/double"quote.ts'];
    for (const name of names) writeFileSync(join(dir, name), good);
    must(dir, 'git', ['add', '--', ...names]);
    const before = must(dir, 'git', ['diff', '--cached', '--binary']);
    for (const path of ['', '.', '/nonexistent']) {
      const result = spawnSync(
        process.execPath,
        [join(root, 'dist/src/check-paths.js')],
        {
          cwd: dir,
          encoding: 'utf8',
          env: { ...process.env, PATH: path },
        },
      );
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stdout + result.stderr);
    }
    assert.equal(must(dir, 'git', ['diff', '--cached', '--binary']), before);
  });
});

await test('Given no Git repository, the filename guard fails closed with an empty PATH', () => {
  const dir = mkdtempSync('/tmp/quality-no-git-');
  try {
    const result = spawnSync(
      process.execPath,
      [join(root, 'dist/src/check-paths.js')],
      {
        cwd: dir,
        encoding: 'utf8',
        env: {
          PATH: '',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
        },
      },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /Unable to read staged filenames/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await test('Given an explicit custom Git installation, the guard uses it without searching PATH', () => {
  const dir = mkdtempSync(join(fixtureRoot, 'custom-git-'));
  try {
    const executable = join(dir, 'custom git');
    symlinkSync('/usr/bin/git', executable);
    const result = spawnSync(
      process.execPath,
      [join(root, 'dist/src/check-paths.js')],
      {
        cwd: root,
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: '',
          CODE_QUALITY_GIT_EXECUTABLE: executable,
        },
      },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await test('Given invalid or missing configured Git, the guard fails without a PATH fallback', () => {
  for (const executable of ['', 'git', '/nonexistent/quality/git']) {
    const result = spawnSync(
      process.execPath,
      [join(root, 'dist/src/check-paths.js')],
      {
        cwd: root,
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: '/usr/bin:/bin',
          CODE_QUALITY_GIT_EXECUTABLE: executable,
        },
      },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /commit checks stopped/);
  }
});
