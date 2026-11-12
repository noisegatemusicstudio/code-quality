/*
Test classification: integration
Review status: Not Reviewed
Evidence: synthetic
Scope: Runs the real pinned ESLint with the type-aware opt-in on synthetic TypeScript fixtures (a type-only violation, partial type information, refused tsconfigs through runEngines on a temp git repository) and checks the default run is unchanged; does not run the reusable workflow or install dependencies.
*/
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { runEslintScan } from '../src/eslint-adapter.js';
import scanConfigDefault, { scanConfig } from '../src/eslint-scan-config.js';
import { runEngines, withTypeInfoNotes } from '../src/quality-scan-run.js';
import { scope } from './eslint-fixtures.js';

const linux = { skip: process.platform !== 'linux' };
const tsconfig = JSON.stringify({
  compilerOptions: {
    strict: true,
    target: 'es2022',
    module: 'esnext',
    moduleResolution: 'bundler',
  },
  include: ['src'],
});
/** `no-floating-promises` is a type-only rule: it cannot fire without type information. */
const floating = `async function save(): Promise<number> {
  return 1;
}
export function run(): void {
  save();
}
`;
const withImport = (names: string[]) =>
  names
    .map(
      (n) =>
        `import { x } from '${n}';\nexport const v_${n.replace(/\W/g, '_')} = x;\n`,
    )
    .join('');
const typedInput = (extra: Record<string, string> = {}) => ({
  tsconfig: 'tsconfig.json',
  files: { 'tsconfig.json': tsconfig, ...extra },
});
const rules = (r: Awaited<ReturnType<typeof runEslintScan>>) =>
  r.envelope.findings.map((f) => f.ruleId);

await test(
  'opt-in: a type-only violation (no-floating-promises) is reported',
  linux,
  async () => {
    const r = await runEslintScan(
      { scope, files: { 'src/a.ts': floating } },
      typedInput(),
    );
    assert.equal(r.envelope.status, 'completed');
    assert.ok(
      rules(r).includes('@typescript-eslint/no-floating-promises'),
      rules(r).join(),
    );
    assert.equal(r.envelope.configVersion, 'bundled-typed-1');
    assert.deepEqual(r.report.typeAware, {
      tsconfig: 'tsconfig.json',
      unresolvedModuleCount: 0,
      unresolvedModules: [],
    });
  },
);

await test(
  'no opt-in: the type-only violation is not reported and the run is unchanged',
  linux,
  async () => {
    const r = await runEslintScan({ scope, files: { 'src/a.ts': floating } });
    assert.equal(r.envelope.status, 'completed');
    assert.ok(!rules(r).includes('@typescript-eslint/no-floating-promises'));
    assert.equal(r.envelope.configVersion, 'bundled-1');
    assert.ok(!('typeAware' in r.report));
    // Unresolved imports are irrelevant without type information: still complete.
    const imports = await runEslintScan({
      scope,
      files: { 'src/a.ts': withImport(['left-pad']) },
    });
    assert.equal(imports.envelope.status, 'completed');
    assert.deepEqual(
      imports.envelope.findings.map((f) => f.ruleId),
      [],
    );
  },
);

await test('the default configuration is the untyped one', () => {
  const ruleNames = (c: ReturnType<typeof scanConfig>): string[] =>
    c.flatMap((entry) =>
      Object.keys((entry as { rules?: object }).rules ?? {}),
    );
  assert.deepEqual(ruleNames(scanConfigDefault), ruleNames(scanConfig(false)));
  assert.ok(
    !ruleNames(scanConfig(false)).includes(
      '@typescript-eslint/no-floating-promises',
    ),
  );
  assert.ok(
    ruleNames(scanConfig(true)).includes(
      '@typescript-eslint/no-floating-promises',
    ),
  );
});

await test(
  'unresolved modules make the run incomplete with type-info-partial and a bounded sample',
  linux,
  async () => {
    const r = await runEslintScan(
      { scope, files: { 'src/a.ts': floating + withImport(['left-pad']) } },
      typedInput(),
    );
    assert.equal(r.envelope.status, 'incomplete');
    assert.equal(r.envelope.reason, 'type-info-partial');
    assert.deepEqual(r.report.typeAware?.unresolvedModules, ['left-pad']);
    // Findings from the resolvable part still report; the probe is never a finding.
    assert.ok(rules(r).includes('@typescript-eslint/no-floating-promises'));
    assert.ok(!rules(r).some((id) => id.startsWith('releaseready/')));
    const names = Array.from(
      { length: 30 },
      (_, i) => `missing-${String(i).padStart(2, '0')}`,
    );
    const many = await runEslintScan(
      { scope, files: { 'src/b.ts': withImport(names) } },
      typedInput(),
    );
    assert.equal(many.envelope.reason, 'type-info-partial');
    assert.equal(many.report.typeAware?.unresolvedModuleCount, 30);
    assert.equal(many.report.typeAware.unresolvedModules.length, 20);
  },
);

await test(
  'resolvable relative imports and side-effect imports are not partial',
  linux,
  async () => {
    const files = {
      'src/b.ts': 'export const x = 1;\n',
      'src/a.ts':
        "import './style.css';\nimport { x } from './b.js';\nexport const y: number = x;\n",
    };
    const r = await runEslintScan({ scope, files }, typedInput());
    assert.equal(r.envelope.status, 'completed', r.envelope.reason);
  },
);

await test(
  'a file outside the tsconfig is reported as a parse failure, never clean',
  linux,
  async () => {
    const r = await runEslintScan(
      { scope, files: { 'other/a.ts': floating } },
      typedInput(),
    );
    assert.equal(r.envelope.status, 'incomplete');
    assert.equal(r.envelope.reason, 'parse-failure');
    assert.deepEqual(r.report.parseFailures, ['other/a.ts']);
  },
);

await test('withTypeInfoNotes names the modules, keeps prior reasons and ignores untyped runs', () => {
  const base = {
    engine: 'eslint' as const,
    status: 'incomplete' as const,
    reason: 'type-info-partial',
    findings: [],
  };
  const typed = {
    typeAware: {
      tsconfig: 'tsconfig.json',
      unresolvedModuleCount: 12,
      unresolvedModules: ['a', 'b'],
    },
  };
  assert.match(
    withTypeInfoNotes(base, typed).reason ?? '',
    /^type-info-partial: 12 module\(s\).*: a, b, and more$/,
  );
  const both = withTypeInfoNotes(
    { ...base, reason: 'parse-failure: 1 file(s)' },
    typed,
  );
  assert.match(
    both.reason ?? '',
    /^parse-failure: 1 file\(s\); type-info-partial: /,
  );
  assert.equal(withTypeInfoNotes(base, {}), base);
  assert.equal(
    withTypeInfoNotes(base, {
      typeAware: { ...typed.typeAware, unresolvedModuleCount: 0 },
    }),
    base,
  );
});

const gitRepo = async (
  files: Record<string, string>,
  untracked: Record<string, string> = {},
) => {
  const repo = await mkdtemp(join(tmpdir(), 'typed-repo-'));
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
  const put = async (set: Record<string, string>) => {
    for (const [name, content] of Object.entries(set)) {
      await mkdir(dirname(join(repo, name)), { recursive: true });
      await writeFile(join(repo, name), content);
    }
  };
  git('init', '-q');
  await put(files);
  git('add', '.');
  git(
    '-c',
    'user.email=t@example.com',
    '-c',
    'user.name=t',
    'commit',
    '-q',
    '-m',
    'x',
  );
  await put(untracked);
  return repo;
};
const scanRepo = async (repo: string, eslintTsconfig?: string) => {
  const results = await runEngines({
    repo,
    scope,
    selected: ['eslint'],
    tools: {},
    installErrors: {},
    gitExecutable: 'git',
    rulesDirectory: repo,
    ...(eslintTsconfig === undefined ? {} : { eslintTsconfig }),
  });
  const eslint = results.find((r) => r.engine === 'eslint');
  assert.ok(eslint);
  return eslint;
};

await test(
  'runEngines: opt-in through the real tracked-file path reports the type-only finding',
  linux,
  async () => {
    const repo = await gitRepo({
      'tsconfig.json': tsconfig,
      'src/a.ts': floating,
    });
    try {
      const typed = await scanRepo(repo, 'tsconfig.json');
      assert.equal(typed.status, 'completed', typed.reason);
      assert.ok(
        typed.findings.some(
          (f) => f.ruleId === '@typescript-eslint/no-floating-promises',
        ),
      );
      const plain = await scanRepo(repo);
      assert.ok(
        !plain.findings.some(
          (f) => f.ruleId === '@typescript-eslint/no-floating-promises',
        ),
      );
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  },
);

await test(
  'runEngines: a refused tsconfig fails the engine closed, never a silent untyped run',
  linux,
  async () => {
    const repo = await gitRepo(
      {
        'tsconfig.json': tsconfig,
        'src/a.ts': floating,
        'ts-config.txt': '{}',
        'pkg.json': '{"extends":"@tsconfig/node20/tsconfig.json"}',
        'node_modules/@tsconfig/node20/tsconfig.json': '{}',
      },
      { 'untracked.json': tsconfig },
    );
    try {
      const cases: Record<string, RegExp> = {
        '../tsconfig.json': /must be a repository-relative path/,
        'src/../tsconfig.json': /must be a repository-relative path/,
        'ts-config.txt': /must be a \.json file/,
        'untracked.json': /not a tracked file/,
        'pkg.json': /extends "@tsconfig\/node20\/tsconfig\.json", a package/,
        'node_modules/@tsconfig/node20/tsconfig.json':
          /must be a repository-relative path/,
      };
      for (const [path, reason] of Object.entries(cases)) {
        const r = await scanRepo(repo, path);
        assert.equal(r.status, 'failed', path);
        assert.match(r.reason ?? '', /^tsconfig-rejected: /, path);
        assert.match(r.reason ?? '', reason, path);
        assert.deepEqual(r.findings, [], path);
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  },
);

await test(
  'CLI: a malformed eslint-tsconfig is rejected as invalid input before any scan',
  linux,
  () => {
    const cli = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      'src',
      'quality-scan-cli.js',
    );
    const out = spawnSync(
      process.execPath,
      [
        cli,
        'run',
        '--repo',
        '.',
        '--out',
        join(tmpdir(), 'typed-cli-out'),
        '--scanners',
        'eslint',
        '--eslint-tsconfig',
        '../tsconfig.json',
      ],
      { encoding: 'utf8' },
    );
    assert.equal(out.status, 2);
    assert.match(
      out.stderr,
      /invalid input: eslint-tsconfig must be a repository-relative path/,
    );
  },
);
