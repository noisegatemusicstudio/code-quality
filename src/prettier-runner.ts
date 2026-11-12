import { lstat, readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import * as prettier from 'prettier';

/**
 * Prettier format-check runner. `prettier-adapter.ts` starts it with
 * `process.execPath` inside a private workspace; the working directory holds
 * copies of the tracked formattable files, any Prettier config files and the
 * root `.prettierignore`. It prints one JSON document and never writes a file.
 *
 * Prettier is the copy installed next to this tool. Nothing from the scanned
 * repository is imported: JS/TS configs are never loaded, `plugins` and
 * non-built-in `parser` values are dropped, and only an explicit path to a
 * JSON or YAML config is handed to `resolveConfig` (no directory search, no
 * `.editorconfig`, no `package.json`).
 */
export type FileState = 'unformatted' | 'error';
export interface RunnerFile {
  path: string;
  state: FileState;
}
export interface RunnerOutput {
  checked: number;
  ignored: number;
  files: RunnerFile[];
  /** Config files that were read (JSON or YAML only). */
  configUsed: string[];
  /** Config files or options not honoured; defaults apply instead. */
  configRejected: string[];
}

const acceptedConfigs = [
  'package.json',
  '.prettierrc',
  '.prettierrc.json',
  '.prettierrc.yaml',
  '.prettierrc.yml',
] as const;
const rejectedConfig =
  /^(?:\.prettierrc\.(?:[cm]?[jt]s|json5|toml)|prettier\.config\.[cm]?[jt]s)$/;
const builtInParsers = new Set([
  'babel',
  'babel-flow',
  'babel-ts',
  'flow',
  'typescript',
  'acorn',
  'espree',
  'meriyah',
  'css',
  'less',
  'scss',
  'json',
  'json5',
  'jsonc',
  'json-stringify',
  'graphql',
  'markdown',
  'mdx',
  'vue',
  'yaml',
  'glimmer',
  'html',
  'angular',
  'lwc',
]);
const ignoreFile = '.prettierignore';
const baseName = (path: string): string =>
  path.slice(path.lastIndexOf('/') + 1);

async function walk(root: string, dir = ''): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(join(root, dir), {
    withFileTypes: true,
  })) {
    const rel = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await walk(root, rel)));
    else if (entry.isFile()) out.push(rel);
  }
  return out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * `package.json` carries Prettier settings only as an object under `prettier`.
 * A string there names a module to load, which is code, so it is refused.
 */
async function packageConfig(
  full: string,
): Promise<'object' | 'module' | undefined> {
  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(full, 'utf8'));
  } catch {
    return undefined;
  }
  if (typeof manifest !== 'object' || manifest === null) return undefined;
  const setting = (manifest as Record<string, unknown>).prettier;
  if (setting === undefined) return undefined;
  return typeof setting === 'object' &&
    setting !== null &&
    !Array.isArray(setting)
    ? 'object'
    : 'module';
}

/** Nearest accepted config at or above the file, by the order Prettier uses. */
function nearestConfig(
  path: string,
  present: ReadonlySet<string>,
): string | undefined {
  let dir = dirname(path);
  for (;;) {
    const prefix = dir === '.' ? '' : `${dir}/`;
    for (const name of acceptedConfigs)
      if (present.has(`${prefix}${name}`)) return `${prefix}${name}`;
    if (dir === '.') return undefined;
    dir = dirname(dir);
  }
}

/** Drop options that would load repository code; report that they were dropped. */
function sanitise(
  options: prettier.Options,
  config: string,
  rejected: Set<string>,
): prettier.Options {
  const clean: Record<string, unknown> = { ...options };
  if ('plugins' in clean) {
    delete clean.plugins;
    rejected.add(`${config}: plugins`);
  }
  const parser = clean.parser;
  if (
    parser !== undefined &&
    !(typeof parser === 'string' && builtInParsers.has(parser))
  ) {
    delete clean.parser;
    rejected.add(`${config}: parser`);
  }
  return clean;
}

export async function runPrettier(root: string): Promise<RunnerOutput> {
  const all = await walk(root);
  const present = new Set(all.filter((p) => baseName(p) !== 'package.json'));
  const rejected = new Set(all.filter((p) => rejectedConfig.test(baseName(p))));
  for (const path of all.filter((p) => baseName(p) === 'package.json')) {
    const kind = await packageConfig(join(root, path));
    if (kind === 'object') present.add(path);
    else if (kind === 'module') rejected.add(`${path}: prettier module`);
  }
  // Any config form that needs code (or a parser we do not read) means the
  // project's own settings cannot be applied: run with defaults everywhere.
  const useConfigs = rejected.size === 0;
  const configUsed = new Set<string>();
  const output: RunnerOutput = {
    checked: 0,
    ignored: 0,
    files: [],
    configUsed: [],
    configRejected: [],
  };
  const ignorePath = present.has(ignoreFile)
    ? join(root, ignoreFile)
    : undefined;
  for (const path of all) {
    const name = baseName(path);
    if (
      name === ignoreFile ||
      rejectedConfig.test(name) ||
      (name !== 'package.json' &&
        (acceptedConfigs as readonly string[]).includes(name))
    )
      continue;
    const full = join(root, path);
    const info = await prettier.getFileInfo(full, {
      ...(ignorePath ? { ignorePath } : {}),
      resolveConfig: false,
    });
    if (info.ignored) {
      output.ignored += 1;
      continue;
    }
    if (info.inferredParser === null) continue;
    output.checked += 1;
    try {
      if ((await lstat(full)).isSymbolicLink()) throw new Error('symlink');
      const source = await readFile(full, 'utf8');
      let options: prettier.Options = {};
      const config = useConfigs ? nearestConfig(path, present) : undefined;
      if (config) {
        const resolved = await prettier.resolveConfig(full, {
          config: join(root, config),
          editorconfig: false,
        });
        configUsed.add(config);
        options = sanitise(resolved ?? {}, config, rejected);
      }
      const formatted = await prettier.format(source, {
        ...options,
        filepath: full,
      });
      if (formatted !== source)
        output.files.push({ path, state: 'unformatted' });
    } catch {
      // Syntax errors, bad options and unreadable files are all "not checked".
      // Prettier's message embeds source text, so it is never copied out.
      output.files.push({ path, state: 'error' });
    }
  }
  output.configUsed = [...configUsed].sort((a, b) => a.localeCompare(b, 'en'));
  output.configRejected = [...rejected].sort((a, b) =>
    a.localeCompare(b, 'en'),
  );
  return output;
}

process.stdout.write(JSON.stringify(await runPrettier(process.cwd())));
