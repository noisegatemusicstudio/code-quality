import { posix } from 'node:path';
import ts from 'typescript';
import { isSafeRelativePath } from './adapter-envelope.js';

/** Bounds on the `extends` chain, so a hostile tsconfig graph stays small. */
export const tsconfigChainLimits = Object.freeze({ files: 20, depth: 10 });
/** Characters a tsconfig path may use; it becomes one fixed ESLint argument. */
const pathPattern = /^[A-Za-z0-9._@/-]+$/;

export type TsconfigRefusal =
  | 'invalid-path'
  | 'not-json'
  | 'not-tracked'
  | 'unreadable'
  | 'invalid-config'
  | 'extends-package'
  | 'extends-outside-repository'
  | 'extends-untracked'
  | 'extends-too-deep';
export type TsconfigChain =
  | { ok: true; path: string; files: Record<string, string> }
  | { ok: false; refusal: TsconfigRefusal; detail: string };

const refuse = (
  refusal: TsconfigRefusal,
  detail: string,
): TsconfigChain & { ok: false } => ({ ok: false, refusal, detail });
const inNodeModules = (path: string): boolean =>
  path.split('/').includes('node_modules');

/**
 * Check the form of the opt-in path alone (no repository needed): repo-relative,
 * no `..`, no `node_modules`, JSON only. Used by the CLI to fail fast and by
 * {@link resolveTsconfigChain} before anything is read.
 */
export function tsconfigPathProblem(
  path: string,
): (TsconfigChain & { ok: false }) | undefined {
  if (
    !isSafeRelativePath(path) ||
    !pathPattern.test(path) ||
    inNodeModules(path)
  )
    return refuse(
      'invalid-path',
      'eslint-tsconfig must be a repository-relative path without "..", "node_modules" or unusual characters',
    );
  return path.endsWith('.json')
    ? undefined
    : refuse('not-json', 'eslint-tsconfig must be a .json file');
}

function extendsList(config: unknown): string[] | undefined {
  const value = (config as { extends?: unknown }).extends;
  if (value === undefined) return [];
  const list = Array.isArray(value) ? (value as unknown[]) : [value];
  return list.every((e): e is string => typeof e === 'string')
    ? list
    : undefined;
}

/**
 * Resolve one `extends` entry to a tracked repository file. Packages (bare
 * specifiers, anything under `node_modules`) and files outside the repository
 * are refused: the scan never reads the scanned repository's dependencies.
 */
function resolveExtends(
  from: string,
  entry: string,
  tracked: ReadonlySet<string>,
): { path: string } | (TsconfigChain & { ok: false }) {
  if (!entry.startsWith('./') && !entry.startsWith('../'))
    return refuse(
      'extends-package',
      `${from} extends "${entry}", a package or absolute path; only tracked repository files may be extended`,
    );
  const joined = posix.normalize(posix.join(posix.dirname(from), entry));
  if (joined.startsWith('../') || joined === '..')
    return refuse(
      'extends-outside-repository',
      `${from} extends "${entry}", which leaves the repository`,
    );
  if (inNodeModules(joined))
    return refuse(
      'extends-package',
      `${from} extends "${entry}" inside node_modules; dependencies are never read`,
    );
  const path = joined.endsWith('.json') ? joined : `${joined}.json`;
  return tracked.has(path)
    ? { path }
    : refuse(
        'extends-untracked',
        `${from} extends "${entry}", which is not a tracked file`,
      );
}

/**
 * Validate the opt-in tsconfig and collect it with every file it extends.
 * Pure over `tracked` and `read`: nothing is executed or installed. The
 * result's `files` are exactly what is written to the scan workspace.
 */
export async function resolveTsconfigChain(
  path: string,
  tracked: ReadonlySet<string>,
  read: (path: string) => Promise<string | undefined>,
): Promise<TsconfigChain> {
  const problem = tsconfigPathProblem(path);
  if (problem) return problem;
  if (!tracked.has(path))
    return refuse('not-tracked', `${path} is not a tracked file`);
  const files: Record<string, string> = {};
  const visit = async (
    current: string,
    chain: readonly string[],
  ): Promise<(TsconfigChain & { ok: false }) | undefined> => {
    if (chain.length >= tsconfigChainLimits.depth)
      return refuse(
        'extends-too-deep',
        `extends chain is deeper than ${String(tsconfigChainLimits.depth)}`,
      );
    if (current in files) return undefined;
    if (Object.keys(files).length >= tsconfigChainLimits.files)
      return refuse(
        'extends-too-deep',
        `more than ${String(tsconfigChainLimits.files)} tsconfig files`,
      );
    const text = await read(current);
    if (text === undefined)
      return refuse('unreadable', `${current} could not be read`);
    files[current] = text;
    const parsed = ts.parseConfigFileTextToJson(current, text);
    const list =
      parsed.error === undefined &&
      typeof parsed.config === 'object' &&
      parsed.config !== null
        ? extendsList(parsed.config)
        : undefined;
    if (list === undefined)
      return refuse('invalid-config', `${current} is not a valid tsconfig`);
    for (const entry of list) {
      const next = resolveExtends(current, entry, tracked);
      if ('ok' in next) return next;
      if (chain.includes(next.path)) continue;
      const refused = await visit(next.path, [...chain, current]);
      if (refused) return refused;
    }
    return undefined;
  };
  const refused = await visit(path, []);
  return refused ?? { ok: true, path, files };
}
