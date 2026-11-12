import { realpathSync } from 'node:fs';

/**
 * Turn a path an engine printed (absolute under the private workspace, `./x`
 * or already relative) into a repository-relative path. Anything outside the
 * workspace stays as printed and is then refused by `isSafeRelativePath`.
 */
export function relativeSourcePath(path: string, sourceRoot?: string): string {
  const prefixes: string[] = [];
  if (sourceRoot) {
    prefixes.push(sourceRoot);
    try {
      prefixes.push(realpathSync(sourceRoot));
    } catch {
      /* the workspace is gone; the raw root still applies */
    }
  }
  let relative = path;
  for (const prefix of prefixes)
    if (relative.startsWith(`${prefix}/`))
      relative = relative.slice(prefix.length + 1);
  while (relative.startsWith('./')) relative = relative.slice(2);
  return relative.replaceAll('/./', '/');
}
