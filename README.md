# Shared TypeScript code quality (RRDSCRUM-69)

## Development

Use tested Node 22.23.4 and the exact package/lockfile pins. ESLint 10.13.0 and typescript-eslint 8.72.1 support TypeScript 5.9.3, not TypeScript 7. Pinned jiti loads TS configurations; only emitted dist JavaScript is generated.
After cloning: `npm ci`, `npm run setup:dev`, then `npm run check`. Developer setup builds and installs Husky hooks. Git-dependency prepare builds exports only and must not alter consumer hooks.
Tests use disposable Git repositories and ordinary commits. Installation smoke tests access the npm registry; no customer code or hosted CI runs.

## Reviewed consumer adoption

Pin an approved immutable Git SHA. Declare ESLint, Prettier, Husky, lint-staged, jiti and TypeScript directly at this package's exact versions; preserve lockfiles and never depend on transitive binary hoisting.
In eslint.config.ts, import `qualityConfig` from `@releaseready/code-quality/eslint` and export `qualityConfig(import.meta.dirname, ['src/**/*.ts', 'tests/**/*.ts'])`.
Use actual project-covered paths, including TSX. Application/tests receive recommended type-checked projectService rules. Legitimate out-of-project configs retain recommended syntax rules; do not classify application code as config to bypass typed checks.
Add framework presets only through reviewed adoption and keep eslint-config-prettier last.
Set package.json `prettier` to `@releaseready/code-quality/prettier`. In lint-staged.config.ts, re-export the default from `@releaseready/code-quality/lint-staged`.

```json
{
  "format": "prettier --ignore-path quality.ignore --write .",
  "format:check": "prettier --ignore-path quality.ignore --check .",
  "lint": "eslint . --max-warnings 0",
  "check:staged": "node node_modules/@releaseready/code-quality/dist/src/check-paths.js && node node_modules/lint-staged/bin/lint-staged.js --hide-unstaged",
  "prepare": "npm run build && husky"
}
```

Copy the pinned quality.ignore into the consumer root and refresh it on upgrades: Prettier resolves paths relative to that file, so never point into node_modules.
Copy hooks/pre-commit to .husky/pre-commit and run local Husky setup. Preserve any existing prepare/build behavior; a consumer without a build step can use `husky` alone.

## Git installation for staged path checks

The staged filename guard invokes system Git by absolute path, never through the
inherited PATH (which hooks can prepend with repository-owned executables).
Install Git in an administrator-managed location: `/usr/bin/git` on macOS/Linux
and other POSIX hosts, `/usr/local/bin/git` on FreeBSD, or
`C:\Program Files\Git\cmd\git.exe` for a machine-wide Git for Windows installation.
These locations and their parent directories must not be writable by untrusted users.
Custom installations (including NixOS, per-user Git and non-C Windows drives)
must explicitly set `CODE_QUALITY_GIT_EXECUTABLE` to their trusted absolute Git
executable path before running the guard. For example, use the installed
`/nix/store/.../bin/git` path on NixOS or `D:\Program Files\Git\cmd\git.exe`
on Windows. Empty, relative, NUL-containing and Windows network paths are rejected.
This is a behavior change: Git available only through PATH is no longer selected.
A missing or failing configured executable stops checks without trying another Git.

The override is trusted user configuration, not a way to accept repository or
third-party input. It does not validate file ownership or ACLs. Set it only in your
trusted development environment, pointing to an installation you trust, and do
not import the value from an untrusted project. This change protects direct Git
executable selection from PATH shadowing, not the entire inherited environment
(such as Node loader or Git configuration variables).
The package does not configure Git installations or permissions. Other tools and
hooks retain their existing behavior and are not a security boundary.

## Commit behavior

Formatting writes only through the explicit format command. Review and stage that diff yourself; hooks check without --fix. Format and format:check cover the same scope. Both CLI and staged checks honor EditorConfig, with explicit Prettier options taking precedence.
Always retain --hide-unstaged, backups and restoration: typed checks must not see unstaged changes in imported files.
The shared ignore policy excludes generated outputs, never authored code. Maintained ignore semantics and ESLint includeIgnoreFile support CRLF, comments and blank lines. Generated paths are filtered before tool invocation.
Native lint-staged tasks pass filenames directly to APIs without shell quoting. Missing dependencies fail closed; hooks never download substitutes through npx.
The approved portable-filename rule rejects literal backslashes before normalization using Git's NUL-delimited names. It reports an actionable error without renaming or hiding files; spaces, Unicode and quotes remain supported. No broader filename ban applies.
Local hooks are bypassable, not an access-control boundary. Hosted check and branch-protection policy is unchanged.

## Governance boundary

A later ticket may add reusable Sonar workflows, secure pins, gate enforcement and defaults. Products retain project keys and source/test/coverage paths; credentials stay in GitHub Secrets and gate administration in Sonar. This package changes neither hosted scans nor Sonar settings.
Future PRs are regular PRs: DO NOT MERGE identifies blockers; Ready To Review requires exact-head verification. Owners review and merge.

Sources: [ESLint](https://eslint.org/docs/latest/use/configure/configuration-files), [typescript-eslint](https://typescript-eslint.io/packages/typescript-eslint/), [lint-staged](https://github.com/lint-staged/lint-staged), [Husky](https://typicode.github.io/husky/how-to.html).
