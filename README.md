# TypeScript code quality and customer-run scans

## Development

Use tested Node 22.23.4 and the exact package/lockfile pins. ESLint 10.13.0 and typescript-eslint 8.72.1 support TypeScript 5.9.3, not TypeScript 7. Pinned jiti loads TS configurations; only emitted dist JavaScript is generated.
After cloning: `npm ci`, `npm run setup:dev`, then `npm run check`. Developer setup builds and installs Husky hooks. Git-dependency prepare builds exports only and must not alter consumer hooks.
Tests use disposable Git repositories and ordinary commits. Installation smoke tests access the npm registry; no customer code or hosted CI runs.

## Offline report imports

The `import:report` command parses existing reports without running scanners or
reading repository configuration. It accepts UTF-8 JSON on stdin (at most
262144 bytes) and a caller-declared commit SHA of exactly 40 lowercase hexadecimal
characters.

```sh
npm run import:report -- --help
node dist/src/import-cli.js eslint "$COMMIT_SHA" < eslint-report.json
node dist/src/import-cli.js coverage "$COMMIT_SHA" < coverage-summary.json
node dist/src/import-cli.js aggregate "$COMMIT_SHA" < scanner-claims.json
```

ESLint imports use the ESLint 10.13.0 JSON dialect. Coverage imports use the
Istanbul reports 3.1.7 JSON-summary dialect. The aggregate includes the ESLint,
TypeScript, Gitleaks, jscpd, OSV, tests and coverage slots.
All imported evidence is `imported-unverified`: a parsed report or complete
aggregate does not prove scanner execution or a passing quality gate.

Import exit codes are 0 for a parsed import or complete aggregate, 1 for an
incomplete aggregate, and 2 for invalid arguments, input or I/O. The public
`/scan-report`, `/eslint-import` and `/coverage-import` exports provide the
corresponding JavaScript APIs.

## Customer-run committed-source scans

The `/customer-scan` export provides `scanCommittedSource`. The
`scan:committed` command accepts a JSON request on stdin and emits a bounded
execution report:

```sh
npm run scan:committed -- --help
node dist/src/scan-cli.js < scan-input.json
```

Required request fields are `gitExecutable` (a trusted absolute Git executable
path), `gitDirectory` (the absolute path to the repository's Git object database)
and `commitSha` (40 lowercase hexadecimal characters). For example, replace
each placeholder with your own trusted local value:

```json
{
  "gitExecutable": "/usr/bin/git",
  "gitDirectory": "/absolute/path/to/repository/.git",
  "commitSha": "<40-character-lowercase-commit-sha>"
}
```

Requests are limited to 262144 UTF-8 bytes. Optional fields are
`tools.gitleaks`, `tools.jscpd`, `tools.osv`, `osvDatabase`,
`declarationBundle.files`, `imports` and `coverageSummary`.
Use `--help` for the execution manifest and pinned tool versions.

The runner copies a bounded committed snapshot, excluding dirty working-tree
changes and untracked files. It does not execute project configuration, plugins,
install scripts or tests. The bundled ESLint syntax rules and fixed TypeScript
semantic profile run independently of the project's configuration. An explicit
validated declaration-only bundle can supply dependency types; unresolved
dependencies and source suppression directives limit coverage. This is not the
project's full type check.

Gitleaks, jscpd and OSV require caller-supplied, trusted absolute paths to the
pinned binaries. Native binaries are pinned for Linux x64, with Linux process
supervision and resource limits; there is no platform fallback or automatic tool
download. Missing tools are reported as missing rather than silently installed.

Offline OSV scanning supports npm package-lock inputs. Supply
`osvDatabase` with an absolute `archivePath`, its SHA-256 `sha256`, and an
`asOf` timestamp. The caller supplies the archive and must have permission to use
its data. Schema and engine licenses do not grant advisory-database or commercial
service rights. Database completeness remains unverified; unsupported dependency
manifests and other limitations are reported rather than treated as clean scans.

### Offline cache validation profiles

OSV archives are copied in fixed-size chunks into an exclusive private cache
while their SHA-256 is checked. Validation streams entries from that same cache
without extracting the archive. The validated cache is read-only and is the only
database supplied to the native scanner; the caller's archive is not changed.
Copy and validation share a 120-second supervised deadline. File-backed limits
are 384 MiB compressed, 2 GiB expanded, 500,000 entries and 8 MiB per record.
The worker has a 256 MiB V8 old-space limit, which is not a total RSS cap.
The small Buffer validation API retains its 64 MiB compressed, 128 MiB expanded
and 50,000-entry limits and its ZIP32-only policy. File-backed validation accepts
ordinary ZIP32 entries plus a narrow count-only ZIP64 directory envelope for large
entry counts, not general ZIP64.

The default `osvDatabase.validationProfile` is `strict-schema-v1`, validating
against the unchanged pinned OSV 1.9.2 schema. Callers may explicitly set
`"validationProfile": "npm-metadata-v1"` to recognize two narrow metadata defects:
invalid URI formatting in top-level reference URLs, and a top-level CVSS v4 score
with one trailing slash whose removal would match the pinned CVSS v4 pattern.
The archive and records are never rewritten. Other schema errors, malformed
records, corruption and duplicate entries still reject the entire archive.
Inherited options do not enable the profile; unknown or null profiles fail.

Results identify `validationProfile`, `schemaConformance` (`strict` or
`metadata-warnings`) and `metadataWarningCounts` for affected records, reference
URI formatting and trailing CVSS v4 slashes. These counts do not certify reference
URLs or severity values. Neither profile establishes archive provenance,
freshness, completeness or coverage of every dependency. Native scanning retains
its separate 30-second deadline and resource limits, so successful validation
does not guarantee successful scanning of an arbitrary archive.

Reports distinguish executed, missing, failed, timed-out, limited and
imported-unverified evidence. Tests and coverage remain unverified imports.
Execution reports deliberately retain `status: "incomplete"`; finding counts
are not a passing quality gate. The scan CLI exits 0 for help, 1 for an incomplete
execution report, and 2 for invalid input or I/O.

The runtime and supplied Git installation must be trusted. This is not a
hostile-code sandbox. Snapshot limits include a 64 MiB object store, 16 MiB of
source, 1000 source files and 1 MiB per source file. Shallow repositories,
alternates and linked-worktree object stores are unsupported. Keep local request
files, advisory archives and raw reports out of public commits.

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
