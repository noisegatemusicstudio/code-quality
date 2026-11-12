# TypeScript code quality and customer-run scans

## Development

Use tested Node 22.23.4 and the exact package/lockfile pins. ESLint 10.13.0 and typescript-eslint 8.72.1 support TypeScript 5.9.3, not TypeScript 7. Pinned jiti loads TS configurations; only emitted dist JavaScript is generated.
After cloning: `npm ci`, `npm run setup:dev`, then `npm run check`. Developer setup builds and installs Husky hooks. Git-dependency prepare builds exports only and must not alter consumer hooks.
Tests use disposable Git repositories and ordinary commits. Installation smoke tests access the npm registry; no customer code runs.

### Environment requirements

- **Node** `22.23.4` (or `>=24.3.0`), see `engines`.
- **Git 2.47 or newer** at `/usr/bin/git` (`/usr/local/bin/git` on FreeBSD), or any absolute path in `CODE_QUALITY_GIT_EXECUTABLE`. Committed-snapshot scanning refuses older Git because its isolation relies on `GIT_NO_LAZY_FETCH`. Ubuntu 24.04 ships Git 2.43, so on such hosts (including Claude cloud containers) install a newer Git and export `CODE_QUALITY_GIT_EXECUTABLE`. Without it the Git-backed tests fail up front with a message naming this requirement; they are not skipped.
- `/usr/bin/tar` and a POSIX shell; the packed-consumer test uses `npm pack` offline and needs no network.

### CI

`.github/workflows/ci.yml` runs on every pull request and push to `main` (ubuntu-latest, Node 22.23.4, read-only token, no secrets): `npm ci`, `build`, `format:check`, `lint`, `test`. Run `npm run check` locally for the same gate.

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
hostile-code sandbox. Snapshot hard caps are a 512 MiB object store, 64 MiB of
source, 10000 source files and 1 MiB per source file, within a 120 s deadline.
Symlinks, submodules, non-ASCII paths and blobs over 1 MiB are not
materialised: they are counted in `source.omitted` and no engine may then report
`completed`. A failed snapshot names the guard in `sourceDetail` (for example
`shallow-history`, `tree-entries`, `object-store-bytes`, `fsck-timeout`).
Shallow repositories, alternates and linked-worktree object stores are
unsupported. Keep local request
files, advisory archives and raw reports out of public commits.

## Scanner adapter result envelope

The `/adapter-envelope` export defines schema version 1 of a bounded result
envelope, and `validateEnvelope` checks it at runtime (unknown keys, oversize
input and inconsistent states fail closed). An envelope carries `tenantId`,
`projectId`, `repository`, the 40-character lowercase `commitSha`, `sourceId`,
`jobId`, `attemptId`, the engine id and version, `rulesetVersion`,
`configVersion`, a `provenance` (`adapter-executed` or `imported-unverified`), a
`status` and per-finding records. Each finding keeps the engine-native `ruleId`
and `nativeSeverity`, a repository-relative `path` with a line/column range, a
`sha256:` fingerprint and a redacted message of at most 300 characters.

Status is `completed`, `failed`, `skipped` or `incomplete`. Everything except
`completed` requires a `reason`; `failed` and `skipped` carry no findings, and
`incomplete` may carry the partial findings it has. Dropped or truncated results
are never reported as `completed`. Limits: 1 MiB of JSON, 5000 findings. Pass the
expected scope to `validateEnvelope` to deny any record for another tenant,
project, repository, commit, source, job or attempt. Redaction is best-effort, and
fingerprints change when a line moves; cross-run comparison belongs to a later
layer. The envelope is unauthenticated data, not proof of a scan.

### Detailed ESLint import

`parseEslintFindings` (`/eslint-import`) turns the same ESLint 10.13.0 JSON report
into an envelope with `imported-unverified` provenance after `parseEslintJson`
has validated the counts, which are unchanged. File paths must be inside the
supplied absolute `pathRoot`; others are dropped and the envelope is `incomplete`.
Suppressed messages, source text and fixes are discarded.

```sh
node dist/src/import-cli.js eslint-envelope "$COMMIT_SHA" \
  --tenant-id=t --project-id=p --repository=owner/name --source-id=s \
  --job-id=j --attempt-id=a --engine-version=10.13.0 \
  --ruleset-version=r1 --config-version=c1 --path-root="$PWD" < eslint-report.json
```

### Adapter interface

`runAdapter` (`/scanner-adapter`) runs a `ScannerAdapter` and returns a validated
envelope. An adapter declares a trusted absolute executable, the pinned engine
version (checked by running `versionArgs` and comparing exact output before any
scan), fixed arguments, an exact-match allowlist for caller arguments, accepted
exit codes and a parser. Package managers and shells are rejected as executables.
Files are written to a private temporary workspace that is always removed.
Requests have a timeout of at most 120 seconds, a 4 MiB output limit and an
`AbortSignal`: cancelling stops the whole process group and reports
`incomplete`/`cancelled` with no findings. The scrubbed environment carries no
credentials, proxy variables or `PATH`, and the adapter never installs packages
or runs lifecycle scripts. This is not a hostile-code or network-enforced sandbox:
the engine must be trusted, and the Linux-only supervisor applies as in
committed-source scans.

### Gitleaks CLI adapter

`createGitleaksAdapter` (`/gitleaks-adapter`) defines a `ScannerAdapter` for the
pinned, approved Gitleaks CLI (v8.30.1, MIT; `gitleaks-action` is not used and its
licence terms do not apply). Modes are `working-tree` (`dir .` over the adapter
workspace) and `commit-range` (`git` over a caller-prepared clone at an absolute
`repoPath`, limited to `base..head` with 40-character commits; `head` is the scoped
commit). The arguments are fixed and callers can pass none: the report goes to
stdout, `--redact` is always on, inline `gitleaks:allow` comments are ignored, and
the rule config and ignore file are the trusted absolute paths you supply, so a
scanned repository cannot supply or widen its own allowlist. The returned
`record` stores the exact mode, engine version and range. Set `shallow: true` for
a shallow or incomplete clone: the envelope is then `incomplete` with reason
`incomplete-history`.

`parseGitleaksReport` reads only `RuleID`, `File` and the line/column fields.
`Secret`, `Match` and every other field are never copied to findings, errors or
fingerprints. If a `Secret` is not the redaction placeholder the whole report is
rejected (`failed`/`invalid-output`). A finding's fingerprint is derived from rule,
path and location only (no secret-derived value, so it changes when a line moves).
Exit code 2 (leaks found) is a result; any other non-zero exit is `failed`.

`classifyGitleaksEnvelope` separates reviewed exceptions from failures. An
exception names one exact fingerprint plus its rule and path, a reviewer, a reason
and `reviewedAt`/`expiresAt` dates at most 90 days apart; there are no wildcards.
Expired, malformed or mismatched entries are rejected and never applied, and an
expired exception makes the finding active again. The result reports active,
excepted, new/existing (against a baseline of known fingerprints), expired,
rejected and unused counts. A `failed` or `skipped` scan stays failed regardless
of exceptions. Secrets are never validated, used or rotated, and no repository is
edited. Cloning the history, storing baselines and review workflows are future work.

Future work, out of scope here: authenticated, idempotent central upload;
recorded redistribution and hosted-use approvals per engine; network-enforced
isolation; baseline comparison of fingerprints across runs.

### Semgrep CE adapter

`runSemgrepScan` and `createSemgrepAdapter` (`/semgrep-adapter`) run Semgrep CE
v1.185.0 over TypeScript/JavaScript files, within
[docs/scanner-licensing.md](docs/scanner-licensing.md). The engine is a
customer- or operator-installed binary at a trusted absolute path; it is never
downloaded, bundled or redistributed, and the engine licence review (LGPL-2.1)
still gates any packaging. CodeQL and Sonar analyzers are not used.

- **Arguments** are fixed and callers pass none: `scan --json --metrics=off
--disable-version-check --config <local rules path> .`. `--config` must be an
  absolute local path; `auto`, `p/...`, `r/...`, URLs and relative paths are
  refused (`skipped`/`customer-config-rejected`, `refusal: registry-config`)
  and rules are never fetched at scan time. Semgrep runs no build or install
  step; like `runAdapter` this is not a network-enforced sandbox.
- **Rulesets**: `releaseready-authored` (starter rules in `rules/semgrep/`,
  ruleset version `2026.11.1`, ReleaseReady licence header) is allowed for any
  scope. `semgrep-maintained-snapshot` is internal-only (Semgrep Rules License
  v1.0): it runs only from a pinned local snapshot and only when
  `audience: 'internal'` is set; otherwise `refusal: internal-only-ruleset`.
  Any other source is `unapproved-ruleset`. Nothing is ever substituted.
- **Languages**: only `.ts/.tsx/.js/.jsx/.mjs/.cjs/.mts/.cts` are scanned. With
  none, the scan is `skipped`/`no-supported-files`; other files are listed in
  `unsupportedFiles`.
- **Parser** (`parseSemgrepReport`): rule id, native severity, range and message
  go in the envelope; `details` (by fingerprint) add CWE ids, confidence, kind
  (`vulnerability` or `review-required-hotspot`: explicit rule `finding-type`,
  else only HIGH/MEDIUM confidence counts as a vulnerability), dataflow
  locations (no source text) and rule remediation text. Matched code and
  `fix` are never copied. A non-empty `errors` array makes the run
  `incomplete`/`engine-error`; unparseable output is `failed`/`invalid-output`.
- Results cover the configured rules only. They are not Sonar-equivalent and are
  not a complete security review. The starter rules are unproven against real
  code and need tuning against the real engine before relying on them.

### OSV dependency-vulnerability adapter

`runOsvScan` (`/osv-adapter`) runs the pinned OSV-Scanner (2.7.1, Apache-2.0)
through `runAdapter` on **one** lockfile (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`,
`Gemfile.lock`, `Cargo.lock`, `go.mod`, `composer.lock`, `pom.xml`) or SBOM
(`*.cdx.json`, `*.spdx.json`). Select the artefact by repository-relative path;
anything else is `skipped`. Only `scan source --format json` plus one allowlisted
`-L <file>` or `--sbom <file>` argument is executed: no installs or lifecycle
scripts. Pass the trusted binary path and its exact `--version` output.

Each `DependencyFinding` has explicit `artefactPath`, `package`
(`name`/`version`/`ecosystem`), `advisory` (`id`, `aliases`), `affectedRanges`
and `fixedVersions` (empty means no fix is known), plus the `fingerprint` of the
matching envelope finding (`ruleId` is the advisory id). Aliases (GHSA/CVE) of the
same package, version and path are merged; different versions or paths never are.

- **Online (default).** Customer-run. Package names, versions and ecosystems
  are sent to the OSV API; `disclosure.transmitted` says so. This code does not
  enforce the network boundary; pass `networkAvailable: false` when it is known
  to be denied and the run is `skipped`.
- **Offline (opt-in).** Needs `databaseTimestamp` (ISO-8601) and refuses data
  older than `maxDatabaseAgeDays` (default 7) or dated in the future. The
  timestamp is disclosed and appears in `rulesetVersion` (`osv-db-YYYYMMDD`).
  Refresh the database before scans. Bundling or hosting database copies needs
  separate clearance (`docs/scanner-licensing.md`). Where the scanner finds its
  database is its own default; that, and the `--offline` flag, are unverified
  against a real binary because tests never download or run it.
- The shared reason enum has no network/stale/unsupported values, so those cases
  are `skipped` with `invalid-request`; the precise cause is `disclosure.outcome`
  (`unsupported-artefact`, `network-denied`, `stale-database`,
  `database-timestamp-missing`).

A clean result does not guarantee the absence of unknown vulnerabilities; it
means no known advisory in the consulted data matched.

### Trivy container and infrastructure adapter

`runTrivyScan` (`/trivy-adapter`) runs the pinned Trivy (0.76.2, Apache-2.0)
through `runAdapter` on one explicit target. Pass the trusted binary path and its
exact `--version` output.

- **Image** (`image-digest` `registry/name@sha256:<64 hex>`, or `image-tarball`
  with an absolute `.tar`/`.tar.gz`/`.tgz` path): only `--scanners vuln`, and
  `--image-src remote` or `--input`, so the Docker, containerd and podman sockets
  are never used. Tag-only references and other formats are `skipped`.
- **IaC** (`iac` with repository-relative files): `trivy config` (misconfiguration
  only) on files written to a private workspace. Unsupported files, and files
  Trivy reads implicitly (`trivy.yaml`, `.trivyignore*`), are dropped and listed
  in `disclosure.droppedFiles`; with nothing left the run is `skipped`
  (`no-supported-files`).
- Images are never started, infrastructure is never applied and customer scripts
  are never run. The scrubbed environment carries no registry or cloud
  credentials, so a private registry fails as `failed`/`engine-error`; pass
  `registryAccess: false` when it is known and the run is `skipped`. Network use
  and Terraform remote-module downloads are not enforced here.
- **Database.** Customer-run with the online DB is the default. Offline image
  scans need `databaseUpdatedAt` and refuse data older than `maxDatabaseAgeDays`
  (default 7) or dated in the future; version and timestamp are disclosed and the
  date is in `rulesetVersion`. Bundling or hosting a DB copy needs clearance
  (`docs/scanner-licensing.md`). Flags (`--offline-scan`, `--skip-db-update`) are
  unverified against a real binary because tests never download or run it.
- Vulnerabilities use the OSV `DependencyFinding` shape (`artefactKind: 'image'`)
  plus `severity: { label, source }`; misconfigurations give `path`, `resource`,
  `ruleId`, `severity`, `remediation`. Free text is redacted; secret findings and
  echoed source lines are never copied.
- `correlateDependencyFindings` (`/dependency-correlation`) groups OSV and Trivy
  findings by package, version, ecosystem and shared advisory id/alias: `total`
  counts each issue once while `occurrences` keeps every source.
- Outcomes beyond the shared reason enum (`registry-denied`, `stale-database`,
  `database-info-missing`, `unsupported-target`) are in `disclosure.outcome`.

## Coverage and duplication measures

Three exports report coverage and duplication with provenance. None of them runs
customer tests, downloads jscpd or produces a maintainability/security rating,
technical-debt estimate or composite score (`measuresNotProvided` lists them).

- `/coverage-detail`: `parseCoverageDetail(raw, format, context)` imports
  Istanbul `json-summary` (counts only) or `coverage-final` (adds per-line and
  per-branch hits, needed for new-code coverage). It keeps exact line and branch
  numerators/denominators per file and maps the report to a `commitSha` plus an
  exact file set. The report carries no commit, so the caller supplies
  `reportCommitSha`; it must equal `commitSha`. Gitignore-style `exclusions` and a
  `renames` map (report path to current path) apply before matching.
- `/duplication`: `jscpdAdapter(executable)` is a `runAdapter` definition (jscpd
  5.4.3, strict mode, 5 lines/50 tokens, no gitignore, empty caller allowlist;
  each clone becomes two findings, one per side). `parseJscpdReport` reads a
  recorded jscpd JSON report: clone locations on both sides and the pinned
  config. The real 5.4.3 report has no per-file line counts, so the caller
  supplies `lineCount` (the adapter counts lines in the committed snapshot) for
  every file a clone names. The numerator is distinct duplicated lines from the
  clone locations (lower than jscpd's own `duplicatedLines`, which sums clone
  sizes). jscpd does not list clone-free files, so the denominator is the
  report's `statistics.total.lines`, accepted only if the format totals agree and
  the snapshot counts of the clone files fit inside it; the method is recorded
  as `counting` in the measure's provenance. jscpd 5.4.3 does not name clone-free
  or skipped files, so they cannot be itemised and no analysed-file list is
  guessed; a failed cross-check fails closed (`invalid`). A scope with exclusions is
  `unsupported`, because the report-wide denominator cannot be scoped.
- `/quality-measures`: `buildQualityMeasures`, `newCodeMeasures`,
  `overallMeasures` and `evaluateThreshold` produce the typed, versioned
  (`schemaVersion: 1`) output.

Report states are explicit and never become a percentage by accident: `missing`
(nothing supplied), `unsupported` (not the declared Istanbul/jscpd shape, for
example lcov), `invalid` (malformed or inconsistent numbers), `stale` (report
commit differs), `unmatched` (report names files outside the file set), `partial`
(in-scope files absent) and `complete`. A complete report with 0 covered lines is
0%, which is different from every other state. A measure is `known` (numerator,
denominator, percent) or `unknown` with a reason; zero denominators are `unknown`.
`evaluateThreshold` returns `pass`, `fail` or `unknown`, so unknown never passes.

New-code measures take an explicit `referenceCommitSha`, the head commit and a
supplied `ChangedLinesDiff` (head-side added/changed lines per file; the diff base
must equal the reference). Coverage uses executable changed lines and changed
branch locations; a `json-summary` report, a stale or partial report, a changed
file missing from the report or a diff that does not match is `unknown`. Exclude
files such as tests by pattern. Duplication counts changed lines inside files
jscpd analyzed; changed lines in other files are reported as `unanalyzedLines`,
and a changed line beyond an analyzed file's length is a `diff-mismatch`.

Limits: coverage and duplication data are unverified customer inputs. jscpd covers
its supported formats only, finds token-level (not semantic) clones, skips files
below its thresholds, and has no generated-code detection: exclude generated code
by pattern, or it counts. A jscpd ignore directive in any committed file limits what a real
scan covers. Istanbul exclusions applied at collection time are invisible in the
report. The adapter's `parse` expects the JSON report on stdout, but jscpd's JSON
reporter writes a file, and that wiring was not verified against a real jscpd.

## Scoped ESLint code-quality adapter

`runEslintScan` lints customer JS/TS with the bundled approved config only,
rejects customer ESLint configs, never auto-fixes and never claims SAST, coverage
or duplication analysis; `compareFindings` reports new, existing and resolved
findings. See [docs/eslint-adapter.md](docs/eslint-adapter.md).

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

## Scanner licensing

Licence, redistribution and hosted-use review of candidate scanners (RRDSCRUM-61): [docs/scanner-licensing.md](docs/scanner-licensing.md).

## Quality scan workflow (GitHub Actions)

`.github/workflows/quality-scan.yml` is a reusable workflow that runs this
package's scanners on a pull request: ESLint (bundled rules), Gitleaks, Trivy
(filesystem IaC checks), Semgrep (ReleaseReady rules in `rules/semgrep` only, no
registry rules), jscpd and OSV, plus ShellCheck and shfmt (`-d`, never rewrites)
for shell scripts, actionlint and zizmor (`--offline`) for workflows, hadolint
(Dockerfiles), tflint (Terraform, bundled ruleset only, no plugin downloads),
yamllint and markdownlint-cli2, all with bundled default configs (project
configs are never applied). Every engine is downloaded at the version and
sha256 pinned in `src/scanner-pins.ts` and refused on mismatch; Semgrep is
installed with `pip --require-hashes` from `scanners/semgrep-requirements.txt`
(yamllint likewise from `scanners/yamllint-requirements.txt`); markdownlint-cli2
comes from the integrity-checked `package-lock.json`.
The job needs `contents: read` and no secrets.

```yaml
# .github/workflows/quality.yml in the caller repository
on: [push, pull_request]
permissions: { contents: read }
jobs:
  quality:
    uses: noisegatemusicstudio/code-quality/.github/workflows/quality-scan.yml@<full-sha>
    with:
      code-quality-ref: <full-sha> # must be the same full 40-character commit SHA
      enforce: false # advisory: report, never fail the PR
```

- **Pin `code-quality-ref` to a full commit SHA** (the job fails otherwise), and
  pin the `uses:` ref the same way. Tags and branches are not accepted.
- The organisation's Actions policy must allow reusable workflows from this
  public repository (Settings, Actions, General, allowed actions and reusable
  workflows).
- Inputs: `enforce` (default `false`), `node-version` (default `22.23.4`),
  `scanners` (comma list or `all`; engines with nothing to scan are skipped),
  `fail-on-severity` (default `high`), `baseline-path` (optional `report.json`
  from an earlier run, enabling the new-vs-baseline column), `osv-mode` (see
  below).
- Output: a Markdown job summary (counts per engine; skipped, failed and
  incomplete engines are listed and never shown as clean) and a
  `code-quality-results` artifact, described below.
- Enforce mode fails when any engine is failed or incomplete, or a finding is at
  or above `fail-on-severity`. Skipped engines do not fail it but are always
  shown with their reason.

### OSV mode and data disclosure

`osv-mode` is `online` (default), `offline` or `off`. **Online sends package
names, versions and ecosystems from each lockfile to the OSV API** (never source
code); the job summary lists this under "Data sent off the runner". Customers
who do not want that choose `off`. `offline` needs a caller-supplied advisory
database that is not provisioned, so OSV is reported `skipped`. Online use by the
customer is allowed by [docs/scanner-licensing.md](docs/scanner-licensing.md).

### Reviewed exceptions

`quality-exceptions.json` in the scanned repository may hold
`{ "gitleaks": [ ... ] }`. Each entry matches one exact finding (fingerprint,
rule and path; no wildcards) and needs `reviewedBy`, `reviewedAt`, `expiresAt`
(at most 90 days later) and `reason`. Expired, over-long or malformed entries
never apply. Excepted findings leave the finding count, are counted as
`excepted` in the summary, and stay in the envelope. A malformed file stops the
run with exit 2.

On `pull_request` events the file is read from the PR's **base commit** only, so
a PR cannot exempt its own findings: a new or changed exception takes effect
after it is merged. Entries the PR adds or changes are listed in the job
summary under "Exceptions pending review". If the base commit cannot be
determined the run stops with exit 2 (fail closed). On `push` events the pushed
commit's file is used.

### `code-quality-results` artifact (stable portal contract)

The workflow uploads the artifact `code-quality-results` with 90-day retention
on every run (`if: !cancelled()`), so the ReleaseReady portal can pull it with a
read-only token. Layout:

```text
manifest.json     identity and per-engine index (below)
report.json       decision and all findings (also usable as a baseline)
summary.md        the job summary text
envelopes/<engine>.json   validated adapter envelope, only for engines that produced one
```

`manifest.json` is built by the CLI from `GITHUB_*` variables with strict
validation; a missing or malformed value fails the run instead of being
guessed. Fields (`schemaVersion` 1):

| Field                 | Type                     | Source                                                                |
| --------------------- | ------------------------ | --------------------------------------------------------------------- |
| `schemaVersion`       | `1`                      | constant; bumped on any breaking change                               |
| `repository`          | `owner/name`             | `GITHUB_REPOSITORY`                                                   |
| `commitSha`           | 40 hex                   | scanned commit, must equal `GITHUB_SHA`                               |
| `ref`                 | string                   | `GITHUB_REF` (`refs/heads/..`, `refs/tags/..` or `refs/pull/N/merge`) |
| `event`               | `push` \| `pull_request` | `GITHUB_EVENT_NAME`; other events are rejected                        |
| `pullRequest`         | number \| `null`         | from the merge ref; `null` for push                                   |
| `runId`, `runAttempt` | positive integers        | `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`                                 |
| `workflowRef`         | string                   | `GITHUB_WORKFLOW_REF`                                                 |
| `codeQualityRef`      | 40 hex                   | the pinned scanner commit (`code-quality-ref`)                        |
| `engines[]`           | list                     | one entry per engine, below                                           |

Each `engines[]` entry: `id` (`eslint`, `gitleaks`, `osv`, `trivy`, `semgrep`,
`jscpd`, `hadolint`, `tflint`, `yamllint`, `markdownlint`), `version` (string or `null`), `status` (`completed`, `incomplete`,
`failed` or `skipped`), `reason` (string or `null`), `findingCount` (after
exceptions), `exceptedCount`, and `envelope` (artifact-relative path or `null`).
Treat anything other than `completed` as "not clean". Additive fields may
appear within a `schemaVersion`; consumers must ignore unknown fields.

Known limits: Gitleaks and jscpd use the
committed-snapshot API, so they need a full-history checkout, Git 2.47 or newer,
and stay within its size bounds (otherwise they report `failed`). A project's own
ESLint config is ignored; the bundled rules run instead.

## Language profiles and default gate

`docs/language-profiles.md` lists the industry-standard tool per language, the
default quality gate (`gates/default.json`, read by `quality-scan-cli run`) and
the follow-up slices. Languages without an engine are reported as
`skipped: no engine yet`, never as clean.
