# Language profiles and default quality gate

Owner direction (2026-11-12): use industry standards for code quality per
language. This repository replaces SonarQube for every ReleaseReady repository.
Reviewed 2026-11-12. Engineering licence summary, **not legal advice**.

Versions below are the latest stable upstream tags found on the review date
(`git ls-remote`). They are **candidates, not pins**: an engine becomes pinned
only in its own adapter slice, with a sha256-verified release asset in
`src/scanner-pins.ts`. Licences were compared against the first lines of each
upstream `LICENSE` file on the same date.

Status key: **internal OK** (we run it in our CI), **customer OK**
(redistribution or customer-run use needs only notices), **customer: needs
review** (GPL/LGPL; acceptable as a separate, unbundled binary for internal use,
not to be bundled or shipped until counsel confirms).

## 1. Repository inventory

Tracked files, shallow clones, lockfiles excluded. All 11 ReleaseReady
repositories are inventoried (the last six on 12 Nov 2026, slice 15).

| Repository                                  | Languages and file types (tracked files)                                                                     | Build / test tooling                                                                | IaC / container / CI                                            | Existing lint intent                                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| noisegatemusicstudio/code-quality           | TypeScript 72, YAML 10, Markdown 5, JSON 4                                                                   | tsc, node --test, Prettier, ESLint, husky, lint-staged                              | 3 workflows                                                     | ESLint flat config (`qualityConfig`) + Prettier + `quality.ignore`                                                 |
| releaseready/ReleaseReady                   | TypeScript 563 (+28 .mts), TSX 63, Gherkin 36, Markdown 101, JSON 82, Python 2, Shell 1, YAML 9, CSS 8       | tsc, Vite, custom test runner, c8, Cucumber, Docker compose tests                   | 8 Dockerfile variants, compose, 3 workflows, `requirements.txt` | `lint` = custom `.build/lint.js`; `format:check` = Prettier over an explicit file list; no ESLint config tracked   |
| releaseready/frontend-ui                    | TSX 154, TypeScript 73 (+2 .mts), JS 9, MJS 34, CSS 31, HTML 30, Markdown 107, JSON 286, Python 2, Gherkin 2 | npm workspaces, tsc (`tsconfig.check.json`), Vitest, Playwright, Storybook          | 1 YAML                                                          | No ESLint, Prettier or other lint config tracked; type-check only                                                  |
| releaseready/test-management                | TypeScript 113, MJS 12, Markdown 15, JSON 7                                                                  | tsc, node --test, Forge wiring scripts                                              | none                                                            | `format:check` = Prettier; no ESLint config tracked                                                                |
| releaseready/universal-appium2-framework    | TypeScript 18, MJS 1, Markdown 8, JSON 3, Gherkin 1, YAML 1                                                  | tsx, WebdriverIO, node --test                                                       | 1 workflow (`quality.yml`)                                      | `eslint.config.mjs`: ESLint `recommended` + typescript-eslint `recommended` with `projectService`; Prettier script |
| noisegatemusicstudio/ai-orchestrator        | Python 159, Markdown 23, JSON 8, MJS 2, YAML 1                                                               | `python3 -m unittest`; `requirements.txt` is standard library only                  | 1 workflow (`quality.yml`)                                      | No Ruff, flake8, mypy or pyproject config tracked                                                                  |
| noisegatemusicstudio/cloud-platform         | Terraform 23 (+15 .hcl), Python 15, Markdown 13, JSON 4, YAML 2, Makefile                                    | `make offline-check` (format-check, validate, test, safety, policy, lint, security) | Terraform modules and environments, 2 workflows                 | `.tflint.hcl`; Python lint not configured                                                                          |
| releaseready/test-data-management           | TypeScript 62, MJS 9, Markdown 13, JSON 7, YAML 4, Dockerfile 1                                              | tsc, node --test, Prettier, Redocly, `npm run check`                                | 1 Dockerfile, 2 compose files, 1 workflow                       | `format:check` = Prettier; no ESLint config tracked; `.sonarcloud.properties` (retire at cutover)                  |
| releaseready/observability                  | Python 6, YAML 8, Markdown 6, text 8, JSON 1                                                                 | Python probes and tests                                                             | 3 compose files, Prometheus config, 1 workflow                  | No lint configuration tracked                                                                                      |
| releaseready/universal-playwright-framework | TypeScript 119, Markdown 29, JSON 22, Gherkin 11, Shell 2, HTML 1                                            | tsc, Playwright, Cucumber, Allure                                                   | 1 workflow                                                      | Legacy `.eslintrc.json` on ESLint 8 / typescript-eslint 6 (`lint` script); Prettier `format:check`                 |
| releaseready/universal-api-framework        | TypeScript 12, MJS 8, JSON 6, Markdown 4, JS 1                                                               | tsc, node --test, k6 performance scripts                                            | 1 workflow                                                      | No ESLint or Prettier config tracked                                                                               |

Across all eleven: no `.editorconfig`, yamllint, markdownlint, Ruff/flake8/mypy,
hadolint or shell-lint configuration exists; only cloud-platform configures
tflint. TypeScript dominates; Python is the second language (about 185 files,
mostly ai-orchestrator), then Terraform (cloud-platform), Shell (3) and
Dockerfiles (9). No Kotlin, Java or Swift files exist yet, so those engines
detect nothing on internal repositories today.

Follow-ups from the six newly inventoried repositories:

- universal-playwright-framework runs ESLint 8 with a legacy `.eslintrc.json`;
  the shared scan uses its own flat config, so the repo's own `lint` script
  can stay until it migrates to the shared `qualityConfig`.
- test-data-management still has `.sonarcloud.properties`; remove it at the
  SonarQube cutover, not before.
- ai-orchestrator and observability are Python-first with no linter
  configuration; the shared Ruff engine covers them from its bundled config.

## 2. Language profiles

| Language / file type    | Standard tool and ruleset                                                                 | Candidate version                                                   | Licence (upstream LICENSE)                                                      | Status                                                           |
| ----------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| TypeScript / JavaScript | ESLint `recommended` + typescript-eslint `strict-type-checked` + `stylistic-type-checked` | ESLint 10.13.0, typescript-eslint 8.72.1 (pinned in `package.json`) | MIT                                                                             | internal OK, customer OK                                         |
| TS/JS formatting        | Prettier `--check`                                                                        | 3.9.10 (pinned)                                                     | MIT (package metadata; upstream LICENSE not re-fetched)                         | internal OK, customer OK                                         |
| Python lint             | Ruff: default (E4, E7, E9, F) plus E, F, W, I, B, UP, S, C4, SIM, PL                      | 0.17.4                                                              | MIT                                                                             | internal OK, customer OK                                         |
| Python types            | mypy `--strict` (pyright 1.1.414 is the accepted alternative, MIT)                        | mypy 2.4.1                                                          | MIT                                                                             | internal OK, customer OK                                         |
| Java                    | PMD `quickstart` ruleset                                                                  | 7.29.0                                                              | BSD-style                                                                       | internal OK, customer OK (keep notice)                           |
| Java                    | Checkstyle `google_checks.xml`                                                            | 14.4.0                                                              | LGPL-2.1                                                                        | internal OK, **customer: needs review**                          |
| Java                    | SpotBugs + FindSecBugs plugin                                                             | SpotBugs 4.10.5, FindSecBugs 1.14.0                                 | LGPL-2.1 / LGPL-3.0                                                             | internal OK, **customer: needs review**                          |
| Kotlin                  | detekt default config                                                                     | 1.23.8 (latest stable tag)                                          | Apache-2.0                                                                      | internal OK, customer OK                                         |
| Kotlin                  | ktlint (official/Android Kotlin style)                                                    | 1.8.0                                                               | MIT                                                                             | internal OK, customer OK                                         |
| Swift                   | SwiftLint default rules                                                                   | 0.65.1                                                              | MIT                                                                             | internal OK, customer OK (needs a Swift toolchain on the runner) |
| Shell                   | ShellCheck                                                                                | 0.11.0                                                              | GPL-3.0                                                                         | internal OK, **customer: needs review**                          |
| Shell                   | shfmt (`mvdan/sh`) `-d`                                                                   | 3.14.1                                                              | BSD-3-Clause                                                                    | internal OK, customer OK                                         |
| Dockerfile              | hadolint                                                                                  | 2.15.1                                                              | GPL-3.0                                                                         | internal OK, **customer: needs review**                          |
| Terraform / IaC         | Trivy config (already in place)                                                           | 0.76.2 (pinned)                                                     | Apache-2.0                                                                      | internal OK, customer OK                                         |
| Terraform               | tflint                                                                                    | 0.66.0                                                              | MPL-2.0                                                                         | internal OK, customer OK (unmodified binary, keep MPL notice)    |
| GitHub Actions          | actionlint                                                                                | 1.7.12                                                              | MIT                                                                             | internal OK, customer OK                                         |
| GitHub Actions          | zizmor                                                                                    | 1.32.0                                                              | MIT                                                                             | internal OK, customer OK                                         |
| YAML                    | yamllint                                                                                  | 1.38.0                                                              | GPL-3.0                                                                         | internal OK, **customer: needs review**                          |
| Markdown                | markdownlint (via markdownlint-cli2)                                                      | markdownlint 0.42.1, cli2 0.24.1                                    | MIT                                                                             | internal OK, customer OK                                         |
| All languages           | gitleaks (secrets)                                                                        | 8.30.1 (pinned)                                                     | MIT                                                                             | internal OK, customer OK                                         |
| All languages           | OSV-Scanner (dependencies)                                                                | 2.7.1 (pinned)                                                      | Apache-2.0; OSV data is mixed, do not bundle                                    | internal OK, customer OK for the scanner                         |
| All languages           | Semgrep CE with our rules                                                                 | 1.185.0 (pinned)                                                    | LGPL-2.1 engine; our own rules only (Semgrep-maintained rules are internal use) | internal OK, **customer: needs review**                          |
| All languages           | jscpd (duplication)                                                                       | 5.4.3 (pinned)                                                      | MIT                                                                             | internal OK, customer OK                                         |

Corrections to the expected candidates:

- Ruff's "S" is a Rust reimplementation of the flake8-bandit rules, not the
  bandit tool; no separate bandit install is needed.
- Ruff's own default set is only E4/E7/E9/F, so the explicit rule list above is
  the real profile.
- Checkstyle was expected to be a plain internal tool; it is LGPL-2.1, so it is
  flagged like the other copyleft tools. Everything GPL/LGPL above runs as a
  separate, unbundled binary.
- detekt 2.x is not yet a stable tag, so 1.23.8 is the candidate.

### TS/JS: what the bundled configs do

- `qualityConfig` (`@releaseready/code-quality/eslint`) now applies ESLint
  `recommended`, typescript-eslint `strict` and `stylistic` everywhere, and
  `strict-type-checked` plus `stylistic-type-checked` on the caller's
  `typedFiles`. Type information comes from typescript-eslint's project
  service, which parses the caller's tsconfig (including `extends`) as JSON. It
  does not execute project code. `typedFiles` must be covered by a real
  tsconfig or ESLint reports a parse error for them.
- The hosted scan config (`eslint-scan-config.ts`) is data only and loads no
  customer config or tsconfig, so it runs the syntax-only `strict` and
  `stylistic` sets. **Limitation:** the type-aware rules (for example
  `no-unnecessary-condition`, `no-floating-promises`) do not run in hosted
  scans; they run in the caller's own `lint`. The report does not claim
  type-aware coverage.
- This repository lints itself with the same `strict-type-checked` profile it
  ships; no rule is switched off in its own `eslint.config.ts`. The only
  exceptions are a few targeted, commented `no-unnecessary-condition` disables
  on runtime guards for untyped callers (follow-up slice 1).

## 3. Default quality gate

`gates/default.json` is the versioned gate that `quality-scan-cli run` reads
(`--gate PATH` selects another file; the file is strictly validated and an
invalid or unreadable gate exits 2). It is modelled on the industry-standard
"Sonar way" new-code gate:

| Condition            | Default                      | Behaviour                                                                            |
| -------------------- | ---------------------------- | ------------------------------------------------------------------------------------ |
| New issues           | none at `high` or `critical` | With a baseline only findings absent from it count; without one every finding counts |
| Secrets              | 0 findings                   | Any gitleaks finding fails, whatever the severity threshold                          |
| Required engines     | all must complete            | A failed or incomplete engine fails; a skipped engine is reported, never clean       |
| New-code coverage    | at least 80% (lines)         | Measured from a caller-supplied report; `onUnknown: "report"` today                  |
| New-code duplication | at most 3%                   | Measured from jscpd over the changed lines; `onUnknown: "report"` today              |

### New-code measures (slice 12)

The CLI measures new code against an explicit base, read from git in the
scanned checkout with no network access:

- **Pull requests** use the PR base SHA from the event payload (a `--base-ref`
  is ignored). The base commit must be in the clone (the workflow checks out
  full history); if it is missing the measures are `unknown`.
- **Pushes and local runs** (including the ReleaseReady Dev app) use
  `--base-ref REF` (workflow input `base-ref`). Without one the measures are
  `unknown: no comparison base`.
- **Coverage** is never produced by the scan. Pass `--coverage PATH` (workflow
  input `coverage-report`, repo-relative) with an Istanbul `coverage-final.json`
  for the scanned commit. The report is unverified and is assumed to match the
  scanned commit. Absent: `unknown: no coverage report supplied`. A
  `json-summary` file has no per-line data and is `unknown`; a supplied path
  that cannot be read exits 2.
- **Duplication** uses the jscpd engine result. Changed source files jscpd
  analyzes are counted even when clone-free, so no duplication is a known 0%.

Results are in `report.json` (`newCode`), `summary.md` ("New-code measures") and
`manifest.json` (`measures`). A measure with no changed executable lines is
`unknown: zero denominator`.

Unknown measures are reported and do not block while `onUnknown` is `"report"`
(the default). To block on them, set `newCodeCoverage.onUnknown` and/or
`newCodeDuplication.onUnknown` to `"fail"` in a gate file and pass it with
`--gate PATH`, or change `gates/default.json`. The default flips to `"fail"`
once the workflow reliably supplies a base and a coverage report.
`--fail-on-severity` (the workflow input) still overrides only the new-issue
threshold; the workflow default `high` equals the gate's.

## 4. Language detection

Every run lists the languages found with file counts. A language without a
language-aware engine is reported as `skipped: no engine yet`, in both
`summary.md` and `report.json` (`languages`). Today only TypeScript and
JavaScript (ESLint, Semgrep), Python (Ruff), Java (PMD, Checkstyle), Kotlin (detekt, ktlint), Shell (ShellCheck, shfmt), GitHub Actions
workflows (actionlint, zizmor), Dockerfile (Trivy, hadolint), Terraform (Trivy,
tflint), YAML (yamllint) and Markdown (markdownlint) count as covered; gitleaks, OSV and jscpd are language-agnostic and not counted.

## 5. Jira mapping

| Story        | Language | Chosen standard                                                  |
| ------------ | -------- | ---------------------------------------------------------------- |
| RRDSCRUM-185 | Java     | PMD quickstart, Checkstyle google_checks, SpotBugs + FindSecBugs |
| RRDSCRUM-186 | Kotlin   | detekt default config, ktlint                                    |
| RRDSCRUM-187 | Python   | Ruff (E, F, W, I, B, UP, S, C4, SIM, PL), mypy `--strict`        |
| RRDSCRUM-188 | Shell    | ShellCheck, shfmt                                                |

## 6. Follow-up slices (one per engine group, in order)

1. Clean up the five migration-debt rules in this repository and re-enable them. **Done.**
2. Python: Ruff and mypy adapters (RRDSCRUM-187). **Done:** Ruff 0.17.4 runs
   from a bundled isolated config and is sha256-pinned; mypy is reported
   `skipped: needs dependency environment` (see `docs/scanner-licensing.md`).
3. Shell: ShellCheck and shfmt (RRDSCRUM-188). **Done**: pinned, severity-mapped.
4. GitHub Actions: actionlint and zizmor (cheap, MIT, we already ship workflows). **Done**: pinned, zizmor offline.
5. Dockerfile: hadolint (GPL, internal runs first). **Done.**
6. Terraform: tflint beside Trivy. **Done** (bundled terraform ruleset, no plugins).
7. Kotlin: detekt and ktlint (RRDSCRUM-186). **Done:** detekt 1.23.8 (default
   ruleset, SARIF) and ktlint 1.8.0 (official style, JSON reporter) are
   sha256-pinned jars run as `java -jar`; no Java runtime means
   `skipped: needs a Java runtime` (see `docs/scanner-licensing.md`).
8. Java: PMD, Checkstyle, SpotBugs + FindSecBugs (RRDSCRUM-185). **Done for
   the source-only engines:** PMD 7.29.0 (quickstart) and Checkstyle 14.4.0
   (Google checks) run on the workflow's JDK; SpotBugs is reported
   `skipped: requires compiled classes` until a reviewed build input exists
   (FindSecBugs comes with it).
9. Swift: SwiftLint (needs a Swift runner).
10. YAML and Markdown: yamllint and markdownlint. **Done.**
11. Prettier check as an engine for TS/JS and the formats above.
12. New-code coverage and duplication measures wired into the gate. **Done**
    (`onUnknown` stays `report`; flipping it to `fail` is a separate decision).
13. Type-aware ESLint for customers: opt-in input that supplies a reviewed
    tsconfig.
14. Counsel review of every "customer: needs review" tool.
15. Inventory the six repositories that could not be read. **Done** (12 Nov 2026).
