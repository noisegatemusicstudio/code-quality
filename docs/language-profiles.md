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

Tracked files, shallow clones, lockfiles excluded. Only 5 of the 11 requested
repositories could be inventoried (see "Not inventoried").

| Repository                               | Languages and file types (tracked files)                                                                     | Build / test tooling                                                       | IaC / container / CI                                            | Existing lint intent                                                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| noisegatemusicstudio/code-quality        | TypeScript 72, YAML 10, Markdown 5, JSON 4                                                                   | tsc, node --test, Prettier, ESLint, husky, lint-staged                     | 3 workflows                                                     | ESLint flat config (`qualityConfig`) + Prettier + `quality.ignore`                                                 |
| releaseready/ReleaseReady                | TypeScript 563 (+28 .mts), TSX 63, Gherkin 36, Markdown 101, JSON 82, Python 2, Shell 1, YAML 9, CSS 8       | tsc, Vite, custom test runner, c8, Cucumber, Docker compose tests          | 8 Dockerfile variants, compose, 3 workflows, `requirements.txt` | `lint` = custom `.build/lint.js`; `format:check` = Prettier over an explicit file list; no ESLint config tracked   |
| releaseready/frontend-ui                 | TSX 154, TypeScript 73 (+2 .mts), JS 9, MJS 34, CSS 31, HTML 30, Markdown 107, JSON 286, Python 2, Gherkin 2 | npm workspaces, tsc (`tsconfig.check.json`), Vitest, Playwright, Storybook | 1 YAML                                                          | No ESLint, Prettier or other lint config tracked; type-check only                                                  |
| releaseready/test-management             | TypeScript 113, MJS 12, Markdown 15, JSON 7                                                                  | tsc, node --test, Forge wiring scripts                                     | none                                                            | `format:check` = Prettier; no ESLint config tracked                                                                |
| releaseready/universal-appium2-framework | TypeScript 18, MJS 1, Markdown 8, JSON 3, Gherkin 1, YAML 1                                                  | tsx, WebdriverIO, node --test                                              | 1 workflow (`quality.yml`)                                      | `eslint.config.mjs`: ESLint `recommended` + typescript-eslint `recommended` with `projectService`; Prettier script |

Across all five: no `.editorconfig`, yamllint, markdownlint, Ruff/flake8/mypy,
hadolint, tflint or shell-lint configuration exists. TypeScript dominates;
Python (4 files), Shell (1) and Dockerfiles (8) are small.

**Not inventoried** — say so rather than assume clean:

- `noisegatemusicstudio/ai-orchestrator`, `noisegatemusicstudio/cloud-platform`,
  `releaseready/test-data-management`, `releaseready/observability`: the
  session's `add_repo` request was denied by the permission classifier.
- `releaseready/universal-playwright-framework`,
  `releaseready/universal-api-framework`: anonymous clone failed (private);
  `add_repo` was not attempted after the denials above.

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
- This repository switches off five rules in its own `eslint.config.ts`
  (`no-unnecessary-condition`, `restrict-template-expressions`,
  `no-non-null-assertion`, `no-confusing-void-expression`, `no-dynamic-delete`)
  because the upgrade flags about 130 existing sites. That is migration debt,
  tracked as follow-up slice 1.

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
| New-code coverage    | at least 80%                 | `onUnknown: "report"` today                                                          |
| New-code duplication | at most 3%                   | `onUnknown: "report"` today                                                          |

Coverage and duplication are shown as thresholds but the workflow does not yet
measure new-code percentages, so a missing measure is reported and does not
block. Set `onUnknown` to `"fail"` once slice 12 lands. `--fail-on-severity`
(the workflow input) still overrides only the new-issue threshold; the workflow
default `high` equals the gate's.

## 4. Language detection

Every run lists the languages found with file counts. A language without a
language-aware engine is reported as `skipped: no engine yet`, in both
`summary.md` and `report.json` (`languages`). Today only TypeScript and
JavaScript (ESLint, Semgrep), Python (Ruff), Dockerfile and Terraform (Trivy)
count as covered; gitleaks, OSV and jscpd are language-agnostic and not counted.

## 5. Jira mapping

| Story        | Language | Chosen standard                                                  |
| ------------ | -------- | ---------------------------------------------------------------- |
| RRDSCRUM-185 | Java     | PMD quickstart, Checkstyle google_checks, SpotBugs + FindSecBugs |
| RRDSCRUM-186 | Kotlin   | detekt default config, ktlint                                    |
| RRDSCRUM-187 | Python   | Ruff (E, F, W, I, B, UP, S, C4, SIM, PL), mypy `--strict`        |
| RRDSCRUM-188 | Shell    | ShellCheck, shfmt                                                |

## 6. Follow-up slices (one per engine group, in order)

1. Clean up the five migration-debt rules in this repository and re-enable them.
2. Python: Ruff and mypy adapters (RRDSCRUM-187). **Done:** Ruff 0.17.4 runs
   from a bundled isolated config and is sha256-pinned; mypy is reported
   `skipped: needs dependency environment` (see `docs/scanner-licensing.md`).
3. Shell: ShellCheck and shfmt (RRDSCRUM-188).
4. GitHub Actions: actionlint and zizmor (cheap, MIT, we already ship workflows).
5. Dockerfile: hadolint (GPL, internal runs first).
6. Terraform: tflint beside Trivy.
7. Kotlin: detekt and ktlint (RRDSCRUM-186).
8. Java: PMD, Checkstyle, SpotBugs + FindSecBugs (RRDSCRUM-185; needs a build).
9. Swift: SwiftLint (needs a Swift runner).
10. YAML and Markdown: yamllint and markdownlint.
11. Prettier check as an engine for TS/JS and the formats above.
12. New-code coverage and duplication measures wired into the gate, then flip
    `onUnknown` to `fail`.
13. Type-aware ESLint for customers: opt-in input that supplies a reviewed
    tsconfig.
14. Counsel review of every "customer: needs review" tool.
15. Inventory the six repositories that could not be read.
