---
name: buildproveship-code-quality
description: Code-quality rules for every change in any BuildProveShip repo (buildproveship, frontend-ui, buildproveship-product-tests, test-management, test-data-management, universal-playwright-framework, universal-api-framework, universal-appium-framework, observability, config). Use before writing or editing code, tests, configs, dependencies or READMEs in these repos, and before saying such work is done. Encodes the 191 defects found in the 18 Nov 2026 cross-repo review so AI-assisted coding does not bring them back.
---

# BuildProveShip code quality

The 18 Nov 2026 review of nine repos found 191 defects (`_review/findings/<repo>.md`, IDs such as `RR-05` or `TM-06`).
Most came from four habits: **keeping old code "just in case", writing a helper instead of using a library, copying
code from another repo instead of importing it, and turning a check off to go green.** Each rule below names the
findings it prevents. `releaseready-guardrails` (from `@buildproveship/config`) enforces the mechanical part in every
repo's `pr.yml`; the rest is on you.

## The rules

1. **No legacy or compatibility code without a named current consumer.** Nothing is in production. When a
   replacement exists, delete the old code, its readers, migrations, shims, exports, duplicate tests and docs in the
   same PR. Keep compatibility code only when you can name the consumer (repo, file, caller or deployed system) in
   a comment next to it and in the PR. No `@deprecated`, no `legacy*`, no `v1` kept beside `v2`, no exported subpath
   that no sibling repo imports. History is in Git. _(RR-03, RR-04, RR-05, TM-11, TM-12, TM-22, TDM-15, TDM-16,
   UPF-01, UPF-02, UPF-17, UA2-10, UA2-12, FUI-06, FUI-10, FUI-17)_
2. **Fix code-quality problems with the tooling, never by weakening it.** Never turn a lint rule off, lower
   `strict`, add `any`, skip or focus a test, narrow a lint/format glob, or loosen a guard to go green. Every
   `eslint-disable`, `@ts-expect-error`, `noqa` or `type: ignore` names the rule and carries a reason
   (`// eslint-disable-next-line rule -- reason`); `@ts-ignore` and `@ts-nocheck` are not allowed. Lint, format and
   typecheck cover every file in the repo, not an allowlist. _(RR-02, RR-11, RR-12, TM-01, TM-03, TM-05, TM-08,
   TDM-04, RPT-04, RPT-21, UPF-02, UPF-03, UPF-18, UAF-01, UAF-02, UA2-06, UA2-07, UA2-18, FUI-02, FUI-15, OBS-01)_
3. **Search before you write a helper.** Before writing retry, HTTP or REST clients, argument or env parsing,
   validation, date maths, UUIDs, deep clone or merge, ZIP/XML/YAML/CSV parsing, migrations, polling waits, colour
   maths, dependency audits or a test runner, look for (in this order) the platform (`node:util.parseArgs`,
   `structuredClone`, `fetch`, `server.closeAllConnections()`), the framework (Playwright fixtures, `storageState`,
   `expect.poll`, Cucumber profiles), the official SDK or CLI (`gh`, Octokit, AWS SDK, `npm ls`, `npm audit`), then a
   maintained npm library (Ajv, `yauzl`, `fast-xml-parser`, `yaml`, `colorjs.io`, `node-pg-migrate`). Write custom
   code only when none fits, and say in a comment which ones you checked and why they don't. _(RR-07, RR-08, RR-09,
   RR-10, RR-19, TM-04, TM-09, TM-10, TDM-08, TDM-09, RPT-11, RPT-12, RPT-16, UPF-06, UPF-07, UPF-08, UAF-05, UAF-14,
   UA2-01, UA2-02, UA2-03, UA2-14, FUI-03, FUI-07, FUI-19, FUI-20, OBS-08)_
4. **Import shared code; never copy it.** One source for each config, constant, type, schema, fixture and doc fact.
   Shared code lives in exactly one of these places — import it, and if what you need is missing, add it there
   first (see [where shared code lives](references/shared-sources.md)):
   - `@buildproveship/test-management`: `schema/v1` (reference, revision, uuid, digest, object primitives),
     `canonical/v1` (canonical JSON + digest), `identity/v1` (JWT/OIDC verifier, incl. Cognito), `sqlite/v1` (open
     helper), `contract-comparator/v1`, `gherkin-cases/v1` (case-ID derivation), and the contract types;
   - `@buildproveship/test-data-management` `dev-fixtures/v1`: seeded Dev accounts, codes and invitations;
   - `@buildproveship/config`: ESLint, Prettier, tsconfig base, Renovate preset, these guardrails;
   - `@buildproveship/ui-web` (`/v8`) and `@buildproveship/tokens`: components, CSS and design tokens.
     Two copies of the same thing inside one repo are also a finding: extract one module. _(TM-06, TM-07, TM-13,
     TM-14, TM-15, TM-16, TM-17, TM-18, TM-20, TM-23, TDM-05, TDM-06, TDM-07, TDM-13, TDM-14, TDM-21, TDM-22, RPT-01,
     RPT-05, RPT-07, RPT-10, RR-05, RR-06, RR-13, RR-16, RR-17, UPF-09, UPF-10, UPF-15, UAF-06, UAF-07, UAF-08, UA2-08,
     UA2-09, UA2-19, UA2-21, FUI-11, FUI-12, FUI-13, FUI-16, OBS-04, OBS-05, OBS-06, OBS-07)_
5. **Depend on published `^` versions only.** Internal packages come from GitHub Packages as `"@buildproveship/x":
"^1.2.0"`. No git URLs or SHA pins, no tarballs (committed or remote), no `file:`/`link:` deps, no tsconfig
   `paths` into `dist/` or `node_modules`, no scripts that build a dependency inside `node_modules`. If a consumer
   needs something unexported, export it from the package and release it. Every import is a declared dependency.
   _(RR-14, RR-15, FUI-04, TM-21, TM-25, TDM-10, TDM-11, TDM-12, RPT-08, RPT-13, RPT-14, RPT-15, UPF-13, UPF-14,
   UPF-16, UAF-09, UAF-17, UA2-03, UA2-04, UA2-05)_
6. **Write it to the standard.** Strict types at every boundary (validate input with the shared schemas, no
   `as unknown as`), errors that fail loudly (no blind `except Exception`/`catch {}`), files created with explicit
   modes (0600 for secrets), no test-only knobs in production modules, no `assert` for runtime checks in Python,
   no secrets in code or logs, dependencies current and audited. _(TDM-01, UPF-11, UPF-21, RPT-09, OBS-02, OBS-03,
   OBS-09, RR-20, TM-24, FUI-08, UPF-19, UPF-22, UAF-15, UAF-18, UA2-16, UA2-17, OBS-16)_
7. **Keep it maintainable and checked on every PR.** One check command runs everything light; `pr.yml` runs it on
   every pull request. **Merge only when `pr.yml` is green** (squash). On config and universal-appium-framework
   GitHub branch protection enforces it; the other repos are private on the free plan, where a local Claude Code
   hook blocks `gh pr merge` until every check on the PR is green. Never bypass either. Build output is cleaned before tests run. Delete unused
   files, exports, dependencies and parameters (knip, vulture). Split files over ~1,000 lines. Every test file has
   the classification header its repo's AGENTS.md asks for. _(RR-01, RR-18, FUI-01, FUI-05, FUI-14, FUI-18, TM-02,
   TDM-02, TDM-03, TDM-17, TDM-18, TDM-24, RPT-02, RPT-03, RPT-06, RPT-19, RPT-20, UPF-04, UPF-05, UPF-12, UPF-20,
   UAF-03, UAF-04, UAF-10, UAF-11, UA2-13, UA2-15, OBS-10, OBS-11, OBS-12, OBS-15)_
8. **READMEs describe the code as it is today.** No dated status, ticket history, migration diaries, evidence maps
   or approval checklists in a README; those go in `CHANGELOG.md` or `docs/history/`. Don't restate facts that live
   elsewhere (versions in package.json, limits in code); link to them. Check every claim against the code before
   you write it. Name things for what they do, not for a ticket. _(TDM-19, TDM-20, TM-26, RPT-17, FUI-09, UA2-11,
   UA2-20, UA2-22, UAF-12, OBS-17, RR-21)_
9. **Every finding gets a permanent guard.** When a review, scanner (semgrep, ruff, ESLint, a former SonarCloud run),
   CI run or person finds a defect, fixing the one instance is not done. In the same PR add the cheapest guard that
   makes the whole class fail next time, in this order: a lint or guardrail rule (`guardrails/rules.js` in
   `@buildproveship/config`, ruff or ESLint config), a test that fails without the fix, then a row in the table below.
   Say which guard you added in the PR. Never dismiss a finding without a reason in the scanner or an allowlist entry.
   Patterns already known: no `assert` for runtime checks (raise); no literal `/tmp` or `/` as a temp or working
   directory (`mkdtemp`, `/var/empty`); no regex whose lazy or nested quantifiers can backtrack on tool or user
   text (split and parse); every path from a CLI argument, config or model output is made absolute, rejected on
   NUL, resolved with `realpath` and checked against the allowed roots, with `O_NOFOLLOW` on create, through one
   shared helper; sort strings with a comparator (`localeCompare`); never write request input into an HTML or
   unsafe-typed response (JSON with `application/json`, `nosniff` and a CSP). _(SonarCloud findings, 20 Nov 2026)_

## Before you say "done"

- [ ] No old path kept beside the new one; every compatibility branch names its consumer.
- [ ] Each new helper: you searched the platform, framework, SDK/CLI and npm first (say which in the PR).
- [ ] Nothing copied from another file or repo; shared code imported from the packages in rule 4.
- [ ] Internal deps are `^` registry versions; no `paths`, tarballs, git pins or `node_modules` builds.
- [ ] No rule, test, glob or guard loosened; every disable comment has `-- reason`.
- [ ] For every finding you fixed, you added a guard for its class (rule 9) and named it in the PR.
- [ ] Unused code, exports and deps you made unused are deleted.
- [ ] README and docs match the code; history went to CHANGELOG or `docs/history/`.
- [ ] The repo's check command (named in its `AGENTS.md`) passes, including `npm run check:guardrails`
      (`releaseready-guardrails`). Report what you ran, what passed and what you didn't run.

## Smell → fix

| If you are about to…                                                       | Do this instead                                                                                                                                                                                   | Findings                     |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| keep a v1 controller, reader or migration "for old data"                   | delete it; nothing is in production                                                                                                                                                               | RR-03, RR-04, TM-11/12       |
| mark something `@deprecated` or name it `legacy…`                          | delete it and update its callers                                                                                                                                                                  | UPF-01, FUI-17               |
| keep an export, starter or slice "someone might use"                       | find the importer; none → delete                                                                                                                                                                  | TM-22, TDM-16, UA2-12        |
| type `/^[A-Za-z0-9][A-Za-z0-9._:-]*$/`, a UUID or a 64-hex regex           | import from `@buildproveship/test-management/schema/v1`                                                                                                                                           | TM-07, TM-16, TDM-07         |
| write `canonical()` / sort keys + sha256                                   | `@buildproveship/test-management/canonical/v1`                                                                                                                                                    | TM-06, TDM-21                |
| call `jwtVerify` / build a JWKS verifier                                   | `@buildproveship/test-management/identity/v1`                                                                                                                                                     | TM-18, TDM-06                |
| write `0.2126 * r + 0.7152 * g …` contrast maths                           | `colorjs.io` (`Color.contrast(…, "WCAG21")`)                                                                                                                                                      | RPT-11                       |
| copy seeded Dev emails or codes into constants                             | `@buildproveship/test-data-management/dev-fixtures/v1`                                                                                                                                            | TDM-14, RPT-05               |
| copy a component, its CSS or a token value                                 | `@buildproveship/ui-web/v8`, `@buildproveship/tokens`                                                                                                                                             | RR-05, RR-06, FUI-11         |
| copy a test tree "to mirror" another repo                                  | one repo owns it; the other imports or runs it                                                                                                                                                    | RPT-01                       |
| pin `"x": "github:org/x#abc123"` or commit a `.tgz`                        | publish the package, depend on `^x.y.z`                                                                                                                                                           | RR-15, TDM-12, UPF-16        |
| alias `paths` to `node_modules/x/dist/...`                                 | export the subpath from the package and import it                                                                                                                                                 | RR-14, RPT-08                |
| run `npm run build --prefix node_modules/x`                                | consume the published build                                                                                                                                                                       | TDM-11, RPT-15               |
| write `argv[4]` or a flag-parsing loop                                     | `node:util.parseArgs`                                                                                                                                                                             | RR-10, UAF-05, UA2-02        |
| write a retry/sleep loop in a Playwright test                              | `expect.poll`, `expect(...).toPass()`, web-first assertions                                                                                                                                       | UPF-07                       |
| hand-write a `fetch` client with response checks                           | generated OpenAPI client/types, Octokit or `gh`, or Ajv on the shared schema                                                                                                                      | RR-07, RR-09, RPT-12         |
| hand-write an XML, ZIP, YAML or CSV parser                                 | a maintained library (`fast-xml-parser`, `yauzl`, `yaml`, `csv-parse`)                                                                                                                            | TM-10, RR-08, UA2-14         |
| validate a body with `typeof` chains                                       | Ajv with the schema you already have                                                                                                                                                              | TDM-08, TM-09                |
| new `new Ajv({ strict: false })`                                           | the repo's one shared strict Ajv instance                                                                                                                                                         | TM-05                        |
| add `// eslint-disable-next-line` or `@ts-expect-error` to go green        | fix the code; if truly needed, name the rule and add `-- reason`                                                                                                                                  | UPF-02, RR-12                |
| set a rule to `"off"` or narrow the lint/format glob                       | fix the code; a repo-level override needs a comment saying why                                                                                                                                    | UPF-03, UA2-07, RR-11        |
| use `any` or `as unknown as`                                               | a real type, a type guard or a schema-derived type                                                                                                                                                | RR-12, UPF-18, RPT-21        |
| `except Exception:` / `catch {}` that hides bugs                           | catch the specific error you expect and let the rest fail                                                                                                                                         | OBS-09                       |
| add `injectedFailure` / test knobs to a production module                  | inject through the test, not the shipped API                                                                                                                                                      | UPF-11                       |
| write a second copy of a constant, limit or config                         | import the one definition; generate both outputs from one source                                                                                                                                  | UPF-10, UAF-06, OBS-06       |
| add a README section "Status — 15 Nov 2026" or a ticket diary              | `CHANGELOG.md` / `docs/history/`; README says what the code does now                                                                                                                              | TDM-20, RPT-17, TM-26        |
| copy versions from package.json into docs                                  | link to package.json                                                                                                                                                                              | UA2-20, UAF-12               |
| fix one finding and stop                                                   | add a lint/guardrail rule, test or skill row for the whole class                                                                                                                                  | rule 9                       |
| write `assert cond, msg` as a runtime check in Python                      | `if not cond: raise SomeError(msg)`                                                                                                                                                               | SonarCloud                   |
| write `"/tmp"` as a temp dir or cwd                                        | `tempfile.mkdtemp()` / `fs.mkdtemp()`, or `/var/empty` when nothing is written                                                                                                                    | SonarCloud                   |
| write a regex with `.+?` or nested quantifiers on tool output              | split and parse the text                                                                                                                                                                          | SonarCloud                   |
| call `.sort()` on strings with no comparator                               | `.sort((a, b) => a.localeCompare(b))`                                                                                                                                                             | SonarCloud                   |
| add `eslint-disable` or `@ts-expect-error` with no reason, or `@ts-ignore` | fix the code; name the rule and add `-- why` (ESLint) / 10+ characters after `@ts-expect-error`; replace `@ts-ignore`                                                                             | Nov 2026 audit, RRDSCRUM-436 |
| read `process.argv[2]` by index                                            | `node:util` `parseArgs` (or commander / yargs)                                                                                                                                                    | Nov 2026 audit, RRDSCRUM-436 |
| say "done" after only the tests you touched                                | run the repo's full check command, incl. `check:guardrails`                                                                                                                                       | TM-01, UPF-20                |
| link, cite or build from a design copy, an old Library or memory           | start from the Design Library hub (`GJXHyxKvFEkyhFgqt9V6D3`) and its area pages; the hub wins over code, repo records and Confluence. A repo's `check:guardrails` fails on the retired Library ID | RRDSCRUM-484                 |

## What CI enforces

`releaseready-guardrails` fails a PR on: git/SHA/tarball/`file:` dependencies and non-`^` internal versions;
tsconfig `paths` into `dist/` or `node_modules`; `strict` turned off; scripts that build in `node_modules`;
re-declared schema-primitive regexes, hand-written WCAG luminance, local `canonical()` digests, local JWT
verification; `@deprecated`/legacy/compatibility markers; skipped tests; ESLint rules turned off without a comment;
dated or ticket headings in READMEs; a tracked `.DS_Store`; tracked `dist/` or `build/` output; a non-generated source file over 1,000 lines;
`@buildproveship/*` installed through an `npm:` alias, an override or a lockfile link or tarball from outside the registry; this skill drifting from the published copy; knip findings; jscpd duplication
over the repo's threshold. The shared ESLint config fails on disable comments without `-- reason`, `@ts-ignore`,
`@ts-expect-error` without a description, and focused (`.only`) tests. Details and the allowlist format:
[references/checks.md](references/checks.md).
