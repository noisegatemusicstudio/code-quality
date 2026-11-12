# Scanner licensing review (RRDSCRUM-61, gates RRDSCRUM-128..136)

Research only. Nothing here was installed, run or scanned. Reviewed 2026-11-12.
This is an engineering licence summary, **not legal advice**; counsel must confirm
anything marked "proceed" before first redistribution.

Rules used: a claim without a primary URL is `unknown`; `unknown` blocks inclusion.
Sonar analyzers and third-party SAST rules are **not** assumed embeddable.
"Redistribute" = ship the tool/rules/data inside the ReleaseReady product or its
CI images. "Hosted" = run it for customers inside a ReleaseReady-operated service.
The initial product model is customer-run (local / customer CI, RRDSCRUM-126),
where ReleaseReady redistributes nothing and the customer installs the tool.

Versions are the latest stable found on the date above (git tags via `git ls-remote`,
npm via the registry). Where they differ from our pin, both are shown.

## Summary

| Candidate                  | Version                                           | Engine              | Rules / data                                                             | Recommendation                                                                                     |
| -------------------------- | ------------------------------------------------- | ------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| ESLint + typescript-eslint | 10.13.0 / 8.72.1 pinned (latest 10.14.0 / 8.72.2) | MIT                 | Rules ship in the packages (MIT)                                         | **Proceed**                                                                                        |
| Gitleaks CLI               | v8.30.1                                           | MIT                 | Default config shipped in the repo (MIT)                                 | **Proceed** (CLI only)                                                                             |
| Gitleaks Action            | see below                                         | Proprietary EULA    | n/a                                                                      | **Reject**                                                                                         |
| OSV-Scanner                | v2.7.1                                            | Apache-2.0          | OSV data: per-source, mixed incl. NC/SA                                  | **Proceed** scanner; **Defer** bundling data                                                       |
| Trivy                      | v0.76.2                                           | Apache-2.0          | Misconfig checks MIT; vuln DB data terms unknown                         | **Proceed** scanner; **Defer** DB/bundle                                                           |
| Semgrep CE engine          | v1.185.0                                          | LGPL-2.1            | Semgrep-maintained rules: Semgrep Rules License v1.0 (internal use only) | **Proceed** engine (LGPL review); **Reject** Semgrep rules in product; **Defer** third-party rules |
| CodeQL                     | CLI v2.27.4                                       | GitHub CodeQL Terms | restricted                                                               | **Reject**                                                                                         |
| jscpd                      | 5.4.3                                             | MIT                 | n/a                                                                      | **Proceed**                                                                                        |
| Istanbul coverage formats  | istanbul-reports 3.2.0 (we parse 3.1.7 dialect)   | BSD-3-Clause        | n/a                                                                      | **Proceed**                                                                                        |

## Per candidate

### ESLint and typescript-eslint

- Version: ESLint 10.13.0, typescript-eslint 8.72.1 (pinned in `package.json`); latest on npm 10.14.0 and 8.72.2 ([eslint](https://registry.npmjs.org/eslint/latest), [typescript-eslint](https://registry.npmjs.org/typescript-eslint/latest)).
- Engine licence: MIT ([ESLint](https://raw.githubusercontent.com/eslint/eslint/main/LICENSE), [typescript-eslint](https://raw.githubusercontent.com/typescript-eslint/typescript-eslint/main/LICENSE)). Rules are part of the same MIT packages. Data: none.
- Redistribution: yes. Hosted SaaS: yes (MIT grants use, copy, modify, publish, distribute, sublicense, sell).
- Notices: keep the MIT copyright and permission notice for each package. Transitive dependency licences are **unknown** until an SBOM/licence scan of the lockfile is done (follow-up).
- Recommendation: **Proceed**. Third-party ESLint plugins/configs need their own review before inclusion; none are approved here.

### Gitleaks CLI (evaluated separately from the Action)

- Version: v8.30.1 ([tags](https://github.com/gitleaks/gitleaks/tags)).
- Licence: MIT ([LICENSE](https://raw.githubusercontent.com/gitleaks/gitleaks/master/LICENSE)). The default rule config lives in the same repository under that licence; a separate rule-licence file was not verified, so treat custom/third-party rule packs as `unknown`.
- Redistribution and hosted use: allowed under MIT. Notice: MIT copyright text.
- Recommendation: **Proceed** (CLI binary, customer-run first).

### Gitleaks Action

- Licence: Gitleaks-Action EULA, not MIT, since v2.0.0 ([README](https://raw.githubusercontent.com/gitleaks/gitleaks-action/master/README.md), [LICENSE.txt](https://raw.githubusercontent.com/gitleaks/gitleaks-action/master/LICENSE.txt)). Organisation accounts need a licence key; the EULA bars redistributing it as part of a product (2.1(b)), modifying it or incorporating it (2.1(d)).
- Recommendation: **Reject**. Call the MIT CLI directly instead.

### OSV-Scanner and OSV data

- Version: v2.7.1 ([tags](https://github.com/google/osv-scanner/tags)). Engine: Apache-2.0 ([LICENSE](https://raw.githubusercontent.com/google/osv-scanner/main/LICENSE)); OSV.dev code is also Apache-2.0 ([LICENSE](https://raw.githubusercontent.com/google/osv.dev/master/LICENSE)).
- Data: OSV aggregates many sources, each with its own licence: CC-BY 4.0, CC0, MIT, Apache-2.0, **CC-BY-SA 4.0** (Ubuntu, Alpine) and **CC-BY-NC-ND 4.0** (Chainguard, with a separate commercial-scanner licence) ([data sources](https://raw.githubusercontent.com/google/osv.dev/master/docs/data.md)). A single blanket licence for the whole database is `unknown`.
- Redistribution: engine yes (Apache-2.0, keep LICENSE/NOTICE). Bundling a data snapshot: **blocked** (NC/ND/SA sources; attribution duties). Hosted: engine yes; data use `unknown` for the NC/ND sources.
- Notices: Apache-2.0 notices; CC-BY attribution per source if data is shown or shipped. The existing `src/osv-schema-LICENSE.txt` / `NOTICE.txt` cover the schema only.
- Recommendation: **Proceed** with the scanner run by the customer against online OSV; **Defer** any bundled/mirrored data until source-by-source terms are cleared.

### Trivy, vulnerability DB and misconfig rules

- Version: v0.76.2 ([tags](https://github.com/aquasecurity/trivy/tags)). Engine: Apache-2.0 ([LICENSE](https://raw.githubusercontent.com/aquasecurity/trivy/main/LICENSE)).
- Misconfig checks (`trivy-checks`): MIT ([LICENSE](https://raw.githubusercontent.com/aquasecurity/trivy-checks/main/LICENSE)).
- Vulnerability DB: `trivy-db` code is Apache-2.0 ([LICENSE](https://raw.githubusercontent.com/aquasecurity/trivy-db/main/LICENSE)), but the DB content is aggregated from NVD, Red Hat, Debian etc. ([README](https://raw.githubusercontent.com/aquasecurity/trivy-db/main/README.md)). The terms of the published DB artefact and of each upstream feed were **not verified: unknown**.
- Redistribution: engine and checks yes. DB mirror/bundle: **unknown, blocked**. Hosted: engine yes; DB `unknown`.
- Notices: Apache-2.0 and MIT notices.
- Recommendation: **Proceed** with engine and checks, customer-run; **Defer** DB redistribution or hosted DB mirroring.

### Semgrep CE engine and Semgrep Registry rules

Sources: dated captures (2026-11-12, 07:41 UTC) of the [Rules License](https://semgrep.dev/legal/rules-license/) (page "Last updated December 13th, 2024") and the [licensing summary](https://docs.semgrep.dev/licensing). The captures were read in full by the author of this doc; the quotes below were checked against them (PDFs are held by the project owner, not in this repo). The [Semgrep terms](https://semgrep.dev/legal/terms/) and the [engine licence](https://github.com/semgrep/semgrep/blob/develop/LICENSE) quotes were relayed by the owner and are **not** re-verified. Version: Semgrep CE v1.185.0 ([tags](https://github.com/semgrep/semgrep/tags)).

**Engine (standalone CE): proceed subject to LGPL compliance review.**

- LGPL-2.1. The Semgrep terms exclude the "Semgrep OSS Engine" from their proprietary Software definition and say it is licensed under LGPL 2.1. The engine licence states: "The act of running a program using the Library is not restricted".
- No blanket ban on commercial use of the standalone engine was found. Shipping it needs a packaging-specific LGPL review (notices, source/modification and relinking obligations). Hosted use of the engine alone: allowed in principle, same review.
- CE is feature-limited (taint is "Single file, single-function taint" per Semgrep's comparison); it is not equivalent to Semgrep Pro. This grants no rights to Semgrep-maintained rules or proprietary services.

**Semgrep-maintained rules (Rules License v1.0): do not use in the customer product.**

- Licence text (verified): "You may use the rules only for your own internal business purposes. This license does not allow you to distribute the rules, or to make them available to others as a service." The licence is also non-sublicensable and non-transferable.
- Summary text (verified): "Vendors cannot use Semgrep-maintained rules in competing products or SaaS offerings." It applies to "all rules, which includes both Community and Pro rules, listed in the semgrep-rules repository".
- Notices: licensor notices must not be altered, removed or obscured and must be kept in any copy; modified copies need a prominent modification notice. Patent licence ends if you or your company make a written patent-infringement claim against the rules or any Semgrep product. "Your company" includes affiliates under common control.
- Violating use is unlicensed and the licences terminate automatically.
- Semgrep invites commercial arrangements: "If you are interested in using Semgrep products for your own solutions and code analysis tools, send us an email at partnerships@semgrep.com". Use this route for the customer-run-CI and hosted questions.

| Use                                                                             | Status                                                                                                                                     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Scanning ReleaseReady's own repositories                                        | Permitted as internal business use, subject to the licence's other terms                                                                   |
| Hosted customer scans                                                           | Not permitted without separate written permission from Semgrep                                                                             |
| Shipping/copying rules into the repo or product                                 | Conflicts with the distribution restriction; no overriding notice/attribution found. Internal-only copies: check the full dated copy first |
| Customer-run CI that downloads the rules, with ReleaseReady integrating results | Not expressly resolved by the text: unknown. Obtain Semgrep's written permission before relying on it                                      |
| Meaning of "competing"                                                          | Not precisely defined; a customer-facing code-quality/SAST product is a clear risk and must not be assumed permitted. Legal question       |

**Third-party Registry rules:** inherit the licences of their source repositories (verified; the summary cites Trail of Bits rules under AGPL-3.0 as an example, so copyleft can apply). No rule IDs or packs are proposed yet, so licences are unknown. Each rule and its source/version needs individual review; neither blanket approval nor blanket rejection is supported.

**Recommendation:** standalone CE engine **Proceed (conditional on LGPL review)**; Semgrep-maintained rules in the customer product **Reject unless Semgrep grants written permission**; third-party rules **Defer, per-rule review**. Interpretations above are the owner's, not legal advice; counsel confirms the competing-use boundary.

### CodeQL

- Version: CLI v2.27.4 ([tags](https://github.com/github/codeql-cli-binaries/tags)). Licence: GitHub CodeQL Terms and Conditions ([LICENSE.md](https://raw.githubusercontent.com/github/codeql-cli-binaries/main/LICENSE.md)).
- Confirmed not usable for us: free use is limited to academic research, demos, and analysis of OSI-licensed open-source codebases (database generation in CI only if hosted on GitHub.com); analysing any non-open-source codebase or generating databases in other automated/CI contexts is excluded. Customer private code is therefore out, and the licence is per user.
- Redistribution and hosted use: no. Recommendation: **Reject** (a commercial GitHub licence would be a separate paid decision, out of scope).

### jscpd (duplication)

- Version: 5.4.3 ([npm](https://registry.npmjs.org/jscpd/latest)). Licence: MIT ([LICENSE](https://raw.githubusercontent.com/kucherenko/jscpd/master/LICENSE)). No rules or data.
- Redistribution and hosted use: yes. Notice: MIT text; transitive licences `unknown` until a lockfile scan.
- Recommendation: **Proceed**.

### hadolint, tflint, yamllint, markdownlint-cli2 (language-profiles slices 5, 6, 10)

Added 2026-11-12. Licences are from `docs/language-profiles.md` (upstream LICENSE first lines on the review date); not legal advice and not re-verified here. All four run as separate, unmodified, unbundled tools from pinned, hash-verified installs, with bundled default configuration only.

| Tool              | Version                      | Licence | Install                                                        | Status                                                        |
| ----------------- | ---------------------------- | ------- | -------------------------------------------------------------- | ------------------------------------------------------------- |
| hadolint          | 2.15.1                       | GPL-3.0 | release binary, sha256 in `src/scanner-pins.ts`                | internal OK, **customer: needs review**                       |
| yamllint          | 1.38.0                       | GPL-3.0 | `pip --require-hashes` (`scanners/yamllint-requirements.txt`)  | internal OK, **customer: needs review**                       |
| tflint            | 0.66.0                       | MPL-2.0 | release zip, asset and binary sha256 pinned                    | internal OK, customer OK (unmodified binary, keep MPL notice) |
| markdownlint-cli2 | 0.24.1 (markdownlint 0.42.1) | MIT     | npm, `package-lock.json` integrity, entry script sha256 pinned | internal OK, customer OK                                      |

Rules: hadolint and yamllint stay separate executables invoked as processes; do not bundle, link or ship them to customers until counsel confirms (slice 14 of `docs/language-profiles.md`). tflint uses its built-in terraform ruleset only: no `tflint --init`, no plugin download.

### Istanbul coverage formats

- Version: istanbul-reports 3.2.0 and istanbul-lib-coverage 3.2.2 are latest, BSD-3-Clause ([reports](https://registry.npmjs.org/istanbul-reports/latest), [lib-coverage](https://registry.npmjs.org/istanbul-lib-coverage/latest)); the repo imports the 3.1.7 JSON-summary dialect. The upstream BSD text seen is the legacy istanbul one ([LICENSE](https://raw.githubusercontent.com/gotwarlost/istanbul/master/LICENSE)); the current istanbuljs LICENSE file URL was not verified.
- We only parse a JSON shape; if we ship no Istanbul code, no notice duty arises. If we ship the libraries: BSD-3 notice, redistribution and hosted use allowed. Whether the data format itself carries any claim: no evidence of one, not formally reviewed.
- Recommendation: **Proceed** (parse only).

## Consequences for RRDSCRUM-128..136

- Approved for the first adapters: ESLint/typescript-eslint, Gitleaks CLI, OSV-Scanner (online data), Trivy engine and checks, jscpd, Istanbul JSON import.
- Blocked on legal/verification: bundled OSV data, Trivy DB, Semgrep LGPL packaging review and per-rule third-party review, any third-party ESLint plugin, transitive licence scan.
- Not usable: CodeQL, Gitleaks Action, Semgrep-maintained rules. RRDSCRUM-133 (SAST engines and licensed rules) must start from our own rules or a separately licensed pack.
- No Sonar analyzer is embeddable; ReleaseReady's own Sonar work stays under RRDPLAT-22/29.
- Re-check versions and licences at integration time; this table is a dated snapshot.

## Language-profile engines (reviewed 2026-11-12, not installed or run)

Candidates for the slices in `docs/language-profiles.md`. Licence = first lines of
the upstream `LICENSE`; versions are latest stable tags, not pins. All are run as
separate, unbundled binaries; nothing is redistributed.

| Engine              | Version         | Licence                                                 | Recommendation                                   |
| ------------------- | --------------- | ------------------------------------------------------- | ------------------------------------------------ |
| Ruff                | 0.17.4          | MIT                                                     | **Proceed**                                      |
| mypy / pyright      | 2.4.1 / 1.1.414 | MIT / MIT                                               | **Proceed**                                      |
| PMD                 | 7.29.0          | BSD-style                                               | **Proceed** (keep notice)                        |
| Checkstyle          | 14.4.0          | LGPL-2.1                                                | Internal **proceed**; customer **needs review**  |
| SpotBugs            | 4.10.5          | LGPL-2.1                                                | Internal **proceed**; customer **needs review**  |
| FindSecBugs         | 1.14.0          | LGPL-3.0                                                | Internal **proceed**; customer **needs review**  |
| detekt              | 1.23.8          | Apache-2.0                                              | **Proceed**                                      |
| ktlint              | 1.8.0           | MIT                                                     | **Proceed**                                      |
| SwiftLint           | 0.65.1          | MIT                                                     | **Proceed**                                      |
| ShellCheck          | 0.11.0 (pinned) | GPL-3.0                                                 | Internal **proceed**; **customer: needs review** |
| shfmt               | 3.14.1 (pinned) | BSD-3-Clause                                            | **Proceed**                                      |
| hadolint            | 2.15.1          | GPL-3.0                                                 | Internal **proceed**; customer **needs review**  |
| tflint              | 0.66.0          | MPL-2.0                                                 | **Proceed** (unmodified, keep notice)            |
| actionlint          | 1.7.12 (pinned) | MIT                                                     | **Proceed**                                      |
| zizmor              | 1.32.0 (pinned) | MIT                                                     | **Proceed**                                      |
| yamllint            | 1.38.0          | GPL-3.0                                                 | Internal **proceed**; customer **needs review**  |
| markdownlint / cli2 | 0.42.1 / 0.24.1 | MIT                                                     | **Proceed**                                      |
| Prettier            | 3.9.10          | MIT (package metadata; upstream LICENSE not re-fetched) | **Proceed**                                      |

### ShellCheck, shfmt, actionlint and zizmor (pinned 2026-11-12)

Pinned in `src/scanner-pins.ts` and installed sha256-verified by
`quality-scan.yml` (linux-amd64 release assets). Each runs as a separate,
unmodified binary; nothing is bundled or redistributed.

- **ShellCheck is GPL-3.0: customer: needs review.** Acceptable internally as a
  separate, unbundled binary. Do not bundle, vendor or ship it to customers
  until counsel confirms (slice 14 in `docs/language-profiles.md`). Customer-run
  scans that install it themselves are a counsel question too.
- shfmt (BSD-3-Clause), actionlint (MIT) and zizmor (MIT): keep the upstream
  notices if ever redistributed.
- Checksums: only actionlint publishes an upstream checksum file. ShellCheck,
  shfmt and zizmor publish none for these tags (the usual `sha256sums`,
  `.sha256` names return 404), so their asset and binary digests were computed
  from the official release assets on 2026-11-12. That detects later change and
  corruption, but it is not an independent upstream attestation.
- zizmor runs `--offline`: no GitHub API call and no token.
