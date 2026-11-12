## Quality scan

Commit `0ded5596db29` · mode **advisory** · fail-on-severity **high**

Baseline: none, so no new-vs-baseline split is available.

| Engine | Status | Findings | New | Notes |
| --- | --- | ---: | ---: | --- |
| eslint bundled | incomplete | 0+ | – | invalid-output |
| prettier 3.9.10 | incomplete | 106+ | – | customer-config-rejected: Prettier config that needs repository code was not loaded \(package.json: prettier module\); Prettier defaults were used for the affected files, so formatting findings may differ from the project's own settings |
| gitleaks | failed | – | – | engine not installed |
| osv | failed | – | – | osv-scanner missing or sha256 mismatch |
| trivy | failed | – | – | trivy missing or sha256 mismatch |
| semgrep | failed | – | – | semgrep not installed |
| jscpd | failed | – | – | engine not installed |
| ruff | failed | – | – | ruff is not installed |
| mypy 2.4.1 | skipped | – | – | skipped (unavailable): needs dependency environment: mypy --strict needs the project dependencies installed, and a scan never installs project dependencies or runs project code, so it cannot give a trustworthy result |
| pmd | skipped | – | – | skipped (not-applicable): no Java files |
| checkstyle | skipped | – | – | skipped (not-applicable): no Java files |
| spotbugs | skipped | – | – | skipped (not-applicable): no Java files |
| shellcheck | skipped | – | – | skipped (not-applicable): no shell scripts |
| shfmt | skipped | – | – | skipped (not-applicable): no shell scripts |
| actionlint | failed | – | – | actionlint missing or sha256 mismatch |
| zizmor | failed | – | – | zizmor missing or sha256 mismatch |
| hadolint | skipped | – | – | skipped (not-applicable): no Dockerfile or Containerfile |
| tflint | skipped | – | – | skipped (not-applicable): no Terraform \(.tf\) files |
| yamllint | failed | – | – | yamllint not installed |
| markdownlint | failed | – | – | markdownlint-cli2 not installed |

### Languages

| Language | Files | Status |
| --- | ---: | --- |
| TypeScript | 99 | analysed by eslint, prettier, semgrep |
| JSON | 9 | analysed by prettier |
| Python | 1 | analysed by ruff |
| GitHub Actions | 3 | analysed by actionlint, zizmor |
| YAML | 10 | analysed by prettier, yamllint |
| Markdown | 6 | analysed by prettier, markdownlint |

"skipped: no engine yet" means no language-specific analysis ran. It is not a clean result.


### Not a clean result

These engines did not complete. "–" above means no result, not zero findings.

- **eslint**: incomplete (invalid-output)
- **prettier**: incomplete (customer-config-rejected: Prettier config that needs repository code was not loaded \(package.json: prettier module\); Prettier defaults were used for the affected files, so formatting findings may differ from the project's own settings)
- **gitleaks**: failed (engine not installed)
- **osv**: failed (osv-scanner missing or sha256 mismatch)
- **trivy**: failed (trivy missing or sha256 mismatch)
- **semgrep**: failed (semgrep not installed)
- **jscpd**: failed (engine not installed)
- **ruff**: failed (ruff is not installed)
- **mypy**: skipped (needs dependency environment: mypy --strict needs the project dependencies installed, and a scan never installs project dependencies or runs project code, so it cannot give a trustworthy result)
- **pmd**: skipped (no Java files)
- **checkstyle**: skipped (no Java files)
- **spotbugs**: skipped (no Java files)
- **shellcheck**: skipped (no shell scripts)
- **shfmt**: skipped (no shell scripts)
- **actionlint**: failed (actionlint missing or sha256 mismatch)
- **zizmor**: failed (zizmor missing or sha256 mismatch)
- **hadolint**: skipped (no Dockerfile or Containerfile)
- **tflint**: skipped (no Terraform \(.tf\) files)
- **yamllint**: failed (yamllint not installed)
- **markdownlint**: failed (markdownlint-cli2 not installed)

### Top rules

- **prettier**: prettier/format (106)

### New-code measures

No comparison base, so new code could not be determined.

| Measure | Result | Lines |
| --- | --- | --- |
| coverage.lines | unknown: no coverage report supplied | – |
| coverage.branches | unknown: no coverage report supplied | – |
| duplication.lines | unknown: no comparison base \(not a pull request and no base ref given\) | – |

### Gate

Would fail in enforce mode: failed or incomplete: eslint, gitleaks, osv, trivy, semgrep, jscpd, ruff, actionlint, zizmor, yamllint, markdownlint.
Advisory mode: this job reports findings but does not fail the pull request.
