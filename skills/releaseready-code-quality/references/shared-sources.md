# Where shared code lives

Import from these; never copy. If what you need is not exported, add it to the owning repo, release a new version and
then import it. Everything is on GitHub Packages (`@releaseready:registry=https://npm.pkg.github.com`).

| What                                                                  | Import                                                 | Owning repo                    |
| --------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------ |
| `reference`, `revision`, `uuid`, `digest`, `object` schema primitives | `@releaseready/test-management/schema/v1`              | test-management                |
| canonical JSON and its SHA-256 digest                                 | `@releaseready/test-management/canonical/v1`           | test-management                |
| JWT/OIDC verifier (incl. Cognito)                                     | `@releaseready/test-management/identity/v1`            | test-management                |
| SQLite open helper (application_id fence, 0600, busy_timeout)         | `@releaseready/test-management/sqlite/v1`              | test-management                |
| OpenAPI contract comparator, `releaseready-setup-oasdiff`             | `@releaseready/test-management/contract-comparator/v1` | test-management                |
| Gherkin case-ID derivation                                            | `@releaseready/test-management/gherkin-cases/v1`       | test-management                |
| contract types (`DraftScope`, `ConfigurationVersion`, …)              | `@releaseready/test-management/contracts/v1`           | test-management                |
| seeded Dev accounts, codes, invitations                               | `@releaseready/test-data-management/dev-fixtures/v1`   | test-data-management           |
| ESLint, Prettier, tsconfig base, Renovate preset, guardrails          | `@releaseready/config`                                 | config                         |
| v8 components and CSS                                                 | `@releaseready/ui-web/v8`                              | frontend-ui                    |
| design tokens, status registry                                        | `@releaseready/tokens`                                 | frontend-ui                    |
| Playwright/Cucumber execution framework                               | `@releaseready/playwright-framework`                   | universal-playwright-framework |
| WCAG contrast maths                                                   | `colorjs.io` (npm)                                     | —                              |

Check the package's `exports` in its `package.json` for the exact subpaths of the version you depend on.

## Inside one repo

The same applies within a repo: one Ajv instance, one loopback-server test fixture, one `sha256` helper, one config
per tool (Cucumber profiles in one file, one tsconfig base the others extend). When you find a second copy, extract
one module and point both callers at it in the same PR.
