# Where shared code lives

Import from these; never copy. If what you need is not exported, add it to the owning repo, release a new version and
then import it. Everything is on GitHub Packages (`@buildproveship:registry=https://npm.pkg.github.com`).

| What                                                                  | Import                                                   | Owning repo                    |
| --------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------ |
| `reference`, `revision`, `uuid`, `digest`, `object` schema primitives | `@buildproveship/test-management/schema/v1`              | test-management                |
| canonical JSON and its SHA-256 digest                                 | `@buildproveship/test-management/canonical/v1`           | test-management                |
| JWT/OIDC verifier (incl. Cognito)                                     | `@buildproveship/test-management/identity/v1`            | test-management                |
| SQLite open helper (application_id fence, 0600, busy_timeout)         | `@buildproveship/test-management/sqlite/v1`              | test-management                |
| OpenAPI contract comparator, `releaseready-setup-oasdiff`             | `@buildproveship/test-management/contract-comparator/v1` | test-management                |
| Gherkin case-ID derivation                                            | `@buildproveship/test-management/gherkin-cases/v1`       | test-management                |
| contract types (`DraftScope`, `ConfigurationVersion`, …)              | `@buildproveship/test-management/contracts/v1`           | test-management                |
| seeded Dev accounts, codes, invitations                               | `@buildproveship/test-data-management/dev-fixtures/v1`   | test-data-management           |
| ESLint, Prettier, tsconfig base, Renovate preset, guardrails          | `@buildproveship/config`                                 | config                         |
| v8 components and CSS                                                 | `@buildproveship/ui-web/v8`                              | frontend-ui                    |
| design tokens, status registry                                        | `@buildproveship/tokens`                                 | frontend-ui                    |
| Playwright/Cucumber execution framework                               | `@buildproveship/playwright-framework`                   | universal-playwright-framework |
| WCAG contrast maths                                                   | `colorjs.io` (npm)                                       | —                              |

Check the package's `exports` in its `package.json` for the exact subpaths of the version you depend on.

## Inside one repo

The same applies within a repo: one Ajv instance, one loopback-server test fixture, one `sha256` helper, one config
per tool (Cucumber profiles in one file, one tsconfig base the others extend). When you find a second copy, extract
one module and point both callers at it in the same PR.
