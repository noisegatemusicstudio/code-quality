# Scoped ESLint code-quality adapter

`runEslintScan` (`/eslint-adapter`) lints customer JavaScript and TypeScript with
the repository's **bundled, approved** ESLint configuration only
(`src/eslint-scan-config.ts`; ESLint 10.13.0, typescript-eslint 8.72.1, see
`scanner-licensing.md`). The installed versions must equal these pins or nothing
runs.

## Supported scope

| Files         | Parser / rules                                                 |
| ------------- | -------------------------------------------------------------- |
| `.js`, `.mjs` | espree, ES latest, ESM; `@eslint/js` recommended               |
| `.cjs`        | espree, ES latest, CommonJS; `@eslint/js` recommended          |
| `.ts`, `.mts` | typescript-eslint parser, ESM; JS recommended + TS recommended |
| `.cts`        | typescript-eslint parser, CommonJS; same rules                 |

Everything else (`.jsx`, `.tsx`, other languages, JSON) is listed under
`unsupportedFiles`, never silently dropped. `node_modules`, `dist`, `build`,
`coverage`, `vendor` and `*.min.js` are excluded and listed. No TypeScript project
or transpilation is needed, so type-aware rules are not run. No browser or Node
globals are configured and `no-undef` is off. Inline `eslint-*` comments are
ignored (`noInlineConfig`), so customer code cannot disable rules.

## Safety limits

- A customer `eslint.config.*`, `.eslintrc*` or `.eslintignore` in the request is
  never loaded: the run is `skipped` with `customer-config-rejected`. Customer
  plugins are never installed or executed. A trusted isolated customer runner is
  a separate, future path.
- Never `--fix`. Findings are advice; this code never modifies customer files.
- Limits come from `runAdapter` (files, size, timeout, output) and the envelope
  (5000 findings). Oversize or inconsistent ESLint output fails closed.
- A file ESLint cannot parse is reported under `parseFailures` and makes the run
  `incomplete`/`parse-failure`: it is never counted as clean.
- No files means `skipped`/`no-supported-files`, not a clean result.

## What the result means

The envelope keeps the native rule id and severity. `report.analysis` is always
`lint` and `report.notAnalysed` lists `sast`, `dependencies`, `coverage` and
`duplication`: lint-clean says nothing about those. Rule, parser and plugin
versions are in `report.versions`; the envelope records the ESLint version,
`rulesetVersion` (`typescript-eslint-<version>`) and `configVersion`.

## Stable identity and comparison

Fingerprints hash engine, rule, path and the whitespace-normalised source of the
flagged range (first 200 characters) plus an occurrence index, so unrelated line
shifts keep the same id while edits to the flagged code change it.
`compareFindings(baseline, current)` (`/finding-compare`) returns `new`,
`existing` and `resolved`. It only compares adapter-executed runs with the same
tenant, project, repository, source, engine, ruleset and config version. A
`resolved` list is empty unless the current run `completed`; an incomplete
baseline yields `unclassified` instead of `new`.
