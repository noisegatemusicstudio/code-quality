# Semgrep `PartialParsing`: evidence and options

## Cause (confirmed)

Semgrep reports syntax it cannot parse as `errors` entries with `level: "warn"` and type
`PartialParsing`. Before this change `parseSemgrepReport` marked the run `incomplete` with
the misleading reason `engine-error` for any non-empty `errors` array.

Reproduced locally with the pinned Semgrep 1.185.0 (hash-locked install, `rules/semgrep`
config, tracked files in a git repo):

| Syntax                             | Result                                         |
| ---------------------------------- | ---------------------------------------------- |
| `export type * from "./contract";` | `PartialParsing` warn, "`type` was unexpected" |
| `export type { Foo } from "./x"`   | parses                                         |
| `import { type B } from "./c"`     | parses                                         |
| `type X = import("./a").Y`         | parses                                         |

So `export type *` (TypeScript 5.0) is the trigger in `src/jira/panel.ts:4` and
`src/jira/service.ts:6` of test-management, as reported. **Not verified here:** the
`import("./annotations").SourceAnnotations` line in `wire.generated.d.ts` (it parses in the
small repro, so it is probably collateral of another construct in that file or a `.d.ts`
specific form) and the Appium repo's Semgrep errors. This session was denied access to
`releaseready/test-management` and `releaseready/universal-appium2-framework`, so neither
repo nor the Appium report artifact was inspected.

## Newer Semgrep

PyPI's newest `semgrep` is 1.185.0, the current pin, so there is no newer release to bump
to. Whether a future release accepts `export type *` is unknown; re-run the table above
when one ships. A bump would need new hashes in `scanners/semgrep-requirements.txt`,
the `semgrepVersion`/`semgrepPin` constants, and a licence re-check per
`docs/scanner-licensing.md` (LGPL-2.1 engine review; rules licence unchanged).

## Options

- **(a) Bump Semgrep.** Not possible today (see above). Revisit on each release.
- **(b) Report precisely (implemented).** Warn-level `PartialParsing` entries for safe
  relative paths give `incomplete`/`parse-failure` with the file list, like ESLint. Any
  other error, an error-level or level-less entry, or an unsafe path stays `engine-error`.
  The gate still fails: this changes the label and makes it actionable, not the outcome.
- **(c) Policy change so partially parsed files do not fail the gate.** Not implemented.
  It weakens "not clean means not clean": a file Semgrep only partly parsed may hide
  findings, so the rules did not fully run over it. If wanted, the narrowest form is a
  per-repo, per-file entry in `quality-exceptions.json` with an owner and expiry, not an
  engine-wide relaxation.

## Recommendation

Ship (b) now. For test-management, avoid the trigger rather than weaken the gate: replace
`export type * from "./contract"` with explicit `export type { ... } from "./contract"` (or
a namespace re-export) in the two files, then re-scan. Track (a) for the next Semgrep
release; consider (c) only as a time-boxed per-file exception.
