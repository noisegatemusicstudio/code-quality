# Claude Code instructions

Follow the shared agent rules in AGENTS.md.

@AGENTS.md

## Code quality (all changes)

Follow `skills/buildproveship-code-quality/SKILL.md` before writing code and before saying a change is done: no legacy
or compatibility code without a named consumer; search npm, the SDK, the framework or the CLI before writing a
helper; import shared code from `@releaseready/test-management`, TDM `dev-fixtures`, `@releaseready/config`,
`@releaseready/ui-web` or `@releaseready/tokens`, never copy it; depend on published `^` versions only; never weaken
a lint rule, test or guard to go green, and give every disable comment a reason; READMEs describe today's code.
The check commands are `npm run check` and `npm run check:guardrails`; `ci.yml` enforces the guardrails on every PR.
