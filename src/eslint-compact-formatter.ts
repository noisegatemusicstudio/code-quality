/*
 * ESLint formatter used only by the hosted scan. ESLint's built-in `json`
 * formatter embeds each file's full `source` text and every message's `fix` and
 * `suggestions`. The scan never reads them, but they dominated the output
 * (about 78% on one real repository) and pushed it past the parser's size cap,
 * which made a working ESLint run `failed` (`invalid-output`).
 *
 * This keeps exactly the fields `parseEslintJson` validates and the adapter
 * reads, in the same shape, so the output stays a valid ESLint JSON report.
 * Suppressed messages are dropped (the scan discards them) but the per-file
 * counts are kept as ESLint reported them.
 */
interface Message {
  ruleId?: unknown;
  severity?: unknown;
  fatal?: unknown;
  message?: unknown;
  line?: unknown;
  column?: unknown;
  endLine?: unknown;
  endColumn?: unknown;
}
interface Result {
  filePath?: unknown;
  messages?: unknown;
  errorCount?: unknown;
  warningCount?: unknown;
  fatalErrorCount?: unknown;
  fixableErrorCount?: unknown;
  fixableWarningCount?: unknown;
}

const compactMessage = (m: Message): Message => ({
  ruleId: m.ruleId,
  severity: m.severity,
  ...(m.fatal === undefined ? {} : { fatal: m.fatal }),
  message: m.message,
  line: m.line,
  column: m.column,
  endLine: m.endLine,
  endColumn: m.endColumn,
});

export default function compactFormatter(results: readonly Result[]): string {
  return JSON.stringify(
    results.map((r) => ({
      filePath: r.filePath,
      messages: Array.isArray(r.messages)
        ? (r.messages as Message[]).map(compactMessage)
        : [],
      suppressedMessages: [],
      errorCount: r.errorCount,
      fatalErrorCount: r.fatalErrorCount,
      warningCount: r.warningCount,
      fixableErrorCount: r.fixableErrorCount,
      fixableWarningCount: r.fixableWarningCount,
    })),
  );
}
