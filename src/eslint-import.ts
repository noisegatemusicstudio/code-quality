export type EslintImport =
  { status: 'parsed'; findingCount: number } | { status: 'invalid' };
/** Parsing is not producer completion, execution proof, or a quality gate. */
export function parseEslintJson(raw: unknown): EslintImport {
  const invalid: EslintImport = { status: 'invalid' };
  if (
    typeof raw !== 'string' ||
    raw.length > 262144 ||
    new TextEncoder().encode(raw).length > 262144
  )
    return invalid;
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return invalid;
  }
  const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);
  const ownCount = (
    item: Record<string, unknown>,
    key: string,
  ): number | null => {
    if (!Object.hasOwn(item, key)) return null;
    const value = item[key];
    return typeof value === 'number' &&
      Number.isSafeInteger(value) &&
      value >= 0
      ? value
      : null;
  };
  if (!Array.isArray(root) || root.length > 1000) return invalid;
  let findingCount = 0;
  let messageCount = 0;
  for (const file of root) {
    if (
      !isRecord(file) ||
      !Object.hasOwn(file, 'messages') ||
      !Object.hasOwn(file, 'suppressedMessages') ||
      !Array.isArray(file.messages) ||
      !Array.isArray(file.suppressedMessages)
    )
      return invalid;
    messageCount += file.messages.length + file.suppressedMessages.length;
    if (messageCount > 10000) return invalid;
    const errors = ownCount(file, 'errorCount');
    const warnings = ownCount(file, 'warningCount');
    const fatals = ownCount(file, 'fatalErrorCount');
    const fixableErrors = ownCount(file, 'fixableErrorCount');
    const fixableWarnings = ownCount(file, 'fixableWarningCount');
    if (
      errors === null ||
      warnings === null ||
      fatals === null ||
      fixableErrors === null ||
      fixableWarnings === null ||
      fixableErrors > errors ||
      fixableWarnings > warnings
    )
      return invalid;
    let derivedErrors = 0;
    let derivedWarnings = 0;
    let derivedFatals = 0;
    for (const message of file.messages) {
      if (
        !isRecord(message) ||
        !Object.hasOwn(message, 'severity') ||
        (message.severity !== 1 && message.severity !== 2)
      )
        return invalid;
      if (Object.hasOwn(message, 'fatal')) {
        if (
          typeof message.fatal !== 'boolean' ||
          (message.fatal && message.severity !== 2)
        )
          return invalid;
        if (message.fatal) derivedFatals++;
      }
      if (message.severity === 2) derivedErrors++;
      else derivedWarnings++;
    }
    if (
      errors !== derivedErrors ||
      warnings !== derivedWarnings ||
      fatals !== derivedFatals
    )
      return invalid;
    findingCount += file.messages.length;
  }
  return { status: 'parsed', findingCount };
}
