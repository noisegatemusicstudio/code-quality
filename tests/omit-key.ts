// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: test helper that copies an object without one key; no production code.
export function omitKey(
  source: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  return Object.fromEntries(Object.entries(source).filter(([k]) => k !== key));
}
