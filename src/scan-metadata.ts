/** Deeply freeze only owned static metadata, never arbitrary caller objects. */
export function immutableMetadata<T extends object>(value: T): Readonly<T> {
  for (const item of Object.values(value as Record<string, unknown>)) {
    if (typeof item === 'object' && item !== null) immutableMetadata(item);
  }
  return Object.freeze(value);
}
