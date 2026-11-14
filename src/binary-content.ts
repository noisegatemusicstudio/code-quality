/**
 * Content-based binary classification shared by the committed snapshot and the
 * text-engine input readers. It looks at bytes, never at a file name, so a file
 * called `logo.png` that holds text is text and a file called `data.json` that
 * holds image bytes is binary.
 */

/** How many leading bytes are inspected. */
export const binaryProbeBytes = 8192;

const startsWith = (b: Uint8Array, text: string, at = 0): boolean =>
  b.length >= at + text.length &&
  [...text].every((c, i) => b[at + i] === c.charCodeAt(0));
const startsWithBytes = (b: Uint8Array, bytes: number[]): boolean =>
  b.length >= bytes.length && bytes.every((v, i) => b[i] === v);

/** Known image, PDF and font signatures (PNG, JPEG, GIF, WebP, PDF, WOFF, WOFF2, OpenType). */
export function hasBinaryMagic(head: Uint8Array): boolean {
  return (
    startsWithBytes(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) ||
    startsWithBytes(head, [0xff, 0xd8, 0xff]) ||
    startsWith(head, 'GIF87a') ||
    startsWith(head, 'GIF89a') ||
    (startsWith(head, 'RIFF') && startsWith(head, 'WEBP', 8)) ||
    startsWith(head, '%PDF-') ||
    startsWith(head, 'wOFF') ||
    startsWith(head, 'wOF2') ||
    startsWith(head, 'OTTO')
  );
}

/** True when the bytes are valid UTF-8 with no control characters other than whitespace. */
function isCleanText(head: Uint8Array): boolean {
  try {
    // `stream` tolerates a multi-byte character cut at the end of the probe.
    const text = new TextDecoder('utf-8', { fatal: true }).decode(head, {
      stream: true,
    });
    return !/[\x00-\x08\x0b\x0e-\x1f\x7f]/.test(text);
  } catch {
    return false;
  }
}

/**
 * Binary when the first 8 KiB contain a NUL byte, or start with a known
 * image/PDF/font signature AND are not clean text. The second condition keeps
 * a text file that merely begins with `%PDF-` or `GIF89a` scannable as text, so
 * a signature prefix cannot be used to hide readable secrets.
 */
export function isBinaryContent(bytes: Uint8Array): boolean {
  const head = bytes.subarray(0, binaryProbeBytes);
  if (head.includes(0)) return true;
  return hasBinaryMagic(head) && !isCleanText(head);
}
