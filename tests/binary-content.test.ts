// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: content-based binary classification of in-memory byte arrays; it does not read files, run Git or run any scanner.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { binaryProbeBytes, isBinaryContent } from '../src/binary-content.js';

const bytes = (...v: number[]) => Uint8Array.from(v);
const text = (s: string) => new TextEncoder().encode(s);

await test('a NUL byte in the first 8 KiB makes content binary', () => {
  assert.equal(isBinaryContent(bytes(0x61, 0, 0x62)), true);
});
await test('a NUL after the probe window does not', () => {
  const data = new Uint8Array(binaryProbeBytes + 10).fill(0x61);
  data[binaryProbeBytes + 5] = 0;
  assert.equal(isBinaryContent(data), false);
});
await test('known image, PDF and font signatures with non-text bytes are binary', () => {
  assert.equal(isBinaryContent(bytes(0xff, 0xd8, 0xff, 0xe0, 0x10)), true);
  assert.equal(
    isBinaryContent(
      Uint8Array.from([...text('%PDF-1.7\n%'), 0xe2, 0xe3, 0xcf, 0xd3]),
    ),
    true,
  );
  assert.equal(
    isBinaryContent(Uint8Array.from([...text('GIF89a'), 0x01, 0x02, 0x80])),
    true,
  );
  assert.equal(
    isBinaryContent(
      Uint8Array.from([...text('RIFF'), 1, 2, 3, 4, ...text('WEBPVP8 ')]),
    ),
    true,
  );
  assert.equal(
    isBinaryContent(Uint8Array.from([...text('wOF2'), 0x80, 0x81])),
    true,
  );
});
await test('plain text is not binary, whatever it is named, including text that starts with a signature', () => {
  assert.equal(isBinaryContent(text('{"openapi":"3.0.0"}\n')), false);
  assert.equal(
    isBinaryContent(text('%PDF-1.4 text only\nsecret=abc\n')),
    false,
  );
  assert.equal(isBinaryContent(text('GIF89a plain words\n')), false);
  assert.equal(isBinaryContent(text('café ☃\n\t')), false);
  assert.equal(isBinaryContent(new Uint8Array()), false);
});
await test('non-UTF-8 bytes without a signature or NUL are not classified binary', () => {
  assert.equal(isBinaryContent(bytes(0xff, 0xfe, 0x41)), false);
});
