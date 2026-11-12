// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: lookup returns present values and undefined for missing keys; nothing else.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { lookup } from '../src/lookup.js';
import { omitKey } from './omit-key.js';

await test('lookup returns a present value and undefined for a missing key', () => {
  assert.equal(lookup({ a: 1 }, 'a'), 1);
  assert.equal(lookup({ a: 1 }, 'b'), undefined);
  assert.equal(lookup({ 3: 'x' }, 3), 'x');
  assert.equal(lookup({}, 7), undefined);
});

await test('omitKey drops only the named key and leaves the source intact', () => {
  const source = { a: 1, b: 2 };
  assert.deepEqual(omitKey(source, 'a'), { b: 2 });
  assert.deepEqual(omitKey(source, 'missing'), { a: 1, b: 2 });
  assert.deepEqual(source, { a: 1, b: 2 });
});
