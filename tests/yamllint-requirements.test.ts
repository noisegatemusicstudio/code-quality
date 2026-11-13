/*
Test classification: contract
Review status: Not Reviewed
Evidence: real
Scope: Checks scanners/yamllint-requirements.txt against wheel sha256 values recorded from the PyPI JSON API (tests/fixtures/yamllint-wheel-hashes.json) so every pin carries a hash for each supported Linux platform (x86_64 and aarch64, CPython 3.10-3.14); makes no network call and does not run pip.
*/
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

type Wheels = Partial<Record<string, string>>;
type WheelHashes = Record<string, Wheels>;

const PYTHONS = ['cp310', 'cp311', 'cp312', 'cp313', 'cp314'];
const ARCHES = ['x86_64', 'aarch64'];

/** Parses `name==version \ --hash=sha256:...` blocks into pin -> hashes. */
export function parseHashPins(text: string): Map<string, string[]> {
  const pins = new Map<string, string[]>();
  for (const block of text.split(/\n(?=\S)/)) {
    const pin = /^([A-Za-z0-9_.-]+==\S+)/.exec(block)?.[1];
    if (pin === undefined) continue;
    pins.set(
      pin,
      [...block.matchAll(/--hash=sha256:([0-9a-f]{64})/g)].map((m) => m[1]),
    );
  }
  return pins;
}

/** Wheel keys a pin must cover that the lock does not hold a hash for. */
export function missingWheelHashes(
  lockHashes: readonly string[],
  wheels: Wheels,
): string[] {
  const universal = wheels['py3-none-any'];
  if (universal !== undefined)
    return lockHashes.includes(universal) ? [] : ['py3-none-any'];
  return PYTHONS.flatMap((py) => ARCHES.map((arch) => `${py}-${arch}`)).filter(
    (key) => wheels[key] === undefined || !lockHashes.includes(wheels[key]),
  );
}

const fixture = JSON.parse(
  await readFile(
    new URL('../../tests/fixtures/yamllint-wheel-hashes.json', import.meta.url),
    'utf8',
  ),
) as WheelHashes;
const lock = parseHashPins(
  await readFile(
    new URL('../../scanners/yamllint-requirements.txt', import.meta.url),
    'utf8',
  ),
);

await test('missingWheelHashes reports a platform whose hash the lock lacks', () => {
  const wheels = Object.fromEntries(
    PYTHONS.flatMap((py, i) =>
      ARCHES.map((arch, j) => [
        `${py}-${arch}`,
        `h${String(i)}${String(j)}`.padEnd(64, '0'),
      ]),
    ),
  );
  const all = Object.values(wheels);
  assert.deepEqual(missingWheelHashes(all, wheels), []);
  // The regression: aarch64 cp313 wheel hash absent from the lock.
  const without = all.filter((h) => h !== wheels['cp313-aarch64']);
  assert.deepEqual(missingWheelHashes(without, wheels), ['cp313-aarch64']);
  assert.deepEqual(missingWheelHashes([], wheels).length, all.length);
});

await test('missingWheelHashes requires the universal wheel hash for pure-Python pins', () => {
  const wheels = { 'py3-none-any': 'a'.repeat(64) };
  assert.deepEqual(missingWheelHashes(['a'.repeat(64)], wheels), []);
  assert.deepEqual(missingWheelHashes(['b'.repeat(64)], wheels), [
    'py3-none-any',
  ]);
});

await test('yamllint lock pins exactly the packages the recorded wheel hashes describe', () => {
  assert.deepEqual([...lock.keys()].sort(), Object.keys(fixture).sort());
});

await test('every pinned package has a hash for each supported platform wheel', () => {
  for (const [pin, hashes] of lock)
    assert.deepEqual(missingWheelHashes(hashes, fixture[pin]), [], pin);
});

await test('the lock holds no hash beyond the recorded wheels', () => {
  for (const [pin, hashes] of lock)
    assert.deepEqual(
      hashes.filter((h) => !Object.values(fixture[pin]).includes(h)),
      [],
      pin,
    );
});
