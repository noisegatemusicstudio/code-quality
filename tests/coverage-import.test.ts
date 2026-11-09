import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseCoverageSummary as parse } from '../src/coverage-import.js';
const names = ['lines', 'statements', 'functions', 'branches'] as const;
const metric = () => ({ total: 4, covered: 3, skipped: 2, pct: 'SECRET' });
const input = () => ({
  total: Object.fromEntries(names.map((n) => [n, metric()])),
});
const read = (v: unknown) => parse(JSON.stringify(v));
const invalid = { status: 'invalid' };
await test('inherited root, metric and numeric fields are not read or accepted', () => {
  const cases: { key: string; value: unknown }[] = [
    { key: 'total', value: {} },
  ];
  for (const name of names) {
    const summary: Record<string, unknown> = { ...input().total };
    delete summary[name];
    cases.push({ key: name, value: { total: summary } });
    for (const key of ['total', 'covered', 'skipped']) {
      const m: Record<string, unknown> = { ...metric() };
      delete m[key];
      cases.push({ key, value: { total: { ...input().total, [name]: m } } });
    }
  }
  for (const { key, value } of cases) {
    const raw = JSON.stringify(value);
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, key);
    let reads = 0;
    let result: ReturnType<typeof parse>;
    try {
      Object.defineProperty(Object.prototype, key, {
        configurable: true,
        get() {
          reads++;
          throw new Error('Inherited field must not be read');
        },
      });
      result = parse(raw);
    } finally {
      if (previous) Object.defineProperty(Object.prototype, key, previous);
      else Reflect.deleteProperty(Object.prototype, key);
    }
    assert.equal(reads, 0);
    assert.deepEqual(result, invalid);
  }
});
const expected = (total = 4, covered = 3, skipped = 2) => ({
  status: 'parsed',
  metrics: Object.fromEntries(
    names.map((n) => [
      n,
      {
        total,
        covered,
        skipped,
        percentage: total === 0 ? null : (covered / total) * 100,
      },
    ]),
  ),
});
await test('reads only total, derives percentages, permits independent skipped counts', () => {
  assert.deepEqual(read(input()), expected());
  assert.deepEqual(
    read({
      total: Object.fromEntries(
        names.map((n) => [n, { total: 0, covered: 0, skipped: 0, pct: 100 }]),
      ),
    }),
    expected(0, 0, 0),
  );
  assert.deepEqual(
    read({
      total: Object.fromEntries(
        names.map((n) => [n, { total: 3, covered: 1, skipped: 0, pct: 99 }]),
      ),
    }),
    expected(3, 1, 0),
  );
  assert.deepEqual(
    read({
      total: Object.fromEntries(
        names.map((n) => [n, { total: 1, covered: 0, skipped: 0 }]),
      ),
    }),
    expected(1, 0, 0),
  );
  assert.deepEqual(
    read({
      total: Object.fromEntries(
        names.map((n) => [
          n,
          {
            total: Number.MAX_SAFE_INTEGER,
            covered: Number.MAX_SAFE_INTEGER,
            skipped: 0,
          },
        ]),
      ),
    }),
    expected(Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0),
  );
});
await test('runtime type, malformed JSON and required shapes reject', () => {
  for (const raw of [
    null,
    undefined,
    1,
    {},
    Object('{}'),
    '',
    '{',
    'null',
    '[]',
    '{}',
    '"{}"',
  ])
    assert.deepEqual(parse(raw), invalid);
  for (const total of [null, [], 1, 'x', {}])
    assert.deepEqual(read({ total }), invalid);
  for (const n of names) {
    for (const bad of [null, [], 1, 'x', {}])
      assert.deepEqual(
        read({ total: { ...input().total, [n]: bad } }),
        invalid,
      );
    const t: Record<string, unknown> = { ...input().total };
    delete t[n];
    assert.deepEqual(read({ total: t }), invalid);
    for (const key of ['total', 'covered', 'skipped']) {
      const m: Record<string, unknown> = { ...metric() };
      delete m[key];
      assert.deepEqual(read({ total: { ...input().total, [n]: m } }), invalid);
    }
  }
});
await test('unsafe and inconsistent numeric counts reject for every metric', () => {
  for (const n of names) {
    for (const key of ['total', 'covered', 'skipped']) {
      for (const bad of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null])
        assert.deepEqual(
          read({
            total: { ...input().total, [n]: { ...metric(), [key]: bad } },
          }),
          invalid,
        );
    }
    for (const m of [
      { total: 0, covered: 1, skipped: 0 },
      { total: 0, covered: 0, skipped: 1 },
      { total: 4, covered: 5, skipped: 0 },
      { total: 4, covered: 0, skipped: 5 },
    ])
      assert.deepEqual(read({ total: { ...input().total, [n]: m } }), invalid);
  }
  assert.deepEqual(
    parse(JSON.stringify(input()).replace('"total":4', '"total":1e400')),
    invalid,
  );
});
await test('private paths, pct and extra data never leak; fresh deterministic metrics', () => {
  const value = { ...input(), SECRET: { source: 'SECRET' }, other: null };
  const raw = JSON.stringify(value);
  const before = raw;
  assert.deepEqual(parse(raw), expected());
  assert.equal(raw, before);
  assert.deepEqual(
    read({
      total: Object.fromEntries(
        [...names]
          .reverse()
          .map((n) => [
            n,
            { ...metric(), pct: { SECRET: 'SECRET' }, source: 'SECRET' },
          ]),
      ),
    }),
    expected(),
  );
  const a = parse(raw),
    b = parse(raw);
  assert.notEqual(a, b);
  if (a.status === 'parsed' && b.status === 'parsed') {
    assert.notEqual(a.metrics, b.metrics);
    for (const n of names) assert.notEqual(a.metrics[n], b.metrics[n]);
  }
  assert.equal(JSON.stringify(a).includes('SECRET'), false);
  assert.deepEqual(parse('{"__proto__":{"total":{}},"SECRET":1}'), invalid);
});
await test('root key count cap is inclusive', () => {
  const extra = Object.fromEntries(
    Array.from({ length: 1000 }, (_, i) => ['p' + String(i), null]),
  );
  assert.deepEqual(read({ ...extra, ...input() }), expected());
  assert.deepEqual(read({ ...extra, ...input(), extra: null }), invalid);
});
await test('UTF-8 cap is inclusive and rejected before JSON.parse', () => {
  const raw = JSON.stringify(input());
  const exact = raw + ' '.repeat(262144 - raw.length);
  assert.deepEqual(parse(exact), expected());
  const multibyte = JSON.stringify({ ...input(), source: 'é'.repeat(140000) });
  const original = JSON.parse;
  let calls = 0;
  JSON.parse = ((...args: Parameters<typeof JSON.parse>): unknown => {
    calls++;
    return original(...args);
  }) as typeof JSON.parse;
  try {
    assert.deepEqual(parse(exact + ' '), invalid);
    assert.deepEqual(parse(multibyte), invalid);
    assert.equal(calls, 0);
  } finally {
    JSON.parse = original;
  }
});
