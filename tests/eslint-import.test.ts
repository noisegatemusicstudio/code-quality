import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseEslintJson as parse } from '../src/eslint-import.js';
const file = () => ({
  messages: [] as unknown[],
  suppressedMessages: [] as unknown[],
  errorCount: 0,
  warningCount: 0,
  fatalErrorCount: 0,
  fixableErrorCount: 0,
  fixableWarningCount: 0,
});
const invalid = { status: 'invalid' };
const parsed = (findingCount: number) => ({ status: 'parsed', findingCount });
const read = (value: unknown) => parse(JSON.stringify(value));
await test('inherited required fields and fatal metadata never supply own values', () => {
  for (const key of [...Object.keys(file()), 'severity', 'fatal']) {
    const f: Record<string, unknown> = { ...file() };
    if (key === 'severity') {
      f.messages = [{}];
      f.errorCount = 1;
    } else if (key === 'fatal') {
      f.messages = [{ severity: 2 }];
      f.errorCount = 1;
    } else {
      delete f[key];
    }
    const raw = JSON.stringify([f]);
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
    assert.deepEqual(result, key === 'fatal' ? parsed(1) : invalid);
  }
});
await test('empty reports and valid severities parse without execution claims', () => {
  assert.deepEqual(read([]), parsed(0));
  assert.deepEqual(read([file()]), parsed(0));
  const f = {
    ...file(),
    messages: [
      { severity: 1, message: 'SECRET' },
      { severity: 2, fatal: true },
      { severity: 2, fatal: false },
    ],
    errorCount: 2,
    warningCount: 1,
    fatalErrorCount: 1,
  };
  assert.deepEqual(read([f]), parsed(3));
  assert.deepEqual(read([f, f]), parsed(6));
});
await test('runtime type, syntax and root/file shapes fail closed', () => {
  for (const raw of [
    null,
    undefined,
    2,
    {},
    Object('[]'),
    '',
    '{',
    'null',
    '{}',
    '1',
    '"[]"',
  ])
    assert.deepEqual(parse(raw), invalid);
  for (const f of [
    null,
    [],
    2,
    'x',
    {},
    { ...file(), messages: {} },
    { ...file(), suppressedMessages: null },
  ])
    assert.deepEqual(read([f]), invalid);
  for (const key of Object.keys(file())) {
    const f: Record<string, unknown> = { ...file() };
    delete f[key];
    assert.deepEqual(read([f]), invalid);
  }
});
await test('unsafe, fractional and inconsistent counts are rejected', () => {
  for (const key of [
    'errorCount',
    'warningCount',
    'fatalErrorCount',
    'fixableErrorCount',
    'fixableWarningCount',
  ]) {
    for (const n of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null])
      assert.deepEqual(read([{ ...file(), [key]: n }]), invalid);
  }
  assert.deepEqual(
    parse(
      '[{"messages":[],"suppressedMessages":[],"errorCount":1e400,"warningCount":0,"fatalErrorCount":0,"fixableErrorCount":0,"fixableWarningCount":0}]',
    ),
    invalid,
  );
  for (const f of [
    { ...file(), errorCount: 1 },
    { ...file(), warningCount: 1 },
    { ...file(), fatalErrorCount: 1 },
    { ...file(), fixableErrorCount: 1 },
    { ...file(), fixableWarningCount: 1 },
    { ...file(), messages: [{ severity: 2 }] },
    {
      ...file(),
      messages: [{ severity: 1, fatal: true }],
      warningCount: 1,
      fatalErrorCount: 1,
    },
  ])
    assert.deepEqual(read([f]), invalid);
  for (const m of [
    null,
    [],
    {},
    { severity: 0 },
    { severity: 3 },
    { severity: '2' },
    { severity: 2, fatal: 1 },
  ])
    assert.deepEqual(
      read([{ ...file(), messages: [m], errorCount: 1 }]),
      invalid,
    );
});
await test('suppressed payloads and private metadata are discarded deterministically', () => {
  const f = {
    ...file(),
    suppressedMessages: [{ severity: 2, message: 'SECRET' }, null],
    source: 'SECRET',
    output: 'SECRET',
    filePath: 'SECRET',
    fix: { text: 'SECRET' },
    suggestions: ['SECRET'],
  };
  const raw = JSON.stringify([f]);
  const before = raw;
  assert.deepEqual(parse(raw), parsed(0));
  assert.equal(raw, before);
  assert.deepEqual(
    parse(raw),
    parse(JSON.stringify([{ ...f, source: 'other' }])),
  );
  const a = parse(raw);
  const b = parse(raw);
  assert.notEqual(a, b);
  assert.equal(JSON.stringify(a).includes('SECRET'), false);
  assert.deepEqual(
    read([
      {
        ...file(),
        messages: [{ severity: 2, fix: { text: 'SECRET' } }],
        errorCount: 1,
        fixableErrorCount: 1,
      },
    ]),
    parsed(1),
  );
  assert.deepEqual(
    parse(
      '[{"__proto__":{"errorCount":0},"messages":[],"suppressedMessages":[],"warningCount":0,"fatalErrorCount":0,"fixableErrorCount":0,"fixableWarningCount":0}]',
    ),
    invalid,
  );
});
await test('file and combined message limits are inclusive', () => {
  assert.deepEqual(read(Array.from({ length: 1000 }, file)), parsed(0));
  assert.deepEqual(read(Array.from({ length: 1001 }, file)), invalid);
  const f = {
    ...file(),
    messages: Array.from({ length: 10000 }, () => ({ severity: 1 })),
    warningCount: 10000,
  };
  assert.deepEqual(read([f]), parsed(10000));
  assert.deepEqual(read([{ ...f, suppressedMessages: [null] }]), invalid);
  assert.deepEqual(
    read([{ ...file(), suppressedMessages: Array(10000).fill(null) }]),
    parsed(0),
  );
  assert.deepEqual(
    read([
      { ...file(), suppressedMessages: Array(5001).fill(null) },
      { ...file(), suppressedMessages: Array(5000).fill(null) },
    ]),
    invalid,
  );
});
await test('UTF-8 byte cap is checked before JSON.parse', () => {
  const exact = '[]' + ' '.repeat(262142);
  assert.deepEqual(parse(exact), parsed(0));
  const over = exact + ' ';
  const multibyte = JSON.stringify([{ ...file(), source: 'é'.repeat(140000) }]);
  const original = JSON.parse;
  let calls = 0;
  JSON.parse = ((...args: Parameters<typeof JSON.parse>): unknown => {
    calls++;
    return original(...args);
  }) as typeof JSON.parse;
  try {
    assert.deepEqual(parse(over), invalid);
    assert.deepEqual(parse(multibyte), invalid);
    assert.equal(calls, 0);
  } finally {
    JSON.parse = original;
  }
});
