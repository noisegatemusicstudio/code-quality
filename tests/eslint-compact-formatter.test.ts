// Test classification: unit
// Review status: Not Reviewed
// Evidence: synthetic
// Scope: Feeds a synthetic ESLint result to the scan's compact formatter and proves bulky fields are dropped, validated fields and counts are kept and the output still parses; runs no ESLint process.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import compactFormatter from '../src/eslint-compact-formatter.js';
import { parseEslintJson } from '../src/eslint-import.js';

const message = {
  ruleId: 'no-debugger',
  severity: 2,
  message: 'Unexpected debugger statement.',
  line: 3,
  column: 1,
  endLine: 3,
  endColumn: 10,
  nodeType: 'DebuggerStatement',
  messageId: 'unexpected',
  fix: { range: [0, 9], text: 'x'.repeat(1000) },
  suggestions: [{ desc: 'remove', fix: { range: [0, 9], text: '' } }],
};
const result = {
  filePath: '/work/source/a.ts',
  messages: [message],
  suppressedMessages: [{ ...message, suppressions: [{ kind: 'directive' }] }],
  errorCount: 1,
  fatalErrorCount: 0,
  warningCount: 0,
  fixableErrorCount: 1,
  fixableWarningCount: 0,
  source: 'debugger;\n'.repeat(5000),
  usedDeprecatedRules: [{ ruleId: 'x', replacedBy: ['y'] }],
};

await test('bulky fields are dropped and the validated fields and counts are kept', () => {
  const out = compactFormatter([result]);
  const [file] = JSON.parse(out) as Record<string, unknown>[];
  for (const dropped of ['source', 'usedDeprecatedRules'])
    assert.equal(Object.hasOwn(file, dropped), false, dropped);
  assert.deepEqual(file.suppressedMessages, []);
  assert.equal(file.filePath, result.filePath);
  assert.equal(file.errorCount, 1);
  assert.equal(file.fixableErrorCount, 1);
  const [kept] = file.messages as Record<string, unknown>[];
  for (const dropped of ['fix', 'suggestions', 'nodeType', 'messageId'])
    assert.equal(Object.hasOwn(kept, dropped), false, dropped);
  assert.deepEqual(
    { ...kept },
    {
      ruleId: 'no-debugger',
      severity: 2,
      message: 'Unexpected debugger statement.',
      line: 3,
      column: 1,
      endLine: 3,
      endColumn: 10,
    },
  );
  assert.ok(out.length < JSON.stringify([result]).length / 10);
});

await test('compact output is a valid report for the shared parser', () => {
  assert.deepEqual(parseEslintJson(compactFormatter([result])), {
    status: 'parsed',
    findingCount: 1,
  });
  assert.deepEqual(parseEslintJson(compactFormatter([])), {
    status: 'parsed',
    findingCount: 0,
  });
});

await test('a fatal message keeps its fatal flag so parse failures stay visible', () => {
  const fatal = {
    ...result,
    messages: [
      {
        ruleId: null,
        severity: 2,
        fatal: true,
        message: 'Parsing error',
        line: 1,
        column: 1,
      },
    ],
    errorCount: 1,
    fatalErrorCount: 1,
    fixableErrorCount: 0,
  };
  const [file] = JSON.parse(compactFormatter([fatal])) as {
    messages: Record<string, unknown>[];
  }[];
  assert.equal(file.messages[0].fatal, true);
  assert.equal(parseEslintJson(compactFormatter([fatal])).status, 'parsed');
});
