/** Inline fixtures keep real defects out of the repository's own lint scope. */
export const defects = `export function check(a: number): boolean {
  var unused = 1;
  return a == 2;
}
debugger;
`;
export const benign = `export function add(a: number, b: number): number {
  return a + b;
}
`;
export const malformed = 'export const = ;\n';
export const jsCommonjs = `const fs = require('node:fs');
module.exports = function read(p) {
  var x = 1;
  return fs.readFileSync(p, 'utf8');
};
`;
export const jsModule = `export const answer = 42;
export default function f() {
  return answer;
}
`;
export const shifted = '// unrelated comment\n\n' + defects;
export const scope = {
  tenantId: 't1',
  projectId: 'p1',
  repository: 'owner/name',
  commitSha: 'a'.repeat(40),
  sourceId: 's1',
  jobId: 'j1',
  attemptId: 'a1',
};
