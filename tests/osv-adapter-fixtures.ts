/** Recorded-style OSV-Scanner JSON fixtures. Nothing here is fetched live. */
const vuln = (id: string, aliases: string[], fixed?: string) => ({
  id,
  aliases,
  summary: `Prototype pollution in lodash (${id})`,
  database_specific: { severity: 'HIGH' },
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [
        {
          type: 'SEMVER',
          events: [{ introduced: '0' }, ...(fixed ? [{ fixed }] : [])],
        },
      ],
    },
  ],
});
const pkg = (version: string, vulnerabilities?: unknown[]) => ({
  package: { name: 'lodash', version, ecosystem: 'npm' },
  ...(vulnerabilities ? { vulnerabilities } : {}),
});
const report = (path: string, packages: unknown[]) =>
  JSON.stringify({
    results: [{ source: { path, type: 'lockfile' }, packages }],
  });

export const artefact = 'package-lock.json';
export const vulnerableReport = report(`/tmp/work/${artefact}`, [
  // Same advisory reported twice under different ids: must merge.
  pkg('4.17.15', [
    vuln('GHSA-p6mc-m468-83gw', ['CVE-2020-8203'], '4.17.19'),
    vuln('CVE-2020-8203', ['GHSA-p6mc-m468-83gw'], '4.17.19'),
  ]),
  // Different version, same advisory: must stay separate.
  pkg('4.17.16', [vuln('GHSA-p6mc-m468-83gw', ['CVE-2020-8203'], '4.17.19')]),
  // A different advisory on the first version stays separate; no fix known.
  pkg('4.17.15', [vuln('GHSA-35jh-r3h4-6jhm', ['CVE-2021-23337'])]),
]);
export const fixedReport = report(`/tmp/work/${artefact}`, [pkg('4.17.21')]);
export const emptyReport = JSON.stringify({ results: [] });
export const otherPathReport = report('/tmp/work/other/yarn.lock', [
  pkg('1.0.0', [vuln('GHSA-aaaa-bbbb-cccc', [])]),
]);
export const malformedReports = [
  '{not json',
  '[]',
  JSON.stringify({ results: 'x' }),
  JSON.stringify({ results: [{ source: {}, packages: [] }] }),
  report(`/tmp/work/${artefact}`, [{ package: { name: 'a' } }]),
  report(`/tmp/work/${artefact}`, [pkg('1.0.0', [{ id: 'bad id!' }])]),
];
