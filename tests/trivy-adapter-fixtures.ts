/** Recorded-style synthetic Trivy JSON (SchemaVersion 2). Nothing is fetched. */
export const digest = `sha256:${'a'.repeat(64)}`;
const name = (key: string) => `registry.test/${key}@${digest}`;
const report = (artifact: string, results: unknown[] | undefined) =>
  JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: artifact,
    ArtifactType: 'container_image',
    ...(results ? { Results: results } : {}),
  });
const vuln = (
  id: string,
  pkg: string,
  version: string,
  severity: string,
  source: string,
  fixed?: string,
) => ({
  VulnerabilityID: id,
  PkgName: pkg,
  InstalledVersion: version,
  ...(fixed ? { FixedVersion: fixed } : {}),
  Severity: severity,
  SeveritySource: source,
  Title: `Synthetic advisory ${id}`,
});

export const vulnerableImage = report(name('vulnerable'), [
  {
    Target: 'registry.test/vulnerable (alpine 3.18.0)',
    Class: 'os-pkgs',
    Type: 'alpine',
    Vulnerabilities: [
      vuln('CVE-2023-5363', 'libssl3', '3.1.2-r0', 'HIGH', 'nvd', '3.1.4-r0'),
    ],
  },
  {
    Target: 'app/package-lock.json',
    Class: 'lang-pkgs',
    Type: 'npm',
    Vulnerabilities: [
      vuln('CVE-2020-8203', 'lodash', '4.17.15', 'HIGH', 'ghsa', '4.17.19'),
      vuln('CVE-2021-23337', 'lodash', '4.17.15', 'HIGH', 'ghsa', '4.17.21'),
      // Repeated report of the same finding is one finding.
      vuln('CVE-2021-23337', 'lodash', '4.17.15', 'HIGH', 'ghsa', '4.17.21'),
      vuln('CVE-2099-0001', 'left-pad', '1.0.0', 'MEDIUM', 'nvd'),
    ],
  },
]);
export const cleanImage = report(name('clean'), [
  {
    Target: 'registry.test/clean (alpine 3.19.0)',
    Class: 'os-pkgs',
    Type: 'alpine',
  },
]);
export const cleanImageNoResults = report(name('clean'), undefined);

const misconf = (
  id: string,
  severity: string,
  message: string,
  resolution: string,
  resource: string,
  lines: [number, number],
  extra: object = {},
) => ({
  Type: 'Terraform Security Check',
  ID: id,
  AVDID: `AVD-${id}`,
  Title: `Title of ${id}`,
  Message: message,
  Resolution: resolution,
  Severity: severity,
  Status: 'FAIL',
  CauseMetadata: {
    Resource: resource,
    StartLine: lines[0],
    EndLine: lines[1],
    // Trivy may echo source lines; the parser must never copy them.
    Code: {
      Lines: [
        {
          Number: lines[0],
          Content: 'secret_key = "SYNTHETIC-CODE-LINE-SECRET-0123456789"',
        },
      ],
    },
  },
  ...extra,
});
export const iacMisconfig = report('.', [
  {
    Target: 'main.tf',
    Class: 'config',
    Type: 'terraform',
    Misconfigurations: [
      misconf(
        'AWS-0086',
        'HIGH',
        'No public access block so not blocking public acls',
        'Enable blocking any PUT calls with a public ACL specified',
        'aws_s3_bucket.logs',
        [5, 9],
      ),
      misconf(
        'AWS-0001',
        'LOW',
        'Passed check',
        'n/a',
        'aws_s3_bucket.logs',
        [1, 1],
        { Status: 'PASS' },
      ),
    ],
  },
  {
    Target: 'deploy/Dockerfile',
    Class: 'config',
    Type: 'dockerfile',
    Misconfigurations: [
      misconf(
        'DS002',
        'HIGH',
        'Image user should not be root; password=hunter2hunter2 is set in ENV',
        'Add USER and remove token ghp_abcdefghijklmnopqrstuvwxyz0123456789',
        'Dockerfile',
        [3, 3],
      ),
    ],
  },
]);
export const malformedReports = [
  '{oops',
  '[]',
  JSON.stringify({ SchemaVersion: 1, ArtifactName: 'x' }),
  JSON.stringify({ SchemaVersion: 2 }),
  JSON.stringify({ SchemaVersion: 2, ArtifactName: 'x', Results: 'no' }),
  JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: 'x',
    Results: [{ Target: 't', Vulnerabilities: [{ PkgName: 'p' }] }],
  }),
  // Misconfiguration on a path outside the workspace.
  JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: 'x',
    Results: [
      {
        Target: '../etc/x.tf',
        Misconfigurations: [{ ID: 'X1', Severity: 'LOW' }],
      },
    ],
  }),
];
export { name as imageName };
