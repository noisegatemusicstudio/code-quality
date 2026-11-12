import { immutableMetadata } from './scan-metadata.js';

/** Single source of truth for every pinned engine: version and binary SHA-256. */
export const externalPins = immutableMetadata({
  gitleaks: {
    version: '8.30.1',
    license: 'MIT',
    sha256: '88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509',
    coverage:
      'Current committed text tree, embedded default rules; no history/archive/decoded-content scan',
  },
  jscpd: {
    version: '5.4.3',
    license: 'MIT',
    sha256: '8fb77187f871c40563389f69dc3c957c35756db69dcd5640ebe445b88d0f53be',
    coverage:
      'Native supported source formats, strict tokens, minimum 5 lines/50 tokens; not semantic duplication',
  },
});
export const osvPin = immutableMetadata({
  version: '2.7.1',
  license: 'Apache-2.0',
  sha256: 'fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8',
  coverage:
    'npm package-lock only; source resolution, call analysis, queries, downloads and updates disabled; caller database completeness/freshness unverified',
  databaseLimits: {
    compressedBytes: 402653184,
    expandedBytes: 2147483648,
    entries: 500000,
    workerV8OldSpaceMiB: 256,
    bufferMemory:
      'File-backed streamed cache and bounded records; V8 old-space is not a total RSS cap',
    validationTimeoutMs: 120000,
    officialFullArchiveCompatibility:
      'unverified; large full-ecosystem archives may exceed supported bounds',
  },
});

/**
 * Lint engines run through `runAdapter` on an explicit file list (Shell and
 * GitHub Actions workflows). ShellCheck is GPL-3.0: it runs only as a separate,
 * unbundled binary and is "customer: needs review" in docs/scanner-licensing.md.
 */
export const lintPins = immutableMetadata({
  shellcheck: {
    version: '0.11.0',
    license: 'GPL-3.0',
    sha256: '4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b',
    coverage:
      'Tracked .sh/.bash/.ksh files, default checks at every severity, no rc file; sourced files are not followed',
  },
  shfmt: {
    version: '3.14.1',
    license: 'BSD-3-Clause',
    sha256: '76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf',
    coverage:
      'Tracked .sh/.bash/.ksh files, diff mode (-d) with -i 2 -ci, never rewrites; a file shfmt cannot parse yields no shfmt finding (ShellCheck reports syntax errors)',
  },
  actionlint: {
    version: '1.7.12',
    license: 'MIT',
    sha256: 'c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4',
    coverage:
      'Tracked .github/workflows/*.yml|yaml, bundled defaults, no actionlint config; embedded ShellCheck/pyflakes integrations do not run',
  },
  zizmor: {
    version: '1.32.0',
    license: 'MIT',
    sha256: '04d55fb88e582a8e9a9ce6b4753df723fc44c35e0d1a8e8771db9e017066c6df',
    coverage:
      'Tracked .github/workflows/*.yml|yaml, --offline: no GitHub API call, no token; online-only audits do not run',
  },
});

/** Pinned engines that are not run through `runExternalScanner`. */
export const trivyPin = immutableMetadata({
  version: '0.76.2',
  license: 'Apache-2.0',
  sha256: '6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3',
  coverage:
    'Filesystem IaC/misconfiguration checks on committed files only; no image, vulnerability-database or secret scanning',
});
export const semgrepPin = immutableMetadata({
  version: '1.185.0',
  license: 'LGPL-2.1',
  /** Hash-locked, binary-only dependency set installed with --require-hashes. */
  requirements: 'scanners/semgrep-requirements.txt',
  /** sha256 of the official manylinux x86_64 wheel (PyPI), also in the lock. */
  wheelSha256:
    '0eb6aaadad5b957af96d1300487e10af1dc8016e8ef53072effb48cd4906c02b',
});

/**
 * Official linux-amd64 release assets. `assetSha256` is the digest of the
 * downloaded file as published upstream; `binarySha256` (when the asset is an
 * archive) is the digest of the extracted executable and must equal the engine
 * pin above. Both are verified before anything is executed.
 */
export const releaseAssets = immutableMetadata({
  gitleaks: {
    url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
    assetSha256:
      '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
    member: 'gitleaks',
    binarySha256: externalPins.gitleaks.sha256,
    source:
      'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt',
  },
  trivy: {
    url: 'https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz',
    assetSha256:
      'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf',
    member: 'trivy',
    binarySha256: trivyPin.sha256,
    source:
      'https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_checksums.txt',
  },
  osv: {
    url: 'https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64',
    assetSha256: osvPin.sha256,
    member: null,
    binarySha256: osvPin.sha256,
    source:
      'https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_SHA256SUMS',
  },
  jscpd: {
    url: 'https://registry.npmjs.org/jscpd-linux-x64-gnu/-/jscpd-linux-x64-gnu-5.4.3.tgz',
    assetSha256:
      'd1848a5cea3695272911239398bf7a2986d171272c67e806db9d3e60e55c9565',
    member: 'package/bin/jscpd',
    binarySha256: externalPins.jscpd.sha256,
    source:
      'npm registry dist.integrity sha512-BbL0HypadbjpxNfK/KY4CfpD4sCd2zf9HpFnGwwOjdryjdTG098isft/95BiS/XvZjVT3p6lwLf5ToI97OoqCg== for jscpd-linux-x64-gnu@5.4.3 (no upstream sha256 file is published; sha256 computed from that verified tarball)',
  },
  shellcheck: {
    url: 'https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz',
    assetSha256:
      '8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198',
    member: 'shellcheck-v0.11.0/shellcheck',
    binarySha256: lintPins.shellcheck.sha256,
    source:
      'No upstream checksum file is published for v0.11.0; sha256 computed from the official release asset downloaded 2026-11-12',
  },
  shfmt: {
    url: 'https://github.com/mvdan/sh/releases/download/v3.14.1/shfmt_v3.14.1_linux_amd64',
    assetSha256: lintPins.shfmt.sha256,
    member: null,
    binarySha256: lintPins.shfmt.sha256,
    source:
      'No upstream checksum file is published for v3.14.1; sha256 computed from the official release asset downloaded 2026-11-12',
  },
  actionlint: {
    url: 'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz',
    assetSha256:
      '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',
    member: 'actionlint',
    binarySha256: lintPins.actionlint.sha256,
    source:
      'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt',
  },
  zizmor: {
    url: 'https://github.com/zizmorcore/zizmor/releases/download/v1.32.0/zizmor-x86_64-unknown-linux-gnu.tar.gz',
    assetSha256:
      'bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b',
    member: 'zizmor',
    binarySha256: lintPins.zizmor.sha256,
    source:
      'No upstream checksum file is published for v1.32.0; sha256 computed from the official release asset downloaded 2026-11-12',
  },
});
