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
export const ruffPin = immutableMetadata({
  version: '0.17.4',
  license: 'MIT',
  /** sha256 of the extracted `ruff` executable (upstream release tarball). */
  sha256: '4ef33997b4bb7c5f141527e90b2da0abe918108362ca1b9825c4d13adce0e347',
  coverage:
    'Ruff E, F, W, I, B, UP, S, C4, SIM, PL from the bundled config only; project pyproject.toml/ruff.toml are never read; no type checking',
});
/**
 * Kotlin engines (RRDSCRUM-186). Both are self-contained JVM jars run as
 * `java -jar <verified copy>`; the pin is the sha256 of the jar itself.
 */
export const detektPin = immutableMetadata({
  version: '1.23.8',
  license: 'Apache-2.0',
  sha256: '2ce2ff952e150baf28a29cda70a363b0340b3e81a55f43e51ec5edffc3d066c1',
  coverage:
    'detekt default ruleset (no project detekt.yml, no plugins, no type resolution) on tracked .kt/.kts files; needs a Java runtime',
});
export const ktlintPin = immutableMetadata({
  version: '1.8.0',
  license: 'MIT',
  sha256: 'a3fd620207d5c40da6ca789b95e7f823c54e854b7fade7f613e91096a3706d75',
  coverage:
    'ktlint standard ruleset, official code style, no .editorconfig and no experimental or custom rulesets, on tracked .kt/.kts files; never formats; needs a Java runtime',
});
/**
 * Swift engine (follow-up slice 9). The official static Linux build
 * (`swiftlint-static` from `swiftlint_linux_amd64.zip`), so no Swift toolchain
 * and no macOS runner are needed. The pin is the sha256 of that executable.
 */
export const swiftlintPin = immutableMetadata({
  version: '0.65.1',
  license: 'MIT',
  sha256: 'ad74a829e43f6842e20556c9dab0b536bf53a524c4412f826cd42785c30a2b29',
  coverage:
    'SwiftLint default rules on tracked .swift files; the repository .swiftlint.yml is honoured only when it is plain YAML data (no URL, parent_config, child_config or tag), otherwise the bundled config applies; no analyzer rules, no swift build',
});
/** SwiftLint analyzer rules need a compiler log; a scan never builds, so they are never run. */
export const swiftlintAnalyzePin = immutableMetadata({
  version: '0.65.1',
  license: 'MIT',
  skipReason:
    'requires compiled sources: SwiftLint analyzer rules need a compiler log from a build, and a scan never runs swift build or project code, so they cannot give a trustworthy result',
});
/** mypy is not run: it needs the project's dependencies installed (see docs/language-profiles.md). */
export const mypyPin = immutableMetadata({
  version: '2.4.1',
  license: 'MIT',
  skipReason:
    'needs dependency environment: mypy --strict needs the project dependencies installed, and a scan never installs project dependencies or runs project code, so it cannot give a trustworthy result',
});

/**
 * Java engines (RRDSCRUM-185). Both run on the JDK that the workflow provisions
 * (src/java-runtime.ts) over source files only: no build, no classpath.
 * PMD ships as a directory of jars, so it is pinned by the zip's sha256 and by
 * a digest of the extracted tree; Checkstyle is one all-in-one jar.
 */
export const pmdPin = immutableMetadata({
  version: '7.29.0',
  license: 'BSD-style (PMD license)',
  /** Digest of the extracted `pmd-bin-7.29.0` tree; see `treeDigest` in src/tree-install.ts. */
  treeSha256:
    '78a8499d17dd84f6d41ead909eaa324f283b5e6f4e3b50dc1144127b4e9ac248',
  coverage:
    'PMD quickstart Java ruleset (rulesets/java/quickstart.xml) over tracked .java files; source only, no auxclasspath, so type-resolution rules are limited; project rulesets are never read',
});
export const checkstylePin = immutableMetadata({
  version: '14.4.0',
  license: 'LGPL-2.1',
  /** sha256 of the all-in-one jar (`checkstyle-14.4.0-all.jar`). */
  sha256: 'c0a521e54eabd1ece4ff7bd84cf231b012615745ed3aa4fb27ab0ca73097250c',
  coverage:
    'Checkstyle bundled Google checks (google_checks.xml) over tracked .java files; no project configuration or suppressions are read',
});
/** SpotBugs analyses compiled bytecode; a scan never builds, so it is never run. */
export const spotbugsPin = immutableMetadata({
  version: '4.10.5',
  license: 'LGPL-2.1',
  skipReason:
    'requires compiled classes: SpotBugs analyses bytecode, and a scan never builds the project or runs project code, so it cannot give a trustworthy result',
});

/** Lint engines added after the first set; all run with bundled defaults only. */
export const hadolintPin = immutableMetadata({
  version: '2.15.1',
  license: 'GPL-3.0',
  sha256: 'c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507',
  coverage:
    'Dockerfile/Containerfile syntax and best-practice rules (bundled defaults, no .hadolint.yaml); no image build, no ShellCheck-free guarantee',
});
export const tflintPin = immutableMetadata({
  version: '0.66.0',
  license: 'MPL-2.0',
  sha256: '8f33a3e34dd83cd4bf43646f2e8492d4d5bb8941036a9ae517b611e56004e70d',
  coverage:
    'Terraform *.tf only, bundled terraform ruleset (no plugin download, no provider rulesets, no .tflint.hcl); no plan/apply',
});
export const yamllintPin = immutableMetadata({
  version: '1.38.0',
  license: 'GPL-3.0',
  /** Hash-locked dependency set installed with --require-hashes. */
  requirements: 'scanners/yamllint-requirements.txt',
  /** sha256 of the yamllint py3-none-any wheel (PyPI), also in the lock. */
  wheelSha256:
    'fc394a5b3be980a4062607b8fdddc0843f4fa394152b6da21722f5d59013c220',
  coverage:
    'YAML syntax and the yamllint `default` preset (no .yamllint config); no schema validation',
});
export const markdownlintPin = immutableMetadata({
  version: '0.24.1',
  license: 'MIT',
  /** markdownlint-cli2 0.24.1 bundles markdownlint 0.42.1; integrity comes from package-lock.json. */
  engineVersion: '0.42.1',
  /** sha256 of node_modules/markdownlint-cli2/markdownlint-cli2-bin.mjs. */
  sha256: '558a203f7c5deb0e2d4f309ed468e0454218427e57f196876cbbdd393678d772',
  npmIntegrity:
    'sha512-nLhes/MIPJQLm+Gmh+3jQEnwMOaalaN0wfCD2qz1247zNZ7R3r2WDHJB191x4hcy6soKAUTybp1bFK7aJGw/WA==',
  coverage:
    'Markdown files, markdownlint default rules (no project config, no custom rules or plugins)',
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
  ruff: {
    url: 'https://github.com/astral-sh/ruff/releases/download/0.17.4/ruff-x86_64-unknown-linux-gnu.tar.gz',
    assetSha256:
      '3ab2b34aeacdbc1ea5c529cdbda3e05792633d587228123fd09f3b5a0facb27a',
    member: 'ruff-x86_64-unknown-linux-gnu/ruff',
    binarySha256: ruffPin.sha256,
    source:
      'https://github.com/astral-sh/ruff/releases/download/0.17.4/ruff-x86_64-unknown-linux-gnu.tar.gz.sha256',
  },
  detekt: {
    url: 'https://github.com/detekt/detekt/releases/download/v1.23.8/detekt-cli-1.23.8-all.jar',
    assetSha256: detektPin.sha256,
    member: null,
    binarySha256: detektPin.sha256,
    source:
      'sha256 computed from the official release asset on 2026-11-12 (upstream publishes no checksum file for it)',
  },
  ktlint: {
    url: 'https://github.com/pinterest/ktlint/releases/download/1.8.0/ktlint',
    assetSha256: ktlintPin.sha256,
    member: null,
    binarySha256: ktlintPin.sha256,
    source:
      'sha256 computed from the official release asset on 2026-11-12 (upstream publishes no checksum file for it)',
  },
  swiftlint: {
    url: 'https://github.com/realm/SwiftLint/releases/download/0.65.1/swiftlint_linux_amd64.zip',
    assetSha256:
      'caeed6f4a679c35539ffaf124f6c4ab4a8416917f7d8796279dc52b74026059d',
    member: 'swiftlint-static',
    binarySha256: swiftlintPin.sha256,
    source:
      'sha256 computed from the official release asset on 2026-11-12 (upstream publishes no checksum file for it)',
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
  hadolint: {
    url: 'https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64',
    assetSha256: hadolintPin.sha256,
    member: null,
    binarySha256: hadolintPin.sha256,
    source:
      'sha256 computed from the release asset downloaded over TLS from github.com (upstream publishes no checksum file for v2.15.1)',
  },
  tflint: {
    url: 'https://github.com/terraform-linters/tflint/releases/download/v0.66.0/tflint_linux_amd64.zip',
    assetSha256:
      '22be11cadc25cd02401e94c0ccc91aa63467debb8485c2a755d98f4c0a9d1e2e',
    member: 'tflint',
    binarySha256: tflintPin.sha256,
    source:
      'https://github.com/terraform-linters/tflint/releases/download/v0.66.0/checksums.txt',
  },
  checkstyle: {
    url: 'https://github.com/checkstyle/checkstyle/releases/download/checkstyle-14.4.0/checkstyle-14.4.0-all.jar',
    assetSha256: checkstylePin.sha256,
    member: null,
    binarySha256: checkstylePin.sha256,
    source:
      'No upstream checksum file is published for 14.4.0; sha256 computed from the official release asset downloaded 2026-11-12',
  },
});

/**
 * Official release archives that install as a directory tree. `assetSha256`
 * is the zip as published; `treeSha256` is the digest of the extracted `member`
 * directory and must equal the engine pin. Both are verified before anything
 * is executed, and the tree is verified again before each run.
 */
export const releaseTrees = immutableMetadata({
  pmd: {
    url: 'https://github.com/pmd/pmd/releases/download/pmd_releases%2F7.29.0/pmd-dist-7.29.0-bin.zip',
    assetSha256:
      'd27177c185b837fa57f097e482d1253468aa035379c5eb2671fa0a279109b179',
    member: 'pmd-bin-7.29.0',
    treeSha256: pmdPin.treeSha256,
    source:
      'No upstream checksum file is published for 7.29.0; sha256 computed from the official release asset downloaded 2026-11-12',
  },
});
