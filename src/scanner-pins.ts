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
