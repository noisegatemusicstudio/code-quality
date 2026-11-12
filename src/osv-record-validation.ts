import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import formats from 'ajv-formats';
import schema from './osv-schema-v1.9.2.json' with { type: 'json' };

export type OsvValidationProfile = 'strict-schema-v1' | 'npm-metadata-v1';
export interface MetadataWarningCounts {
  records: number;
  referenceUriFormat: number;
  cvssV4TrailingSlash: number;
}

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const reject = (): never => {
  throw new Error('Invalid or unsupported offline OSV database');
};

/** Only an explicit own property opts in. Do not invoke inherited getters. */
export function selectOsvValidationProfile(
  input: object,
): OsvValidationProfile {
  const profile: unknown = Object.hasOwn(input, 'validationProfile')
    ? Reflect.get(input, 'validationProfile')
    : undefined;
  if (profile === undefined || profile === 'strict-schema-v1')
    return 'strict-schema-v1';
  if (profile === 'npm-metadata-v1') return profile;
  return reject();
}

function compile(allErrors: boolean) {
  const ajv = new Ajv2020({ strict: false, allErrors, validateFormats: true });
  formats.default(ajv);
  // No coercion, defaults, property removal, remote loader or modified schema.
  return ajv.compile(schema);
}
const strict = compile(false);
const metadata = compile(true);
const cvss4Pattern =
  schema.$defs.severity.items.allOf[2].then.properties.score.pattern;
if (cvss4Pattern === undefined)
  throw new Error('OSV schema is missing the CVSS v4 score pattern');
const cvss4 = new RegExp(cvss4Pattern, 'u');

function acceptedCvssParent(error: ErrorObject, value: unknown): string | null {
  const path = /^\/severity\/(0|[1-9][0-9]*)\/score$/.exec(error.instancePath);
  if (
    error.keyword !== 'pattern' ||
    error.schemaPath !==
      '#/$defs/severity/items/allOf/2/then/properties/score/pattern' ||
    path === null ||
    !object(value) ||
    !Array.isArray(value.severity)
  )
    return null;
  const entry: unknown = value.severity[Number(path[1])];
  if (
    !object(entry) ||
    entry.type !== 'CVSS_V4' ||
    typeof entry.score !== 'string' ||
    !entry.score.endsWith('/') ||
    entry.score.endsWith('//') ||
    !cvss4.test(entry.score.slice(0, -1))
  )
    return null;
  return `/severity/${path[1]}`;
}

/** Recognizes two metadata defects without changing record bytes or match fields. */
export function validateOsvRecord(
  value: unknown,
  profile: OsvValidationProfile = 'strict-schema-v1',
): MetadataWarningCounts {
  const counts = { records: 0, referenceUriFormat: 0, cvssV4TrailingSlash: 0 };
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- exported API: JS callers can pass any profile at runtime.
  if (profile !== 'strict-schema-v1' && profile !== 'npm-metadata-v1') reject();
  if (profile === 'strict-schema-v1') {
    if (!strict(value)) reject();
    return counts;
  }
  if (metadata(value)) return counts;
  const errors = metadata.errors;
  if (!errors?.length) return reject();
  // Correlate an Ajv conditional wrapper with the exact accepted score error.
  const acceptedParents = new Set<string>();
  for (const error of errors) {
    const parent = acceptedCvssParent(error, value);
    if (parent !== null) acceptedParents.add(parent);
  }
  for (const error of errors) {
    if (acceptedCvssParent(error, value) !== null) {
      counts.cvssV4TrailingSlash++;
      continue;
    }
    const reference = /^\/references\/(0|[1-9][0-9]*)\/url$/.exec(
      error.instancePath,
    );
    if (
      error.keyword === 'format' &&
      error.params.format === 'uri' &&
      error.schemaPath ===
        '#/properties/references/items/properties/url/format' &&
      reference !== null &&
      object(value) &&
      Array.isArray(value.references)
    ) {
      const item: unknown = value.references[Number(reference[1])];
      if (object(item) && typeof item.url === 'string') {
        counts.referenceUriFormat++;
        continue;
      }
    }
    if (
      error.keyword === 'if' &&
      error.schemaPath === '#/$defs/severity/items/allOf/2/if' &&
      error.params.failingKeyword === 'then' &&
      acceptedParents.has(error.instancePath)
    )
      continue;
    reject();
  }
  counts.records =
    counts.referenceUriFormat + counts.cvssV4TrailingSlash > 0 ? 1 : 0;
  return counts;
}
