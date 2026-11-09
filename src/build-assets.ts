import { copyFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';

// TypeScript reserializes JSON on emit. Restore the exact upstream artifact and
// notices after compilation; this reads only these explicitly owned vendor assets.
const source = resolve(import.meta.dirname, '../../src');
const schema = 'osv-schema-v1.9.2.json';
if (
  createHash('sha256')
    .update(readFileSync(join(source, schema)))
    .digest('hex') !==
  '15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653'
)
  throw new Error('Vendored schema integrity mismatch');
for (const name of [schema, 'osv-schema-LICENSE.txt', 'osv-schema-NOTICE.txt'])
  copyFileSync(join(source, name), join(import.meta.dirname, name));
