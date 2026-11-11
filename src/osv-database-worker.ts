import { copyOsvCache } from './osv-cache-copy.js';
import { validateOsvDatabaseFile } from './osv-database.js';
import { selectOsvValidationProfile } from './osv-record-validation.js';

async function main() {
  const args = process.argv.slice(2);
  const [sourcePath, cachePath, sha256, validationProfile] = args;
  if (args.length !== 4 || !sourcePath || !cachePath || !sha256)
    throw new Error();
  const profile = selectOsvValidationProfile({ validationProfile });
  await copyOsvCache(sourcePath, cachePath, sha256);
  const result = await validateOsvDatabaseFile(cachePath, 'npm', profile);
  if (result.sha256 !== sha256) throw new Error();
  process.stdout.write(JSON.stringify(result));
}
main().catch(() => {
  process.exitCode = 2;
});
