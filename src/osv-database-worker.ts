import { readBoundedRegular } from './external-scanners.js';
import { validateOsvDatabaseZip } from './osv-database.js';

async function main() {
  const [path] = process.argv.slice(2);
  if (!path) throw new Error();
  const result = await validateOsvDatabaseZip(
    await readBoundedRegular(path, 67108864),
    'npm',
  );
  process.stdout.write(JSON.stringify(result));
}
main().catch(() => {
  process.exitCode = 2;
});
