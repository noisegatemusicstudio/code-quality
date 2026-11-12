import { readdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { ESLint } from 'eslint';
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import ts from 'typescript';
import { validateDeclarationBundle } from './declaration-bundle.js';

// Private worker: fixed bundled config only; no repository modules/config/scripts.
async function main() {
  const [id, root, bundlePath] = process.argv.slice(2);
  if ((id !== 'eslint' && id !== 'typescript') || !root) throw new Error();
  if (ESLint.version !== '10.13.0' || ts.version !== '5.9.3') throw new Error();
  const files: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (
        entry.isFile() &&
        /\.(?:js|cjs|mjs|jsx|ts|cts|mts|tsx)$/.test(entry.name)
      )
        files.push(path);
      else if (!entry.isFile()) throw new Error();
    }
  };
  await walk(root);
  files.sort((left, right) => {
    if (left === right) return 0;
    return left < right ? -1 : 1;
  });
  let findings = 0;
  let unresolved = 0;
  let suppressionCount = 0;
  if (id === 'eslint') {
    const lint = new ESLint({
      cwd: root,
      overrideConfigFile: true,
      ignore: false,
      allowInlineConfig: false,
      errorOnUnmatchedPattern: true,
      overrideConfig: [
        { files: ['**/*.{js,cjs,mjs,jsx,ts,cts,mts,tsx}'] },
        js.configs.recommended,
        ...tseslint.configs.recommended,
        {
          files: ['**/*.{js,cjs,mjs,jsx}'],
          languageOptions: {
            parserOptions: { ecmaFeatures: { jsx: true } },
          },
        },
      ],
    });
    for (const file of files) {
      const results = await lint.lintText(await readFile(file, 'utf8'), {
        filePath: file,
      });
      if (results.length !== 1) throw new Error();
      findings += results[0].errorCount + results[0].warningCount;
    }
  } else {
    // Fixed semantic profile. No tsconfig loading, emit, plugins, project
    // references or filesystem fallback. Libraries come only from pinned TS.
    const sources = new Map<string, string>();
    for (const file of files) {
      const text = await readFile(file, 'utf8');
      suppressionCount += [
        ...text.matchAll(/@ts-(?:nocheck|ignore|expect-error)\b/g),
      ].length;
      sources.set(file, text);
    }
    if (bundlePath !== undefined) {
      const input: unknown = JSON.parse(await readFile(bundlePath, 'utf8'));
      const bundle = validateDeclarationBundle(input);
      if (bundle === null) throw new Error();
      for (const [path, content] of Object.entries(bundle.files)) {
        suppressionCount += [
          ...content.matchAll(/@ts-(?:nocheck|ignore|expect-error)\b/g),
        ].length;
        const target = join(root, 'node_modules', path);
        if (sources.has(target)) throw new Error();
        sources.set(target, content);
      }
    }
    const options: ts.CompilerOptions = {
      noEmit: true,
      allowJs: true,
      checkJs: true,
      strict: true,
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.Preserve,
    };
    const libRoot = dirname(ts.getDefaultLibFilePath(options));
    for (const lib of await readdir(libRoot)) {
      if (/^lib[.a-z0-9-]*\.d\.ts$/.test(lib)) {
        const path = join(libRoot, lib);
        sources.set(path, await readFile(path, 'utf8'));
      }
    }
    const directories = new Set<string>();
    for (const path of sources.keys()) {
      let directory = dirname(path);
      while (directory !== dirname(directory)) {
        directories.add(directory);
        directory = dirname(directory);
      }
    }
    const host: ts.CompilerHost = {
      getSourceFile: (name, languageVersion) => {
        const text = sources.get(name);
        return text === undefined
          ? undefined
          : ts.createSourceFile(name, text, languageVersion);
      },
      getDefaultLibFileName: () => ts.getDefaultLibFilePath(options),
      writeFile: () => {
        throw new Error();
      },
      getCurrentDirectory: () => root,
      getDirectories: () => [],
      getCanonicalFileName: (name) => name,
      useCaseSensitiveFileNames: () => true,
      getNewLine: () => '\n',
      fileExists: (name) => sources.has(name),
      readFile: (name) => sources.get(name),
      directoryExists: (name) => directories.has(name),
    };
    const diagnostics = ts.getPreEmitDiagnostics(
      ts.createProgram(files, options, host),
    );
    findings = diagnostics.length;
    unresolved = diagnostics.filter((diagnostic) =>
      [2307, 2688, 7016, 2792].includes(diagnostic.code),
    ).length;
  }
  process.stdout.write(
    JSON.stringify({
      protocol: 1,
      id,
      fileCount: files.length,
      findings,
      unresolved,
      suppressionCount,
    }),
  );
}
main().catch(() => {
  process.exitCode = 2;
});
