import { statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

/**
 * Shared JVM launcher for every Java-based engine (PMD, Checkstyle and, in
 * the Kotlin engines, ktlint/detekt). The JDK is provisioned by the workflow
 * (`actions/setup-java`, Temurin {@link jdkMajor}); this module only locates
 * it and fixes the JVM flags, so engine adapters never build their own.
 * The JDK is the runner's trusted toolchain and is not sha256-pinned: the
 * engines that run on it (jar or distribution tree) are.
 */
export const jdkMajor = 21;

/** Fixed JVM flags: headless, UTF-8, bounded heap, no state outside the workspace. */
export const jvmFlags: readonly string[] = Object.freeze([
  '-Xmx1g',
  '-Dfile.encoding=UTF-8',
  '-Djava.awt.headless=true',
  '-XX:+ExitOnOutOfMemoryError',
]);

export interface JavaResolution {
  /** Absolute path of the `java` launcher, when one was found. */
  java?: string;
  /** Why none was found; shown as the failed engine's reason. */
  error?: string;
}

const isFile = (path: string): boolean => {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
};

/**
 * Locate `java`: an explicit absolute path (`--java`) wins, then
 * `$JAVA_HOME/bin/java`. A missing runtime is an error, never a skip.
 */
export function resolveJava(
  explicit: string | undefined,
  environment: Readonly<Record<string, string | undefined>>,
): JavaResolution {
  const candidate =
    explicit ??
    (environment.JAVA_HOME ? join(environment.JAVA_HOME, 'bin', 'java') : '');
  if (!candidate || !isAbsolute(candidate) || candidate.includes('\0'))
    return {
      error: `no Java ${String(jdkMajor)} runtime: pass --java or set JAVA_HOME (the workflow uses actions/setup-java)`,
    };
  return isFile(candidate)
    ? { java: candidate }
    : { error: `Java runtime not found at ${candidate}` };
}

/** The `runtime` block of a JVM engine adapter (see `ScannerAdapter.runtime`). */
export function javaRuntime(
  java: string,
  engineArgs: readonly string[],
): { executable: string; args: readonly string[] } {
  return { executable: java, args: [...jvmFlags, ...engineArgs] };
}
