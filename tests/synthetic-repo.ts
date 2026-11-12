/*
Test classification: unit
Review status: Not Reviewed
Evidence: synthetic
Scope: Shared helper that creates a temporary git repository with one committed file; asserts nothing itself.
*/
import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Create a temp repository whose single commit holds `name` with `content`. */
export async function commitRepo(
  prefix: string,
  name: string,
  content: string,
): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), prefix));
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
  git('init', '-q');
  await writeFile(join(repo, name), content);
  git('add', '.');
  git(
    '-c',
    'user.email=t@example.com',
    '-c',
    'user.name=t',
    'commit',
    '-q',
    '-m',
    'x',
  );
  return repo;
}
