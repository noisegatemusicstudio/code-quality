import type { EngineId } from './quality-scan.js';

/**
 * Languages and file types the quality standard covers (docs/language-profiles.md).
 * `engines` lists engines that actually analyse that language today; an empty
 * list means the standard tool is not wired in yet. Language-agnostic engines
 * (gitleaks, jscpd) are not listed here because they say nothing about
 * language-specific rules.
 */
interface LanguageRule {
  language: string;
  test: (path: string) => boolean;
  engines: readonly EngineId[];
}
const ext = (pattern: RegExp) => (path: string) => pattern.test(path);
const base = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

const rules: readonly LanguageRule[] = [
  {
    language: 'TypeScript',
    test: ext(/\.(?:[cm]?ts|tsx)$/),
    engines: ['eslint', 'prettier', 'semgrep'],
  },
  {
    language: 'JavaScript',
    test: ext(/\.(?:[cm]?js|jsx)$/),
    engines: ['eslint', 'prettier', 'semgrep'],
  },
  { language: 'JSON', test: ext(/\.json$/), engines: ['prettier'] },
  { language: 'CSS', test: ext(/\.css$/), engines: ['prettier'] },
  { language: 'Python', test: ext(/\.pyi?$/), engines: ['ruff'] },
  { language: 'Java', test: ext(/\.java$/), engines: ['pmd', 'checkstyle'] },
  {
    language: 'Kotlin',
    test: ext(/\.kts?$/),
    engines: ['detekt', 'ktlint'],
  },
  { language: 'Swift', test: ext(/\.swift$/), engines: [] },
  {
    language: 'Shell',
    test: ext(/\.(?:sh|bash|ksh)$/),
    engines: ['shellcheck', 'shfmt'],
  },
  {
    language: 'Dockerfile',
    test: (p) =>
      /^(?:Dockerfile|Containerfile)(?:\.[A-Za-z0-9_-]+)?$/.test(base(p)) &&
      !p.endsWith('.dockerignore'),
    engines: ['trivy', 'hadolint'],
  },
  {
    language: 'Terraform',
    test: ext(/\.(?:tf|tfvars)$/),
    engines: ['trivy', 'tflint'],
  },
  {
    language: 'GitHub Actions',
    test: ext(/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/),
    engines: ['actionlint', 'zizmor'],
  },
  {
    language: 'YAML',
    test: ext(/\.ya?ml$/),
    engines: ['prettier', 'yamllint'],
  },
  {
    language: 'Markdown',
    test: ext(/\.(?:md|markdown)$/),
    engines: ['prettier', 'markdownlint'],
  },
];

export interface LanguageReport {
  language: string;
  files: number;
  engines: EngineId[];
  /** `covered` only when at least one language-aware engine exists for it. */
  status: 'covered' | 'skipped: no engine yet';
}

/** Count tracked files per language. A file may count for GitHub Actions and YAML; unknown types are ignored. */
export function detectLanguages(paths: readonly string[]): LanguageReport[] {
  const out: LanguageReport[] = [];
  for (const rule of rules) {
    const files = paths.filter((p) => rule.test(p)).length;
    if (files === 0) continue;
    out.push({
      language: rule.language,
      files,
      engines: [...rule.engines],
      status: rule.engines.length > 0 ? 'covered' : 'skipped: no engine yet',
    });
  }
  return out;
}

export function renderLanguages(
  languages: readonly LanguageReport[],
): string[] {
  if (languages.length === 0) return [];
  return [
    '### Languages',
    '',
    '| Language | Files | Status |',
    '| --- | ---: | --- |',
    ...languages.map(
      (l) =>
        `| ${l.language} | ${String(l.files)} | ${l.status === 'covered' ? `analysed by ${l.engines.join(', ')}` : l.status} |`,
    ),
    '',
    '"skipped: no engine yet" means no language-specific analysis ran. It is not a clean result.',
    '',
  ];
}
