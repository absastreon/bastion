/**
 * F005: .gitignore coverage check
 * Verifies that essential entries are present in the project's .gitignore
 * to prevent accidental commit of secrets, dependencies, and build artifacts.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, CheckResult, Severity } from '@bastion/shared';

/** Entry that should be present in .gitignore */
interface RequiredEntry {
  readonly id: string;
  readonly pattern: string;
  readonly severity: Severity;
  readonly description: string;
  readonly fix: string;
  readonly aiPrompt: string;
}

/** Essential .gitignore entries with severity levels */
const REQUIRED_ENTRIES: readonly RequiredEntry[] = [
  {
    id: 'gitignore-env',
    pattern: '.env',
    severity: 'critical',
    description: 'Environment file (.env) is not gitignored — secrets may be committed',
    fix: 'Add `.env` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `.env`. Explain the security risk of committing environment files and suggest a comprehensive .gitignore for my project.',
  },
  {
    id: 'gitignore-env-local',
    pattern: '.env.local',
    severity: 'critical',
    description: 'Local environment file (.env.local) is not gitignored — secrets may be committed',
    fix: 'Add `.env.local` to your .gitignore (or `.env*` to cover all env variants)',
    aiPrompt:
      'My project .gitignore is missing `.env.local`. Explain why local environment files should never be committed and how to properly manage environment variables.',
  },
  {
    id: 'gitignore-node-modules',
    pattern: 'node_modules',
    severity: 'high',
    description:
      'node_modules is not gitignored — bloats repository and may leak internal paths',
    fix: 'Add `node_modules` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `node_modules`. Explain why dependencies should not be committed and the security implications.',
  },
  {
    id: 'gitignore-pem',
    pattern: '*.pem',
    severity: 'high',
    description:
      'PEM certificate files (*.pem) are not gitignored — private keys may be committed',
    fix: 'Add `*.pem` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `*.pem`. Explain the risk of committing SSL/TLS certificates and private keys.',
  },
  {
    id: 'gitignore-key',
    pattern: '*.key',
    severity: 'high',
    description:
      'Key files (*.key) are not gitignored — private keys may be committed',
    fix: 'Add `*.key` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `*.key`. Explain the risk of committing cryptographic key files to version control.',
  },
  {
    id: 'gitignore-next',
    pattern: '.next',
    severity: 'medium',
    description:
      'Next.js build output (.next) is not gitignored — build artifacts bloat the repository',
    fix: 'Add `.next` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `.next`. Explain why build artifacts should not be committed.',
  },
  {
    id: 'gitignore-dist',
    pattern: 'dist',
    severity: 'medium',
    description:
      'Build output (dist) is not gitignored — compiled files bloat the repository',
    fix: 'Add `dist` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `dist`. Explain why build output should be gitignored.',
  },
  {
    id: 'gitignore-build',
    pattern: 'build',
    severity: 'medium',
    description:
      'Build output (build) is not gitignored — compiled files bloat the repository',
    fix: 'Add `build` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `build`. Explain why build output directories should be gitignored.',
  },
  {
    id: 'gitignore-ds-store',
    pattern: '.DS_Store',
    severity: 'medium',
    description:
      'macOS metadata files (.DS_Store) are not gitignored — OS-specific files should not be committed',
    fix: 'Add `.DS_Store` to your .gitignore file',
    aiPrompt:
      'My project .gitignore is missing `.DS_Store`. Explain why OS-specific metadata files should be gitignored.',
  },
];

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit testing)
// ---------------------------------------------------------------------------

/** Parse .gitignore content into active pattern lines */
export function parseGitignore(content: string): readonly string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

/** Normalize a gitignore line: strip leading `/` anchor and trailing `/` */
function normalizeLine(line: string): string {
  let result = line;
  if (result.startsWith('/')) result = result.slice(1);
  if (result.endsWith('/')) result = result.slice(0, -1);
  return result;
}

/** Escape regex special characters */
function escapeRegex(s: string): string {
  return s.replace(/[.+^${}()|[\]\\?]/g, '\\$&');
}

/** Test if a simple glob pattern (with `*`) matches a text string */
function globMatches(pattern: string, text: string): boolean {
  const regexStr = pattern.split('*').map(escapeRegex).join('[^/]*');
  return new RegExp(`^${regexStr}$`).test(text);
}

/**
 * Check if a required entry is covered by any gitignore line.
 * Handles exact matches, trailing/leading slashes, and glob patterns.
 */
export function isEntryCovered(entry: string, lines: readonly string[]): boolean {
  for (const raw of lines) {
    const line = normalizeLine(raw);

    // Negation patterns do not provide coverage
    if (line.startsWith('!')) continue;

    // Exact match after normalization
    if (line === entry) return true;

    // If the required entry is itself a glob (e.g. *.pem),
    // only an exact pattern match satisfies it — skip glob expansion
    if (entry.includes('*')) continue;

    // Check if the gitignore glob pattern covers the literal entry
    if (line.includes('*') && globMatches(line, entry)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Check function
// ---------------------------------------------------------------------------

/** F005: .gitignore coverage check */
const gitignoreCheck: CheckFunction = async (context) => {
  let content: string;

  try {
    content = await readFile(join(context.projectPath, '.gitignore'), 'utf-8');
  } catch (error: unknown) {
    const isNotFound =
      error instanceof Error &&
      'code' in error &&
      (error as NodeJS.ErrnoException).code === 'ENOENT';

    if (isNotFound) {
      return [
        {
          id: 'gitignore-missing',
          name: '.gitignore coverage',
          status: 'fail',
          severity: 'critical',
          category: 'configuration',
          description:
            'No .gitignore file found — sensitive files, dependencies, and build artifacts may be committed',
          fix: 'Create a .gitignore file with entries for .env, node_modules, build outputs, and key files',
          aiPrompt: `My ${context.stack.language} project has no .gitignore file. Generate a comprehensive .gitignore that covers environment files, dependencies, build outputs, IDE files, OS files, and cryptographic keys.`,
        },
      ];
    }

    // Unexpected error — return skip rather than throwing
    return [
      {
        id: 'gitignore-error',
        name: '.gitignore coverage',
        status: 'skip',
        severity: 'info',
        category: 'configuration',
        description: `Could not read .gitignore: ${error instanceof Error ? error.message : String(error)}`,
      },
    ];
  }

  const lines = parseGitignore(content);
  const results: CheckResult[] = [];

  for (const entry of REQUIRED_ENTRIES) {
    if (!isEntryCovered(entry.pattern, lines)) {
      results.push({
        id: entry.id,
        name: '.gitignore coverage',
        status: 'fail',
        severity: entry.severity,
        category: 'configuration',
        location: '.gitignore',
        description: entry.description,
        fix: entry.fix,
        aiPrompt: entry.aiPrompt,
      });
    }
  }

  if (results.length === 0) {
    return [
      {
        id: 'gitignore-coverage',
        name: '.gitignore coverage',
        status: 'pass',
        severity: 'info',
        category: 'configuration',
        location: '.gitignore',
        description: 'All essential entries are present in .gitignore',
      },
    ];
  }

  return results;
};

export default gitignoreCheck;
