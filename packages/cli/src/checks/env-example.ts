/**
 * Check: .env.example existence — verifies a template file exists
 * when .env is gitignored, and that it contains only placeholders.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction } from '@bastion/shared';

const CHECK_ID = 'env-example';
const CHECK_NAME = '.env.example exists';

/** Strong prefixes — always indicate real credentials regardless of placeholder words */
const STRONG_PREFIXES: readonly string[] = [
  'AKIA',
  'ghp_',
  'gho_',
  'github_pat_',
  'xoxb-',
  'xoxp-',
  'glpat-',
];

/** Weak prefixes — flag as real only when no placeholder words are present */
const WEAK_PREFIXES: readonly string[] = [
  'sk-',
  'sk_live_',
  'sk_test_',
  'pk_live_',
  'pk_test_',
];

/** Words that indicate a value is an intentional placeholder */
const PLACEHOLDER_WORDS: readonly string[] = [
  'your_',
  'your-',
  'changeme',
  'change_me',
  'change-me',
  'replace',
  'xxx',
  'placeholder',
  'example',
  'sample',
  'todo',
  'fixme',
  'insert',
  '<',
  '>',
];

/** Check if a gitignore line covers the .env file */
function matchesEnvPattern(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) {
    return false;
  }
  const clean = trimmed.startsWith('/') ? trimmed.slice(1) : trimmed;
  return clean === '.env' || clean === '.env*';
}

/** Check whether .env is covered by any gitignore line */
function isEnvGitignored(content: string): boolean {
  return content.split(/\r?\n/).some(matchesEnvPattern);
}

/** Check if a value looks like a real secret rather than a placeholder */
function looksLikeRealSecret(value: string): boolean {
  const trimmed = value.trim().replace(/^["']|["']$/g, '');

  if (!trimmed) return false;

  // Strong prefixes always indicate real credentials (e.g. AKIA for AWS)
  if (STRONG_PREFIXES.some((prefix) => trimmed.startsWith(prefix))) return true;

  // Placeholder words override weaker signals
  const lower = trimmed.toLowerCase();
  if (PLACEHOLDER_WORDS.some((w) => lower.includes(w))) return false;

  // Weak prefixes flag as real when no placeholder words are present
  if (WEAK_PREFIXES.some((prefix) => trimmed.startsWith(prefix))) return true;

  if (/^[a-zA-Z0-9+/=_-]{40,}$/.test(trimmed)) return true;

  return false;
}

/** Parse .env-style content and return keys whose values look like real secrets */
function findRealSecrets(content: string): readonly string[] {
  const secrets: string[] = [];

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;

    const key = trimmed.slice(0, eqIndex);
    const value = trimmed.slice(eqIndex + 1);

    if (looksLikeRealSecret(value)) {
      secrets.push(key);
    }
  }

  return secrets;
}

/** Read a file from the project, returning undefined on failure */
async function readProjectFile(projectPath: string, filename: string): Promise<string | undefined> {
  try {
    return await readFile(join(projectPath, filename), 'utf-8');
  } catch {
    return undefined;
  }
}

/**
 * Checks that .env.example (or .env.sample) exists when .env is gitignored.
 * Optionally flags real secret values left in the template file.
 */
const envExampleCheck: CheckFunction = async (context) => {
  try {
    const gitignoreContent = await readProjectFile(context.projectPath, '.gitignore');

    if (gitignoreContent === undefined) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'skip',
          severity: 'info',
          description: 'No .gitignore found — cannot determine if .env is excluded',
        },
      ];
    }

    if (!isEnvGitignored(gitignoreContent)) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'skip',
          severity: 'info',
          description: '.env is not in .gitignore — see gitignore check for coverage',
        },
      ];
    }

    const hasExample = context.files.includes('.env.example');
    const hasSample = context.files.includes('.env.sample');

    if (!hasExample && !hasSample) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'fail',
          severity: 'high',
          category: 'configuration',
          description:
            '.env is gitignored but no .env.example or .env.sample exists. ' +
            'New developers won\u2019t know which environment variables are required, ' +
            'leading to broken setups and wasted onboarding time.',
          fix:
            'Create a .env.example file listing every required environment variable ' +
            'with placeholder values (e.g. DATABASE_URL=your_database_url_here). ' +
            'Commit it to the repository so new team members can copy it to .env ' +
            'and fill in their own values.',
          aiPrompt:
            'I have a project with a .env file that is gitignored. Generate a .env.example ' +
            'file based on my .env file. Replace all real values with descriptive placeholders ' +
            '(e.g. YOUR_API_KEY_HERE, your_database_url_here). Add comments explaining what ' +
            'each variable is for and where to get the value. Keep the structure identical ' +
            'to the original .env.',
        },
      ];
    }

    const templateFile = hasExample ? '.env.example' : '.env.sample';
    const templateContent = await readProjectFile(context.projectPath, templateFile);

    if (templateContent === undefined) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'pass',
          severity: 'info',
          category: 'configuration',
          description: `${templateFile} exists (content could not be verified)`,
        },
      ];
    }

    const realSecrets = findRealSecrets(templateContent);

    if (realSecrets.length > 0) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'fail',
          severity: 'high',
          category: 'configuration',
          location: templateFile,
          description:
            `${templateFile} appears to contain real secret values for: ` +
            `${realSecrets.join(', ')}. Template files should only contain ` +
            'placeholders, not actual credentials.',
          fix:
            `Replace real values in ${templateFile} with descriptive placeholders ` +
            'like YOUR_API_KEY_HERE or empty strings. Never commit actual secrets ' +
            'to version control, even in example files.',
          aiPrompt:
            `Review my ${templateFile} file and replace any real-looking secret values ` +
            'with safe placeholders. Keep the variable names but replace values with ' +
            'descriptive placeholders like YOUR_API_KEY_HERE. Add a comment above each ' +
            'variable explaining what it\u2019s for.',
        },
      ];
    }

    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'pass',
        severity: 'info',
        category: 'configuration',
        description: `${templateFile} exists with placeholder values`,
      },
    ];
  } catch (error: unknown) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        description: `Check failed: ${error instanceof Error ? error.message : String(error)}`,
      },
    ];
  }
};

export default envExampleCheck;
