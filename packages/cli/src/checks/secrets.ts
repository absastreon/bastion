/**
 * F006: Hardcoded secrets detection
 *
 * Scans source files for patterns that indicate hardcoded API keys,
 * tokens, and credentials. Returns a CheckResult per finding.
 */
import { readFile } from 'node:fs/promises';
import { join, basename } from 'node:path';
import type { CheckFunction, CheckResult } from 'bastion-shared';

/** File extensions to scan for secrets */
const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.js',
  '.tsx',
  '.jsx',
  '.env',
  '.json',
  '.yaml',
  '.yml',
]);

/** Directory segments to skip */
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'tests', '__tests__', 'test', 'fixtures']);

/** A secret pattern definition */
interface SecretPattern {
  readonly name: string;
  readonly regex: RegExp;
  readonly description: string;
}

/** Patterns that indicate hardcoded secrets */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'OpenAI API key',
    regex: /sk-[A-Za-z0-9]{20,}/,
    description: 'OpenAI API key detected',
  },
  {
    name: 'Stripe secret key',
    regex: /sk_live_[A-Za-z0-9]{20,}/,
    description: 'Stripe secret key detected',
  },
  {
    name: 'Stripe publishable key',
    regex: /pk_live_[A-Za-z0-9]{20,}/,
    description: 'Stripe publishable live key detected',
  },
  {
    name: 'AWS access key',
    regex: /AKIA[0-9A-Z]{16}/,
    description: 'AWS access key ID detected',
  },
  {
    name: 'Generic API key assignment',
    regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-/.]{8,}['"]/i,
    description: 'Hardcoded API key assignment detected',
  },
  {
    name: 'Bearer token',
    regex: /['"]Bearer\s+[A-Za-z0-9_\-/.+]{20,}['"]/,
    description: 'Hardcoded Bearer token detected',
  },
  {
    name: 'Database connection string',
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^:]+:[^@\s]+@/i,
    description: 'Database connection string with embedded password detected',
  },
];

const AI_PROMPT =
  'I found a hardcoded secret in my source code. ' +
  'Help me move it to an environment variable. ' +
  'Show me: (1) how to add it to .env, (2) how to read it with process.env ' +
  'or the equivalent for my framework, (3) how to add the key name to .env.example ' +
  'with a placeholder value, and (4) how to validate at startup that the variable is set.';

/** Check whether a file path should be scanned */
function isScannableFile(relativePath: string): boolean {
  const segments = relativePath.split('/');
  const fileName = segments[segments.length - 1] ?? '';
  const ext = fileName.includes('.') ? '.' + (fileName.split('.').pop() ?? '') : '';

  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;
  if (segments.some((s) => IGNORED_DIRS.has(s))) return false;
  if (basename(relativePath) === '.env.example') return false;
  if (/\.(?:test|spec)\.[jt]sx?$/.test(fileName)) return false;

  return true;
}

/** Scan a single file's contents for secret patterns */
function scanContent(
  content: string,
  relativePath: string,
): readonly CheckResult[] {
  const lines = content.split('\n');
  const results: CheckResult[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;

    // Skip comment-only lines (common in docs/examples)
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      continue;
    }

    // Skip string constants, template literals, and regex literals
    if (trimmed.startsWith("'") || trimmed.startsWith('"') || trimmed.startsWith('`') || trimmed.startsWith('/')) {
      continue;
    }
    // Skip object property values — pattern definitions, fix text, AI prompts
    if (/^\w+\s*:\s*['"`/([]/.test(trimmed)) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(line)) {
        results.push({
          id: 'secrets',
          name: `Hardcoded secret: ${pattern.name}`,
          status: 'fail',
          severity: 'critical',
          category: 'Secrets',
          location: `${relativePath}:${i + 1}`,
          description: pattern.description,
          fix: `Remove the hardcoded value and load it from an environment variable instead. Add the key to .env (gitignored) and a placeholder to .env.example.`,
          aiPrompt: AI_PROMPT,
        });
      }
    }
  }

  return results;
}

/** F006 check: scan project files for hardcoded secrets */
const secretsCheck: CheckFunction = async (context) => {
  const filesToScan = context.files.filter(isScannableFile);

  if (filesToScan.length === 0) {
    return [
      {
        id: 'secrets',
        name: 'Hardcoded secrets',
        status: 'skip',
        severity: 'info',
        description: 'No scannable files found',
      },
    ];
  }

  const allResults: CheckResult[] = [];

  const settled = await Promise.allSettled(
    filesToScan.map(async (file) => {
      const content = await readFile(join(context.projectPath, file), 'utf-8');
      return scanContent(content, file);
    }),
  );

  for (const outcome of settled) {
    if (outcome.status === 'fulfilled') {
      allResults.push(...outcome.value);
    }
    // Silently skip files that can't be read (permissions, binary, etc.)
  }

  if (allResults.length === 0) {
    return [
      {
        id: 'secrets',
        name: 'Hardcoded secrets',
        status: 'pass',
        severity: 'info',
        description: 'No hardcoded secrets detected',
      },
    ];
  }

  return allResults;
};

export default secretsCheck;

// Exported for testing
export { isScannableFile, scanContent, SECRET_PATTERNS };
