/**
 * F006: Hardcoded secrets detection
 *
 * Scans source files for patterns that indicate hardcoded API keys,
 * tokens, and credentials. Returns a CheckResult per finding.
 */
import { readFile } from 'node:fs/promises';
import { join, basename } from 'node:path';
import type { CheckFunction, CheckResult, Severity } from 'bastion-shared';

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
  readonly severity: Severity;
}

/** Patterns that indicate hardcoded secrets */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  // ── OpenAI ──────────────────────────────────────────────────────────────
  {
    name: 'OpenAI API key (project)',
    regex: /sk-proj-[a-zA-Z0-9_-]{20,}/,
    description: 'OpenAI project API key detected',
    severity: 'critical',
  },
  {
    name: 'OpenAI API key (service account)',
    regex: /sk-svcacct-[a-zA-Z0-9_-]{20,}/,
    description: 'OpenAI service account key detected',
    severity: 'critical',
  },
  {
    name: 'OpenAI API key (legacy)',
    regex: /sk-[a-zA-Z0-9]{20,}/,
    description: 'OpenAI API key detected',
    severity: 'critical',
  },

  // ── Anthropic ───────────────────────────────────────────────────────────
  {
    name: 'Anthropic API key',
    regex: /sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{40,}/,
    description: 'Anthropic API key detected',
    severity: 'critical',
  },
  {
    name: 'Anthropic admin key',
    regex: /sk-ant-admin[0-9]{2}-[a-zA-Z0-9_-]{40,}/,
    description: 'Anthropic admin API key detected',
    severity: 'critical',
  },

  // ── GitHub ──────────────────────────────────────────────────────────────
  {
    name: 'GitHub PAT (classic)',
    regex: /ghp_[a-zA-Z0-9]{36}/,
    description: 'GitHub personal access token (classic) detected',
    severity: 'critical',
  },
  {
    name: 'GitHub OAuth token',
    regex: /gho_[a-zA-Z0-9]{36}/,
    description: 'GitHub OAuth access token detected',
    severity: 'critical',
  },
  {
    name: 'GitHub PAT (fine-grained)',
    regex: /github_pat_[a-zA-Z0-9_]{82}/,
    description: 'GitHub fine-grained personal access token detected',
    severity: 'critical',
  },
  {
    name: 'GitHub app token',
    regex: /ghs_[a-zA-Z0-9]{36}/,
    description: 'GitHub app installation token detected',
    severity: 'critical',
  },
  {
    name: 'GitHub refresh token',
    regex: /ghr_[a-zA-Z0-9]{36}/,
    description: 'GitHub refresh token detected',
    severity: 'critical',
  },

  // ── Stripe ──────────────────────────────────────────────────────────────
  {
    name: 'Stripe secret key',
    regex: /sk_live_[a-zA-Z0-9]{24,}/,
    description: 'Stripe secret key detected',
    severity: 'critical',
  },
  {
    name: 'Stripe publishable key',
    regex: /pk_live_[a-zA-Z0-9]{20,}/,
    description: 'Stripe publishable live key detected',
    severity: 'critical',
  },
  {
    name: 'Stripe restricted key',
    regex: /rk_live_[a-zA-Z0-9]{24,}/,
    description: 'Stripe restricted API key detected',
    severity: 'critical',
  },
  {
    name: 'Stripe test key',
    regex: /sk_test_[a-zA-Z0-9]{24,}/,
    description: 'Stripe test secret key detected',
    severity: 'high',
  },

  // ── AWS ─────────────────────────────────────────────────────────────────
  {
    name: 'AWS access key',
    regex: /AKIA[0-9A-Z]{16}/,
    description: 'AWS access key ID detected',
    severity: 'critical',
  },

  // ── Google ──────────────────────────────────────────────────────────────
  {
    name: 'Google API key',
    regex: /AIza[a-zA-Z0-9_-]{35}/,
    description: 'Google API key detected',
    severity: 'critical',
  },

  // ── Slack ───────────────────────────────────────────────────────────────
  {
    name: 'Slack bot token',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/,
    description: 'Slack bot token detected',
    severity: 'critical',
  },
  {
    name: 'Slack user token',
    regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}/,
    description: 'Slack user token detected',
    severity: 'critical',
  },
  {
    name: 'Slack webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]{8,12}\/B[a-zA-Z0-9]{8,12}\/[a-zA-Z0-9]{24}/,
    description: 'Slack incoming webhook URL detected',
    severity: 'high',
  },

  // ── Generic ─────────────────────────────────────────────────────────────
  {
    name: 'Generic API key assignment',
    regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-/.]{8,}['"]/i,
    description: 'Hardcoded API key assignment detected',
    severity: 'critical',
  },
  {
    name: 'Bearer token',
    regex: /['"]Bearer\s+[A-Za-z0-9_\-/.+]{20,}['"]/,
    description: 'Hardcoded Bearer token detected',
    severity: 'critical',
  },
  {
    name: 'Database connection string',
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^:]+:[^@\s]+@/i,
    description: 'Database connection string with embedded password detected',
    severity: 'critical',
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
          severity: pattern.severity,
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
