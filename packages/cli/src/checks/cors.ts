/**
 * F016: CORS configuration check
 *
 * Scans source files for permissive CORS configurations.
 * Detects wildcard origins, bare cors() calls, and
 * dangerous credentials + wildcard combinations.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, CheckResult, DetectedStack } from '@bastion/shared';

const CHECK_ID = 'cors';
const CHECK_NAME = 'CORS configuration';

/** File extensions to scan for CORS patterns */
const SCANNABLE_EXTENSIONS = new Set(['.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs']);

/** Directory segments to skip */
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git', '.next', 'tests', '__tests__', 'test', 'fixtures']);

/** A CORS misconfiguration pattern */
interface CorsPattern {
  readonly name: string;
  readonly regex: RegExp;
  readonly kind: 'wildcard-header' | 'wildcard-config' | 'bare-cors';
}

/** Patterns that indicate CORS misconfiguration */
const CORS_PATTERNS: readonly CorsPattern[] = [
  {
    name: 'Access-Control-Allow-Origin: * (header method)',
    regex:
      /(?:\.setHeader|\.header|headers\.set|\.append)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/,
    kind: 'wildcard-header',
  },
  {
    name: 'Access-Control-Allow-Origin: * (object literal)',
    regex: /['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/,
    kind: 'wildcard-header',
  },
  {
    name: 'Wildcard origin in CORS config',
    regex: /\borigin\s*:\s*['"]\*['"]/,
    kind: 'wildcard-config',
  },
  {
    name: 'cors() with no configuration',
    regex: /\bcors\(\s*\)/,
    kind: 'bare-cors',
  },
];

/** Credentials pattern — used for severity escalation */
const CREDENTIALS_REGEX = /\bcredentials\s*:\s*true\b/;

/** Check whether a file path should be scanned */
function isScannableFile(relativePath: string): boolean {
  const segments = relativePath.split('/');
  const fileName = segments[segments.length - 1] ?? '';
  const ext = fileName.includes('.') ? '.' + (fileName.split('.').pop() ?? '') : '';

  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;
  if (segments.some((s) => IGNORED_DIRS.has(s))) return false;
  if (/\.(?:test|spec)\.[jt]sx?$/.test(fileName)) return false;

  return true;
}

/** Check whether credentials: true appears in non-comment code lines */
function hasCredentialsInCode(lines: readonly string[]): boolean {
  return lines.some((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      return false;
    }
    return CREDENTIALS_REGEX.test(line);
  });
}

/** Build stack-specific AI prompt for CORS fix */
function buildAiPrompt(stack: DetectedStack): string {
  switch (stack.framework) {
    case 'express':
      return (
        'I found a permissive CORS configuration in my Express app. ' +
        "Help me fix it by: (1) replacing cors() or cors({ origin: '*' }) " +
        "with cors({ origin: 'https://yourdomain.com' }), " +
        '(2) listing only trusted origins if multiple are needed, ' +
        '(3) explaining when credentials: true is safe to use, ' +
        '(4) showing how to use a dynamic origin function for multiple allowed domains.'
      );
    case 'next.js':
      return (
        'I found a permissive CORS configuration in my Next.js app. ' +
        'Help me fix it by: (1) replacing Access-Control-Allow-Origin: * ' +
        'with my specific domain in API routes or middleware, ' +
        '(2) showing the correct way to handle CORS in Next.js App Router and Pages Router, ' +
        '(3) explaining how to handle OPTIONS preflight requests, ' +
        '(4) showing how to use next.config.js headers for static CORS if needed.'
      );
    case 'fastify':
      return (
        'I found a permissive CORS configuration in my Fastify app. ' +
        "Help me fix it by: (1) replacing origin: '*' with my specific domain " +
        'in the @fastify/cors plugin options, ' +
        '(2) showing how to configure @fastify/cors with a whitelist of allowed origins, ' +
        "(3) explaining the difference between origin: true and origin: '*', " +
        '(4) showing how to handle credentials safely with Fastify CORS.'
      );
    default:
      return (
        'I found a permissive CORS configuration in my project. ' +
        'Help me fix it by: (1) replacing Access-Control-Allow-Origin: * ' +
        'with my specific domain, (2) listing only trusted origins, ' +
        '(3) explaining when credentials: true is safe and how it interacts with wildcard origins, ' +
        '(4) showing the correct CORS configuration for my framework.'
      );
  }
}

/** Scan a single file's contents for CORS misconfigurations */
function scanContent(
  content: string,
  relativePath: string,
  stack: DetectedStack,
): readonly CheckResult[] {
  const lines = content.split('\n');
  const hasCredentials = hasCredentialsInCode(lines);
  const results: CheckResult[] = [];
  const aiPrompt = buildAiPrompt(stack);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;

    // Skip comment lines
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      continue;
    }

    // Skip string constants, template literals, and regex literals
    if (trimmed.startsWith("'") || trimmed.startsWith('"') || trimmed.startsWith('`') || trimmed.startsWith('/')) {
      continue;
    }
    // Skip object property values (pattern definitions) but preserve CORS config properties
    if (/^(?!origin\b)\w+\s*:\s*['"`/([]/.test(trimmed)) {
      continue;
    }

    for (const pattern of CORS_PATTERNS) {
      if (!pattern.regex.test(line)) continue;

      if (pattern.kind === 'bare-cors') {
        results.push({
          id: CHECK_ID,
          name: `CORS: ${pattern.name}`,
          status: 'fail',
          severity: 'medium',
          category: 'CORS',
          location: `${relativePath}:${i + 1}`,
          description:
            'cors() called with no configuration allows all origins by default. ' +
            'Any website can make requests to your API.',
          fix: "Pass an options object with a restrictive origin: cors({ origin: 'https://yourdomain.com' })",
          aiPrompt,
        });
      } else {
        const severity = hasCredentials ? 'critical' : 'high';
        const credentialsNote = hasCredentials
          ? ' Combined with credentials: true, this allows any site to make ' +
            'authenticated requests \u2014 a serious security risk.'
          : '';

        const description =
          pattern.kind === 'wildcard-header'
            ? 'Access-Control-Allow-Origin is set to "*", allowing any website to read ' +
              `responses from your API.${credentialsNote}`
            : 'CORS origin is configured as "*", allowing any website to make ' +
              `requests to your API.${credentialsNote}`;

        const fix = hasCredentials
          ? 'Set a specific origin instead of "*" and only enable credentials for trusted origins. ' +
            'Browsers block credentials with wildcard origins, but misconfigured proxies or ' +
            'non-browser clients can still exploit this.'
          : "Set a specific origin instead of \"*\" \u2014 e.g., origin: 'https://yourdomain.com'. " +
            'Only allow origins you trust.';

        results.push({
          id: CHECK_ID,
          name: hasCredentials
            ? 'CORS: Credentials with wildcard origin'
            : `CORS: ${pattern.name}`,
          status: 'fail',
          severity,
          category: 'CORS',
          location: `${relativePath}:${i + 1}`,
          description,
          fix,
          aiPrompt,
        });
      }
    }
  }

  return results;
}

/** F016 check: scan project files for CORS misconfigurations */
const corsCheck: CheckFunction = async (context) => {
  const filesToScan = context.files.filter(isScannableFile);

  if (filesToScan.length === 0) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        description: 'No scannable source files found',
      },
    ];
  }

  const allResults: CheckResult[] = [];

  const settled = await Promise.allSettled(
    filesToScan.map(async (file) => {
      const content = await readFile(join(context.projectPath, file), 'utf-8');
      return scanContent(content, file, context.stack);
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
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'pass',
        severity: 'info',
        description: 'No permissive CORS configurations detected',
      },
    ];
  }

  return allResults;
};

export default corsCheck;

// Exported for testing
export { isScannableFile, scanContent, buildAiPrompt, CORS_PATTERNS };
