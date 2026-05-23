/**
 * F017: Rate limiting detection
 *
 * Scans for rate limiting middleware in dependencies and source files.
 * Without rate limiting, brute-force attacks are trivial.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, DetectedStack } from '@bastion/shared';

/** Known rate limiting packages in npm */
const RATE_LIMIT_PACKAGES: readonly string[] = [
  'express-rate-limit',
  '@upstash/ratelimit',
  'rate-limiter-flexible',
  '@fastify/rate-limit',
  'fastify-rate-limit',
];

/** Source patterns indicating rate limiting middleware usage */
const RATE_LIMIT_PATTERNS: readonly RegExp[] = [
  // Package imports (ESM)
  /from\s+['"]express-rate-limit['"]/,
  /from\s+['"]@upstash\/ratelimit['"]/,
  /from\s+['"]rate-limiter-flexible['"]/,
  /from\s+['"]@fastify\/rate-limit['"]/,
  /from\s+['"]hono\/rate-limit['"]/,
  // Package imports (CJS)
  /require\s*\(\s*['"]express-rate-limit['"]\s*\)/,
  /require\s*\(\s*['"]@upstash\/ratelimit['"]\s*\)/,
  /require\s*\(\s*['"]rate-limiter-flexible['"]\s*\)/,
  /require\s*\(\s*['"]@fastify\/rate-limit['"]\s*\)/,
  // Common function call patterns
  /rateLimit\s*\(/,
  // rate-limiter-flexible class constructors
  /RateLimiterMemory|RateLimiterRedis|RateLimiterMongo/,
];

/** File extensions to scan for rate limiting patterns */
const SCANNABLE_EXTENSIONS = new Set(['.ts', '.js', '.tsx', '.jsx']);

/** Directory segments to skip */
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git']);

/** Stack-specific rate limiter recommendation */
interface StackRecommendation {
  readonly packageName: string;
  readonly install: string;
}

/** Get the recommended rate limiting package for the detected stack */
function getRecommendation(stack: DetectedStack): StackRecommendation {
  switch (stack.framework) {
    case 'express':
      return {
        packageName: 'express-rate-limit',
        install: 'npm install express-rate-limit',
      };
    case 'fastify':
      return {
        packageName: '@fastify/rate-limit',
        install: 'npm install @fastify/rate-limit',
      };
    case 'hono':
      return {
        packageName: 'hono (built-in)',
        install: 'import { rateLimiter } from "hono/rate-limit"',
      };
    case 'next.js':
      return {
        packageName: '@upstash/ratelimit',
        install: 'npm install @upstash/ratelimit @upstash/redis',
      };
    default:
      return {
        packageName: 'rate-limiter-flexible',
        install: 'npm install rate-limiter-flexible',
      };
  }
}

/** Build AI prompt tailored to the detected stack */
function buildAiPrompt(stack: DetectedStack): string {
  const rec = getRecommendation(stack);
  const framework = stack.framework ?? 'my web application';
  return (
    `I need to add rate limiting to my ${framework} project. ` +
    `The recommended package is ${rec.packageName}. ` +
    `Show me: (1) how to install and configure it, ` +
    `(2) how to apply it to my API routes with sensible defaults, ` +
    `(3) recommended limits for login and API endpoints ` +
    `(e.g. 5 login attempts per 15 minutes, 100 API requests per minute), ` +
    `and (4) how to return proper 429 Too Many Requests responses with Retry-After headers.`
  );
}

/** Check whether a file path should be scanned */
function isScannableFile(relativePath: string): boolean {
  const segments = relativePath.split('/');
  const fileName = segments[segments.length - 1] ?? '';
  const ext = fileName.includes('.') ? '.' + (fileName.split('.').pop() ?? '') : '';

  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;
  if (segments.some((s) => IGNORED_DIRS.has(s))) return false;

  return true;
}

/** Find a rate limiting package in the dependency list */
function findRateLimitDependency(
  dependencies: readonly string[],
): string | undefined {
  return dependencies.find((dep) => RATE_LIMIT_PACKAGES.includes(dep));
}

/** Check if file content contains rate limiting patterns */
function hasRateLimitPattern(content: string): boolean {
  return RATE_LIMIT_PATTERNS.some((pattern) => pattern.test(content));
}

/** F017 check: detect presence/absence of rate limiting */
const rateLimitCheck: CheckFunction = async (context) => {
  const dependencies = context.stack.dependencies ?? [];

  // Step 1: check package.json dependencies for rate limiting packages
  const foundPackage = findRateLimitDependency(dependencies);
  if (foundPackage) {
    return [
      {
        id: 'rate-limit',
        name: 'Rate limiting',
        status: 'pass',
        severity: 'info',
        category: 'API Security',
        description: `Rate limiting package detected: ${foundPackage}`,
      },
    ];
  }

  // Step 2: scan source files for rate limiting patterns
  const filesToScan = context.files.filter(isScannableFile);

  if (filesToScan.length > 0) {
    const settled = await Promise.allSettled(
      filesToScan.map(async (file) => {
        const content = await readFile(
          join(context.projectPath, file),
          'utf-8',
        );
        return hasRateLimitPattern(content);
      }),
    );

    const foundInSource = settled.some(
      (outcome) => outcome.status === 'fulfilled' && outcome.value,
    );

    if (foundInSource) {
      return [
        {
          id: 'rate-limit',
          name: 'Rate limiting',
          status: 'pass',
          severity: 'info',
          category: 'API Security',
          description: 'Rate limiting middleware detected in source code',
        },
      ];
    }
  }

  // No rate limiting found
  const rec = getRecommendation(context.stack);
  return [
    {
      id: 'rate-limit',
      name: 'Rate limiting',
      status: 'fail',
      severity: 'high',
      category: 'API Security',
      description:
        'No rate limiting middleware detected — brute-force and denial-of-service attacks are trivial without it',
      fix: `Install a rate limiting package: ${rec.install}. Apply it to all API routes, especially authentication endpoints.`,
      aiPrompt: buildAiPrompt(context.stack),
    },
  ];
};

export default rateLimitCheck;

// Exported for testing
export {
  findRateLimitDependency,
  hasRateLimitPattern,
  getRecommendation,
  isScannableFile,
  buildAiPrompt,
  RATE_LIMIT_PACKAGES,
};
