/**
 * F018: Authentication method detection
 *
 * Checks if the project uses an established auth provider, custom auth
 * implementation, or no auth at all. Recommends the best provider for
 * the detected stack.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, DetectedStack, ScanContext } from '@bastion/shared';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Human-readable names for detected auth providers */
const PROVIDER_NAMES: Readonly<Record<string, string>> = {
  clerk: 'Clerk',
  auth0: 'Auth0',
  'next-auth': 'NextAuth.js',
  'supabase-auth': 'Supabase Auth',
  passport: 'Passport.js',
  lucia: 'Lucia',
};

/** Packages that indicate custom auth implementation */
const CUSTOM_AUTH_PACKAGES: readonly string[] = [
  'bcrypt',
  'bcryptjs',
  'argon2',
  'jsonwebtoken',
];

/** Regex patterns for custom auth in source files */
interface AuthFilePattern {
  readonly name: string;
  readonly regex: RegExp;
}

const AUTH_FILE_PATTERNS: readonly AuthFilePattern[] = [
  { name: 'crypto.scrypt', regex: /crypto\.scrypt(?:Sync)?\s*\(/ },
  { name: 'crypto.pbkdf2', regex: /crypto\.pbkdf2(?:Sync)?\s*\(/ },
  { name: 'jwt.sign', regex: /jwt\.sign\s*\(/ },
  { name: 'jwt.verify', regex: /jwt\.verify\s*\(/ },
  { name: 'password hashing', regex: /(?:hashPassword|comparePassword|verifyPassword|passwordHash)\s*[=(]/ },
];

/** Source file extensions to scan */
const SCANNABLE_EXTENSIONS = new Set(['.ts', '.js', '.tsx', '.jsx']);

/** Directories to skip during file scanning */
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git']);

/** Directory names that indicate user-facing features */
const USER_FACING_DIRS = new Set(['api', 'routes', 'pages', 'views']);

// ---------------------------------------------------------------------------
// Pure helpers (exported for testing)
// ---------------------------------------------------------------------------

/** Find custom auth packages in the dependency list */
export function findCustomAuthDeps(
  dependencies: readonly string[],
): readonly string[] {
  return dependencies.filter((dep) => CUSTOM_AUTH_PACKAGES.includes(dep));
}

/** Scan file content for custom auth patterns, returns matched pattern names */
export function scanFileForAuthPatterns(content: string): readonly string[] {
  const found: string[] = [];
  for (const pattern of AUTH_FILE_PATTERNS) {
    if (pattern.regex.test(content)) {
      found.push(pattern.name);
    }
  }
  return found;
}

/** Check if project has API routes or user-facing features */
export function hasUserFacingFeatures(context: ScanContext): boolean {
  if (context.stack.framework) return true;
  return context.files.some((f) =>
    f.split('/').some((segment) => USER_FACING_DIRS.has(segment)),
  );
}

/** Check if project appears to be a library, CLI tool, or monorepo root */
export function isLibraryOrCli(context: ScanContext): boolean {
  if (!context.packageJson) return false;
  if (context.packageJson['bin']) return true;
  // Monorepo roots (private + workspaces) are tooling, not user-facing apps
  if (context.packageJson['private'] && context.packageJson['workspaces']) return true;
  if (
    !context.stack.framework &&
    (context.packageJson['main'] || context.packageJson['exports'])
  ) {
    return true;
  }
  return false;
}

/** Get recommended auth provider for the detected stack */
export function getRecommendedProvider(stack: DetectedStack): string {
  switch (stack.framework) {
    case 'next.js':
      return stack.database === 'supabase' ? 'Supabase Auth' : 'Clerk or NextAuth.js';
    case 'express':
    case 'fastify':
    case 'hono':
      return 'Auth0 or Passport.js';
    case 'remix':
      return 'Auth0 or Lucia';
    case 'sveltekit':
      return 'Lucia or Auth.js';
    case 'nuxt':
      return 'Auth0 or Sidebase Auth';
    case 'astro':
      return 'Lucia or Auth.js';
    default:
      return 'Clerk or Auth0';
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Check whether a file should be scanned for auth patterns */
function isScannableFile(relativePath: string): boolean {
  const segments = relativePath.split('/');
  const fileName = segments[segments.length - 1] ?? '';
  const ext = fileName.includes('.') ? '.' + (fileName.split('.').pop() ?? '') : '';
  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;
  if (segments.some((s) => IGNORED_DIRS.has(s))) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Main check
// ---------------------------------------------------------------------------

/** F018 check: detect authentication method */
const authCheck: CheckFunction = async (context) => {
  const recommended = getRecommendedProvider(context.stack);
  const stackLabel = context.stack.framework ?? context.stack.language;

  // 1. Established auth provider detected via stack detector
  if (context.stack.auth) {
    const providerName = PROVIDER_NAMES[context.stack.auth] ?? context.stack.auth;
    return [
      {
        id: 'auth',
        name: 'Authentication method',
        status: 'pass',
        severity: 'info',
        category: 'Authentication',
        description: `Established auth provider detected: ${providerName}`,
        fix: `Ensure ${providerName} is configured securely with proper session management and CSRF protection.`,
        aiPrompt:
          `I'm using ${providerName} for authentication in my ${stackLabel} project. ` +
          `Help me ensure it's configured securely. Show me: ` +
          `(1) how to protect all API routes, ` +
          `(2) how to set up role-based access control, ` +
          `(3) how to implement secure session management, ` +
          `(4) best practices for ${providerName} specifically.`,
      },
    ];
  }

  // 2. Check for custom auth — first via dependencies (fast), then via file scan
  const deps = context.stack.dependencies ?? [];
  const customAuthDeps = findCustomAuthDeps(deps);

  if (customAuthDeps.length > 0) {
    return [
      {
        id: 'auth',
        name: 'Authentication method',
        status: 'warn',
        severity: 'medium',
        category: 'Authentication',
        description: `Custom auth implementation detected via dependencies: ${customAuthDeps.join(', ')}. Consider using an established auth provider.`,
        fix: `Replace custom auth with ${recommended}. Established providers handle password hashing, session management, CSRF protection, and security updates automatically.`,
        aiPrompt:
          `I'm using custom authentication (${customAuthDeps.join(', ')}) in my ${stackLabel} project. ` +
          `Help me migrate to ${recommended}. Show me: ` +
          `(1) how to install and configure it, ` +
          `(2) how to protect API routes, ` +
          `(3) how to handle user sessions, ` +
          `(4) how to implement sign-up and login flows.`,
      },
    ];
  }

  // Scan source files for auth patterns (catches Node.js built-in crypto usage)
  const filesToScan = context.files.filter(isScannableFile);
  const allPatterns: string[] = [];

  if (filesToScan.length > 0) {
    const settled = await Promise.allSettled(
      filesToScan.map(async (file) => {
        const content = await readFile(join(context.projectPath, file), 'utf-8');
        return scanFileForAuthPatterns(content);
      }),
    );

    for (const outcome of settled) {
      if (outcome.status === 'fulfilled' && outcome.value.length > 0) {
        allPatterns.push(...outcome.value);
      }
    }
  }

  if (allPatterns.length > 0) {
    const unique = [...new Set(allPatterns)];
    return [
      {
        id: 'auth',
        name: 'Authentication method',
        status: 'warn',
        severity: 'medium',
        category: 'Authentication',
        description: `Custom auth patterns detected: ${unique.join(', ')}. Consider using an established auth provider.`,
        fix: `Replace custom auth with ${recommended}. Established providers handle password hashing, session management, CSRF protection, and security updates automatically.`,
        aiPrompt:
          `I'm using custom authentication patterns (${unique.join(', ')}) in my ${stackLabel} project. ` +
          `Help me migrate to ${recommended}. Show me: ` +
          `(1) how to install and configure it, ` +
          `(2) how to protect API routes, ` +
          `(3) how to handle user sessions, ` +
          `(4) how to implement sign-up and login flows.`,
      },
    ];
  }

  // 3. No auth detected — skip for libraries and CLI tools
  if (isLibraryOrCli(context)) {
    return [
      {
        id: 'auth',
        name: 'Authentication method',
        status: 'skip',
        severity: 'info',
        category: 'Authentication',
        description: 'Project appears to be a library or CLI tool — authentication check not applicable.',
      },
    ];
  }

  // 4. No auth + user-facing features → fail
  if (hasUserFacingFeatures(context)) {
    return [
      {
        id: 'auth',
        name: 'Authentication method',
        status: 'fail',
        severity: 'high',
        category: 'Authentication',
        description: 'No authentication detected in a project with API routes or user-facing features.',
        fix: `Add authentication using ${recommended}. This protects your API routes and user data from unauthorized access.`,
        aiPrompt:
          `My ${stackLabel} project has no authentication. ` +
          `Help me add authentication using ${recommended}. Show me: ` +
          `(1) how to install and configure it, ` +
          `(2) how to protect API routes and pages, ` +
          `(3) how to implement sign-up, login, and logout flows, ` +
          `(4) how to manage user sessions securely.`,
      },
    ];
  }

  // 5. No user-facing features detected — skip
  return [
    {
      id: 'auth',
      name: 'Authentication method',
      status: 'skip',
      severity: 'info',
      category: 'Authentication',
      description: 'No user-facing features detected — authentication check not applicable.',
    },
  ];
};

export default authCheck;
