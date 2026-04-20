/**
 * F011: Stack detector — auto-detect framework, database, auth, hosting, language
 * from package.json dependencies and file patterns.
 */
import type { DetectedStack } from '@bastion/shared';

/** Matcher: first package found in deps → detected value */
interface PackageMatcher {
  readonly packages: readonly string[];
  readonly value: string;
}

const FRAMEWORK_MATCHERS: readonly PackageMatcher[] = [
  { packages: ['next'], value: 'next.js' },
  { packages: ['express'], value: 'express' },
  { packages: ['fastify'], value: 'fastify' },
  { packages: ['@remix-run/node', '@remix-run/react'], value: 'remix' },
  { packages: ['astro'], value: 'astro' },
  { packages: ['nuxt'], value: 'nuxt' },
  { packages: ['@sveltejs/kit'], value: 'sveltekit' },
  { packages: ['hono'], value: 'hono' },
];

const DATABASE_MATCHERS: readonly PackageMatcher[] = [
  { packages: ['@supabase/supabase-js'], value: 'supabase' },
  { packages: ['@prisma/client', 'prisma'], value: 'prisma' },
  { packages: ['drizzle-orm'], value: 'drizzle' },
  { packages: ['mongoose'], value: 'mongoose' },
  { packages: ['typeorm'], value: 'typeorm' },
  { packages: ['sequelize'], value: 'sequelize' },
];

const AUTH_MATCHERS: readonly PackageMatcher[] = [
  { packages: ['@clerk/nextjs', '@clerk/clerk-sdk-node', '@clerk/express'], value: 'clerk' },
  { packages: ['auth0', '@auth0/nextjs-auth0', '@auth0/auth0-react'], value: 'auth0' },
  { packages: ['next-auth', '@auth/core'], value: 'next-auth' },
  { packages: ['@supabase/auth-helpers-nextjs', '@supabase/auth-helpers-react', '@supabase/ssr'], value: 'supabase-auth' },
  { packages: ['passport'], value: 'passport' },
  { packages: ['lucia'], value: 'lucia' },
];

/** Find first matcher whose packages overlap with deps */
function findMatch(
  matchers: readonly PackageMatcher[],
  deps: ReadonlySet<string>,
): string | undefined {
  for (const matcher of matchers) {
    if (matcher.packages.some((pkg) => deps.has(pkg))) {
      return matcher.value;
    }
  }
  return undefined;
}

/** Detect hosting from presence of config files */
function detectHosting(fileSet: ReadonlySet<string>): string | undefined {
  if (fileSet.has('vercel.json')) return 'vercel';
  if (fileSet.has('netlify.toml')) return 'netlify';
  if (fileSet.has('Dockerfile') || fileSet.has('dockerfile')) return 'docker';
  return undefined;
}

/** Detect language from file patterns */
function detectLanguage(
  files: readonly string[],
  hasPackageJson: boolean,
): string {
  if (files.some((f) => f === 'tsconfig.json' || f.endsWith('/tsconfig.json'))) {
    return 'typescript';
  }
  return hasPackageJson ? 'javascript' : 'unknown';
}

/** Detect package manager from lock files */
function detectPackageManager(
  fileSet: ReadonlySet<string>,
  hasPackageJson: boolean,
): string | undefined {
  if (fileSet.has('pnpm-lock.yaml')) return 'pnpm';
  if (fileSet.has('yarn.lock')) return 'yarn';
  if (fileSet.has('bun.lockb') || fileSet.has('bun.lock')) return 'bun';
  if (fileSet.has('package-lock.json')) return 'npm';
  return hasPackageJson ? 'npm' : undefined;
}

/** Extract all dependency names from package.json */
function extractDependencies(packageJson: Record<string, unknown>): readonly string[] {
  const deps = packageJson['dependencies'];
  const devDeps = packageJson['devDependencies'];
  const names: string[] = [];

  if (deps !== null && typeof deps === 'object' && !Array.isArray(deps)) {
    names.push(...Object.keys(deps as Record<string, unknown>));
  }
  if (devDeps !== null && typeof devDeps === 'object' && !Array.isArray(devDeps)) {
    names.push(...Object.keys(devDeps as Record<string, unknown>));
  }

  return names;
}

/**
 * Detect the project's technology stack from package.json and file patterns.
 * Pure function — no filesystem I/O.
 */
export function detectStack(
  packageJson: Record<string, unknown> | undefined,
  files: readonly string[],
): DetectedStack {
  const hasPackageJson = packageJson !== undefined;
  const dependencies = hasPackageJson ? extractDependencies(packageJson) : [];
  const depSet: ReadonlySet<string> = new Set(dependencies);
  const fileSet: ReadonlySet<string> = new Set(files);

  return {
    language: detectLanguage(files, hasPackageJson),
    framework: findMatch(FRAMEWORK_MATCHERS, depSet),
    database: findMatch(DATABASE_MATCHERS, depSet),
    auth: findMatch(AUTH_MATCHERS, depSet),
    hosting: detectHosting(fileSet),
    packageManager: detectPackageManager(fileSet, hasPackageJson),
    dependencies,
  };
}
