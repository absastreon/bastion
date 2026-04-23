/**
 * Scanner orchestrator — loads checks, runs them in parallel, scores results
 */
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import type {
  CheckFunction,
  CheckResult,
  ProjectType,
  ScanContext,
  ScanReport,
  ScanSummary,
} from '@bastion/shared';
import { getAllChecks, getUrlOnlyChecks, getStaticSiteSkippableChecks } from './checks/index.js';
import { detectStack } from './detectors/stack.js';
import { enrichWithAiPrompts } from './education/prompts.js';

/** Directories excluded from file listing */
const EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  '.next',
  'out',
  'coverage',
  '__pycache__',
  '.venv',
  'build',
  '.svn',
  '.hg',
  'tests',
  '__tests__',
  'test',
  'fixtures',
]);


// ---------------------------------------------------------------------------
// Project type detection
// ---------------------------------------------------------------------------

/** Server-side framework packages that indicate a non-static project */
const SERVER_FRAMEWORKS = new Set([
  'express', 'fastify', 'next', 'nuxt', 'remix', '@remix-run/node',
  'hono', 'koa', '@nestjs/core', '@adonisjs/core', 'sails',
  'hapi', '@hapi/hapi',
]);

/** Frameworks that are inherently fullstack (server + client) */
const FULLSTACK_FRAMEWORKS = new Set([
  'next', 'nuxt', 'remix', '@remix-run/node', '@sveltejs/kit',
]);

/** Get all dependency names from a package.json object */
function getAllDependencyNames(pkgJson: Record<string, unknown>): readonly string[] {
  const deps = pkgJson.dependencies as Record<string, string> | undefined;
  const devDeps = pkgJson.devDependencies as Record<string, string> | undefined;
  return [...Object.keys(deps ?? {}), ...Object.keys(devDeps ?? {})];
}

/** Check whether any files indicate server-side code */
function hasServerSideFiles(files: readonly string[]): boolean {
  return files.some((f) => {
    const segments = f.split('/');
    const name = segments.at(-1) ?? '';
    if (/^server\.(ts|js|mjs|cjs)$/.test(name)) return true;
    if (segments.includes('api')) return true;
    if (segments.includes('routes')) return true;
    return false;
  });
}

/**
 * Detect project type from package.json and file listing.
 * Pure function — exported for testing.
 */
export function detectProjectType(
  packageJson: Record<string, unknown> | undefined,
  files: readonly string[],
): ProjectType {
  const hasCodeFiles = files.some((f) => CODE_EXTENSIONS.test(f));
  const hasServerFiles = hasServerSideFiles(files);

  // No package.json — static only if no code and no server files
  if (!packageJson) {
    if (!hasCodeFiles && !hasServerFiles) return 'static';
    return hasServerFiles ? 'api' : 'unknown';
  }

  // Has package.json — check dependencies for server frameworks
  const allDeps = getAllDependencyNames(packageJson);
  const hasServerDep = allDeps.some((d) => SERVER_FRAMEWORKS.has(d));

  // No server deps AND no server files → static
  if (!hasServerDep && !hasServerFiles) {
    return 'static';
  }

  // Has server indicators — fullstack or API-only?
  if (allDeps.some((d) => FULLSTACK_FRAMEWORKS.has(d))) {
    return 'fullstack';
  }

  // Server-only framework — check for frontend files
  const hasFrontendFiles = files.some(
    (f) =>
      f.endsWith('.tsx') ||
      f.endsWith('.jsx') ||
      f.endsWith('.vue') ||
      f.endsWith('.svelte'),
  );

  return hasFrontendFiles ? 'fullstack' : 'api';
}

// ---------------------------------------------------------------------------
// Context builder
// ---------------------------------------------------------------------------

/** Build ScanContext from CLI options */
export async function buildContext(options: {
  readonly path: string;
  readonly url?: string;
  readonly verbose: boolean;
  readonly type?: 'auto' | 'static' | 'api' | 'fullstack';
}): Promise<ScanContext> {
  const projectPath = resolve(options.path);

  const info = await stat(projectPath).catch(() => null);
  if (!info?.isDirectory()) {
    throw new Error(`Not a directory: ${projectPath}`);
  }

  // Read package.json (optional)
  let packageJson: Record<string, unknown> | undefined;
  try {
    const raw = await readFile(join(projectPath, 'package.json'), 'utf-8');
    packageJson = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    // No package.json or invalid JSON — fine
  }

  // List project files, excluding common non-project directories
  const entries = await readdir(projectPath, { recursive: true, withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile())
    .map((e) => relative(projectPath, join(e.parentPath, e.name)))
    .filter((f) => !f.split('/').some((segment) => EXCLUDED_DIRS.has(segment)));

  const stack = detectStack(packageJson, files);

  const typeOverride = options.type ?? 'auto';
  const projectType: ProjectType =
    typeOverride === 'auto'
      ? detectProjectType(packageJson, files)
      : typeOverride;
  const projectTypeSource: 'auto' | 'manual' = typeOverride === 'auto' ? 'auto' : 'manual';

  return {
    projectPath,
    url: options.url,
    stack,
    packageJson,
    files,
    verbose: options.verbose,
    projectType,
    projectTypeSource,
  };
}

// ---------------------------------------------------------------------------
// Check runner
// ---------------------------------------------------------------------------

/** Run all registered checks and produce a report */
export async function runChecks(
  context: ScanContext,
  checks: readonly CheckFunction[],
): Promise<ScanReport> {
  const start = Date.now();

  const settled = await Promise.allSettled(checks.map((check) => check(context)));

  const results: CheckResult[] = [];
  for (const outcome of settled) {
    if (outcome.status === 'fulfilled') {
      results.push(...outcome.value);
    } else {
      results.push({
        id: 'error',
        name: 'Check error',
        status: 'skip',
        severity: 'info',
        description: `Check threw: ${outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason)}`,
      });
    }
  }

  const enrichedResults = enrichWithAiPrompts(results, context);

  return {
    results: enrichedResults,
    score: calculateScore(enrichedResults),
    summary: summarizeResults(enrichedResults),
    duration: Date.now() - start,
  };
}

/** Project indicator files/directories — if none exist, it's not a real project */
const PROJECT_INDICATORS = ['package.json', '.gitignore', '.git', 'src', 'lib'];
const CODE_EXTENSIONS = /\.(ts|js|tsx|jsx)$/;

/** Check whether the scanned path contains a real project */
function hasProjectFiles(files: readonly string[], projectPath: string, packageJson: Record<string, unknown> | undefined): boolean {
  if (packageJson) return true;

  // Check for indicator files/directories in the file listing
  for (const f of files) {
    const first = f.split('/')[0];
    if (PROJECT_INDICATORS.includes(first)) return true;
    if (CODE_EXTENSIONS.test(f)) return true;
  }

  return false;
}

/** Load checks and run them — auto-detects URL-only mode and static sites */
export async function scan(context: ScanContext): Promise<ScanReport> {
  const isUrlOnly = context.url && !hasProjectFiles(context.files, context.projectPath, context.packageJson);

  if (isUrlOnly) {
    const report = await runChecks(context, getUrlOnlyChecks());
    return { ...report, urlOnly: true, projectType: context.projectType, projectTypeSource: context.projectTypeSource };
  }

  const allChecks = getAllChecks();

  // Static sites: skip server-specific checks
  if (context.projectType === 'static') {
    const skipInfos = getStaticSiteSkippableChecks();
    const hasEnvFile = context.files.some((f) => f === '.env');

    // Build set of check functions to skip
    const skipFns = new Set(
      skipInfos
        .filter((s) => (s.id === 'env-example' ? !hasEnvFile : true))
        .map((s) => s.fn),
    );

    const checksToRun = allChecks.filter((c) => !skipFns.has(c));

    // Build not-applicable results for skipped checks
    const notApplicableResults: CheckResult[] = skipInfos
      .filter((s) => skipFns.has(s.fn))
      .map((s) => ({
        id: s.id,
        name: s.name,
        status: 'not-applicable' as const,
        severity: 'info' as const,
        category: 'static-site',
        description: 'Not applicable — static site has no server-side code',
      }));

    const report = await runChecks(context, checksToRun);

    return {
      ...report,
      results: [...report.results, ...notApplicableResults],
      summary: summarizeResults([...report.results, ...notApplicableResults]),
      projectType: context.projectType,
      projectTypeSource: context.projectTypeSource,
    };
  }

  const report = await runChecks(context, allChecks);
  return { ...report, projectType: context.projectType, projectTypeSource: context.projectTypeSource };
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for testing)
// ---------------------------------------------------------------------------

/** Calculate security score: pass-rate among checks that actually ran (excludes skipped and not-applicable) */
export function calculateScore(results: readonly CheckResult[]): number {
  const ran = results.filter((r) => r.status !== 'skip' && r.status !== 'not-applicable');

  if (ran.length === 0) return 100;

  const passed = ran.filter((r) => r.status !== 'fail').length;

  return Math.max(0, Math.round((passed / ran.length) * 100));
}

/** Count results by status */
export function summarizeResults(results: readonly CheckResult[]): ScanSummary {
  let pass = 0;
  let fail = 0;
  let warn = 0;
  let skip = 0;
  let notApplicable = 0;

  for (const r of results) {
    if (r.status === 'pass') pass++;
    else if (r.status === 'fail') fail++;
    else if (r.status === 'warn') warn++;
    else if (r.status === 'not-applicable') notApplicable++;
    else skip++;
  }

  return { pass, fail, warn, skip, notApplicable, checksRun: pass + fail + warn, total: results.length };
}
