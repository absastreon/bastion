/**
 * Scanner orchestrator — loads checks, runs them in parallel, scores results
 */
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import type {
  CheckFunction,
  CheckResult,
  ScanContext,
  ScanReport,
  ScanSummary,
} from '@bastion/shared';
import { getAllChecks, getUrlOnlyChecks } from './checks/index.js';
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
// Context builder
// ---------------------------------------------------------------------------

/** Build ScanContext from CLI options */
export async function buildContext(options: {
  readonly path: string;
  readonly url?: string;
  readonly verbose: boolean;
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

  return { projectPath, url: options.url, stack, packageJson, files, verbose: options.verbose };
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

/** Load checks and run them — auto-detects URL-only mode */
export async function scan(context: ScanContext): Promise<ScanReport> {
  const isUrlOnly = context.url && !hasProjectFiles(context.files, context.projectPath, context.packageJson);

  const checks = isUrlOnly ? getUrlOnlyChecks() : getAllChecks();
  const report = await runChecks(context, checks);

  return isUrlOnly ? { ...report, urlOnly: true } : report;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for testing)
// ---------------------------------------------------------------------------

/** Calculate security score: pass-rate among checks that actually ran (excludes skipped) */
export function calculateScore(results: readonly CheckResult[]): number {
  const ran = results.filter((r) => r.status !== 'skip');

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

  for (const r of results) {
    if (r.status === 'pass') pass++;
    else if (r.status === 'fail') fail++;
    else if (r.status === 'warn') warn++;
    else skip++;
  }

  return { pass, fail, warn, skip, checksRun: pass + fail + warn, total: results.length };
}
