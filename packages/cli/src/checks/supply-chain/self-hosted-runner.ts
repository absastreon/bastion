/**
 * Check: BSTN-SUP-006 — self-hosted runner detection
 *
 * Detects GitHub Actions workflows configured to run on self-hosted runners.
 * Shai-Hulud installed self-hosted runners named SHA1HULUD as a persistence
 * mechanism, so runner label inspection is a real IoC check.
 *
 * Three severity levels:
 * - HIGH: IoC pattern match (SHA1HULUD, shai-hulud, etc.)
 * - WARN: General self-hosted runner (verification required)
 * - INFO: Unrecognized custom label (documentation recommended)
 *
 * v1 scope: GitHub Actions only (.github/workflows/*.yml, *.yaml).
 */
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { CheckFunction, CheckResult } from '@bastion/shared';

const CHECK_ID = 'self-hosted-runner';
const CHECK_NAME = 'Self-hosted runner detection';
const CATEGORY = 'supply-chain';

/** Matches standard GitHub-hosted runner labels */
const GITHUB_HOSTED_REGEX = /^(ubuntu|macos|windows)(-(latest|\d+(\.\d+)?))?$/;

/** Known IoC patterns from Shai-Hulud / SHA1-Hulud worm (case-insensitive substring match) */
const IOC_PATTERNS: readonly string[] = ['sha1hulud', 'shai-hulud', 'sha1-hulud', 'hulud'];

export type RunnerCategory = 'github-hosted' | 'self-hosted' | 'ioc-match' | 'unknown';

/**
 * Categorize a runner label.
 * Returns the category indicating security relevance.
 */
export function categorizeRunner(label: string): RunnerCategory {
  const trimmed = label.trim();
  const lower = trimmed.toLowerCase();

  // Check IoC patterns first (highest severity)
  if (IOC_PATTERNS.some((pattern) => lower.includes(pattern))) {
    return 'ioc-match';
  }

  // Check for explicit self-hosted keyword
  if (lower.includes('self-hosted')) {
    return 'self-hosted';
  }

  // Check GitHub-hosted pattern
  if (GITHUB_HOSTED_REGEX.test(trimmed)) {
    return 'github-hosted';
  }

  return 'unknown';
}

/** Represents a job's runs-on configuration extracted from a workflow */
export interface JobRunsOn {
  readonly jobName: string;
  readonly runsOn: readonly string[];
}

/**
 * Extract runs-on configurations from a parsed GitHub Actions workflow YAML.
 * Normalizes runs-on to an array (handles both string and array syntax).
 */
export function extractRunsOn(parsedYaml: unknown): readonly JobRunsOn[] {
  if (!parsedYaml || typeof parsedYaml !== 'object') return [];

  const workflow = parsedYaml as Record<string, unknown>;
  const jobs = workflow['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];

  const results: JobRunsOn[] = [];

  for (const [jobName, job] of Object.entries(jobs as Record<string, unknown>)) {
    if (!job || typeof job !== 'object') continue;

    const runsOn = (job as Record<string, unknown>)['runs-on'];
    if (!runsOn) continue;

    if (typeof runsOn === 'string') {
      results.push({ jobName, runsOn: [runsOn] });
    } else if (Array.isArray(runsOn)) {
      const labels = runsOn.filter((item): item is string => typeof item === 'string');
      if (labels.length > 0) {
        results.push({ jobName, runsOn: labels });
      }
    }
  }

  return results;
}

/** Severity precedence for runner categories */
const CATEGORY_PRIORITY: Record<RunnerCategory, number> = {
  'ioc-match': 3,
  'self-hosted': 2,
  'unknown': 1,
  'github-hosted': 0,
};

/** Get the highest-severity category from a list of labels */
function highestCategory(labels: readonly string[]): RunnerCategory {
  let highest: RunnerCategory = 'github-hosted';

  for (const label of labels) {
    const cat = categorizeRunner(label);
    if (CATEGORY_PRIORITY[cat] > CATEGORY_PRIORITY[highest]) {
      highest = cat;
    }
  }

  return highest;
}

const selfHostedRunnerCheck: CheckFunction = async (context) => {
  const workflowsDir = join(context.projectPath, '.github', 'workflows');

  let filenames: string[];

  try {
    const entries = await readdir(workflowsDir);
    filenames = entries.filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
  } catch (error: unknown) {
    const isNotFound =
      error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT';

    if (isNotFound) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'skip',
          severity: 'info',
          category: CATEGORY,
          description: 'No .github/workflows/ directory found — skipping runner detection.',
        },
      ];
    }

    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: `Check failed: ${error instanceof Error ? error.message : String(error)}`,
      },
    ];
  }

  if (filenames.length === 0) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: 'No workflow files found in .github/workflows/ — skipping runner detection.',
      },
    ];
  }

  const findings: CheckResult[] = [];

  for (const filename of filenames) {
    let content: string;

    try {
      content = await readFile(join(workflowsDir, filename), 'utf-8');
    } catch {
      continue;
    }

    let parsed: unknown;

    try {
      parsed = parseYaml(content);
    } catch {
      continue;
    }

    const jobsRunsOn = extractRunsOn(parsed);

    for (const { jobName, runsOn } of jobsRunsOn) {
      const category = highestCategory(runsOn);
      const labelsDisplay = runsOn.join(', ');

      if (category === 'ioc-match') {
        findings.push({
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'fail',
          severity: 'high',
          category: CATEGORY,
          location: `.github/workflows/${filename}`,
          description:
            `Suspicious runner label matches known IoC: ${filename}. ` +
            `Job: ${jobName}. Runs-on: ${labelsDisplay}. ` +
            'This label matches known indicators of compromise from the Shai-Hulud / SHA1-Hulud worm.',
          fix:
            'IMMEDIATE ACTION: Inspect this repository\'s recent commits, workflow files, and any ' +
            'associated infrastructure. This may be evidence of active compromise. Remove the ' +
            'suspicious runner and audit all recent workflow runs.',
          aiPrompt:
            `My GitHub Actions workflow ${filename} has a runner label "${labelsDisplay}" that matches ` +
            'known IoC patterns from the Shai-Hulud worm. Help me investigate: what should I check ' +
            'for signs of compromise, how do I audit recent workflow runs, and what remediation ' +
            'steps should I take immediately?',
        });
      } else if (category === 'self-hosted') {
        findings.push({
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'warn',
          severity: 'medium',
          category: CATEGORY,
          location: `.github/workflows/${filename}`,
          description:
            `Self-hosted runner in workflow: ${filename}. ` +
            `Job: ${jobName}. Runs-on: ${labelsDisplay}. ` +
            'Self-hosted runners can be a persistence vector for supply-chain attacks.',
          fix:
            'Verify this runner was intentionally configured. If not, this may indicate compromise. ' +
            'Ensure self-hosted runners are hardened, regularly patched, and use ephemeral instances ' +
            'where possible.',
          aiPrompt:
            `My GitHub Actions workflow ${filename} uses a self-hosted runner (${labelsDisplay}). ` +
            'Explain the supply-chain security risks of self-hosted runners, best practices for ' +
            'hardening them, and how to verify this configuration is intentional and safe.',
        });
      } else if (category === 'unknown') {
        findings.push({
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'pass',
          severity: 'info',
          category: CATEGORY,
          location: `.github/workflows/${filename}`,
          description:
            `Custom/unrecognized runner label: ${filename}. ` +
            `Job: ${jobName}. Runs-on: ${labelsDisplay}. ` +
            'This label doesn\'t match standard GitHub-hosted runner patterns. ' +
            'If this is intentional (e.g., self-hosted with a custom name), document it.',
        });
      }
      // github-hosted → silent pass, no finding generated
    }
  }

  if (findings.length === 0) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        description: `All ${filenames.length} workflow file(s) use standard GitHub-hosted runners.`,
      },
    ];
  }

  return findings;
};

export default selfHostedRunnerCheck;
