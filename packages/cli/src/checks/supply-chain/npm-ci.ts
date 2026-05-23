/**
 * Check: BSTN-SUP-005 — npm ci vs install in CI
 *
 * Detects GitHub Actions workflows using `npm install` instead of `npm ci`.
 * `npm install` can mutate package-lock.json, bypassing lockfile integrity
 * and allowing attackers to slip compromised packages into builds.
 *
 * v1 scope: GitHub Actions only (.github/workflows/*.yml, *.yaml).
 * Yarn, pnpm, GitLab CI, CircleCI, Bitbucket Pipelines deferred.
 */
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { CheckFunction, CheckResult } from '@bastion/shared';

const CHECK_ID = 'npm-ci';
const CHECK_NAME = 'npm ci in CI workflows';
const CATEGORY = 'supply-chain';

/**
 * Detect whether a command line uses `npm install` (or `npm i`) in a
 * problematic way. Returns true if the line uses npm install without
 * the -g or --global flag.
 */
export function isProblematicNpmCommand(cmdLine: string): boolean {
  const trimmed = cmdLine.trim();

  // Match `npm install` or `npm i` (with word boundaries)
  const hasNpmInstall =
    /\bnpm\s+install\b/.test(trimmed) || /\bnpm\s+i\b/.test(trimmed);

  if (!hasNpmInstall) return false;

  // Exception: global installs are fine
  if (/\s-g\b/.test(trimmed) || /\s--global\b/.test(trimmed)) return false;

  return true;
}

/** Represents a run command extracted from a workflow step */
export interface RunCommand {
  readonly stepName: string | undefined;
  readonly command: string;
}

/**
 * Extract all run commands from a parsed GitHub Actions workflow YAML.
 * Walks jobs → steps → run fields, handling both single-line and
 * multi-line (pipe) blocks.
 */
export function extractRunCommands(parsedYaml: unknown): readonly RunCommand[] {
  if (!parsedYaml || typeof parsedYaml !== 'object') return [];

  const workflow = parsedYaml as Record<string, unknown>;
  const jobs = workflow['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];

  const results: RunCommand[] = [];

  for (const job of Object.values(jobs as Record<string, unknown>)) {
    if (!job || typeof job !== 'object') continue;

    const steps = (job as Record<string, unknown>)['steps'];
    if (!Array.isArray(steps)) continue;

    for (const step of steps) {
      if (!step || typeof step !== 'object') continue;

      const stepObj = step as Record<string, unknown>;
      const run = stepObj['run'];
      if (typeof run !== 'string') continue;

      const stepName = typeof stepObj['name'] === 'string' ? stepObj['name'] : undefined;

      // Multi-line run blocks: split into individual lines
      for (const line of run.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed) {
          results.push({ stepName, command: trimmed });
        }
      }
    }
  }

  return results;
}

const npmCiCheck: CheckFunction = async (context) => {
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
          description: 'No .github/workflows/ directory found — skipping CI workflow check.',
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
        description: 'No workflow files found in .github/workflows/ — skipping CI workflow check.',
      },
    ];
  }

  const findings: CheckResult[] = [];

  for (const filename of filenames) {
    let content: string;

    try {
      content = await readFile(join(workflowsDir, filename), 'utf-8');
    } catch {
      continue; // Skip unreadable files
    }

    let parsed: unknown;

    try {
      parsed = parseYaml(content);
    } catch {
      continue; // Skip malformed YAML
    }

    const commands = extractRunCommands(parsed);

    for (const { stepName, command } of commands) {
      if (isProblematicNpmCommand(command)) {
        findings.push({
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'warn',
          severity: 'medium',
          category: CATEGORY,
          location: `.github/workflows/${filename}`,
          description:
            `CI workflow uses \`npm install\` instead of \`npm ci\`: ${filename}. ` +
            `Step: ${stepName ?? '(unnamed)'}. Command: \`${command}\`. ` +
            'npm install can mutate package-lock.json, bypassing lockfile integrity.',
          fix: 'Replace `npm install` with `npm ci` which enforces lockfile-based installs.',
          aiPrompt:
            `My GitHub Actions workflow ${filename} uses \`npm install\` instead of \`npm ci\`. ` +
            'Explain the security implications of npm install mutating the lockfile in CI, ' +
            'and help me update the workflow to use npm ci correctly. Note any cases where ' +
            'npm install might still be needed (e.g., global tool installs).',
        });
      }
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
        description: `All ${filenames.length} workflow file(s) use npm ci or have no npm install commands.`,
      },
    ];
  }

  return findings;
};

export default npmCiCheck;
