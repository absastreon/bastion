/**
 * Check: BSTN-SUP-001 — compromised package detection
 *
 * Detects direct dependencies matching a known-compromised package list.
 * v1 scope: npm lockfile only, direct dependencies only, small hardcoded seed list.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { satisfies } from 'semver';
import type { CheckFunction, CheckResult } from '@bastion/shared';
import { COMPROMISED_PACKAGES, type CompromisedPackage } from '../../data/compromised-packages.js';

const CHECK_ID = 'compromised-deps';
const CHECK_NAME = 'Compromised package detection';
const CATEGORY = 'supply-chain';

/** Extract direct dependency names from a parsed package.json */
export function getDirectDeps(packageJson: Record<string, unknown>): readonly string[] {
  const deps = (packageJson['dependencies'] ?? {}) as Record<string, unknown>;
  const devDeps = (packageJson['devDependencies'] ?? {}) as Record<string, unknown>;
  return [...Object.keys(deps), ...Object.keys(devDeps)];
}

/**
 * Resolve installed version for a package from npm lockfile (v2/v3 format).
 * The `packages` field maps paths to metadata; direct deps live at
 * `node_modules/<name>`.
 */
export function resolveVersionFromLockfile(
  lockfile: Record<string, unknown>,
  packageName: string,
): string | undefined {
  const packages = lockfile['packages'] as Record<string, Record<string, unknown>> | undefined;
  if (!packages) return undefined;

  const entry = packages[`node_modules/${packageName}`];
  if (!entry) return undefined;

  const version = entry['version'];
  return typeof version === 'string' ? version : undefined;
}

/**
 * Check a single dependency against the compromised list.
 * Returns the matching entry or undefined.
 */
export function findCompromisedMatch(
  packageName: string,
  installedVersion: string,
  list: readonly CompromisedPackage[] = COMPROMISED_PACKAGES,
): CompromisedPackage | undefined {
  return list.find(
    (entry) => entry.name === packageName && satisfies(installedVersion, entry.versionRange),
  );
}

const compromisedDepsCheck: CheckFunction = async (context) => {
  if (!context.packageJson) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: 'No package.json found — skipping compromised dependency check.',
      },
    ];
  }

  let lockfileContent: string;

  try {
    lockfileContent = await readFile(join(context.projectPath, 'package-lock.json'), 'utf-8');
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
          description:
            'No package-lock.json found — skipping compromised dependency check. ' +
            'This check requires an npm lockfile to resolve installed versions.',
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

  let lockfile: Record<string, unknown>;

  try {
    lockfile = JSON.parse(lockfileContent) as Record<string, unknown>;
  } catch {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: 'package-lock.json contains malformed JSON — cannot check dependencies.',
      },
    ];
  }

  if (COMPROMISED_PACKAGES.length === 0) {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        description: 'Compromised package list is empty — no packages to check against.',
      },
    ];
  }

  const directDeps = getDirectDeps(context.packageJson);
  const findings: CheckResult[] = [];

  for (const depName of directDeps) {
    const installedVersion = resolveVersionFromLockfile(lockfile, depName);
    if (!installedVersion) continue;

    const match = findCompromisedMatch(depName, installedVersion);
    if (match) {
      findings.push({
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'fail',
        severity: 'high',
        category: CATEGORY,
        location: `package-lock.json (${depName}@${installedVersion})`,
        description:
          `Compromised package detected: ${depName}@${installedVersion}. ` +
          `Match: ${match.versionRange} (${match.source}, ${match.advisoryId}). ` +
          `Date added to list: ${match.dateAdded}. ${match.description}`,
        fix:
          `Remove ${depName} or pin to a version outside the compromised range ` +
          `(${match.versionRange}). Run \`npm audit\` for additional details.`,
        aiPrompt:
          `My project depends on ${depName}@${installedVersion} which is flagged as compromised ` +
          `(${match.advisoryId}). Help me find a safe alternative or a patched version. ` +
          `Explain what the compromise does and whether my project is affected.`,
      });
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
        description: `No compromised packages found among ${directDeps.length} direct dependencies.`,
      },
    ];
  }

  return findings;
};

export default compromisedDepsCheck;
