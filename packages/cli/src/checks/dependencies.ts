/**
 * Check: Dependency vulnerabilities — wraps npm audit, maps to Bastion severity levels
 */
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { CheckFunction, CheckResult, Severity } from '@bastion/shared';

const CHECK_ID = 'dep-vuln';
const CHECK_NAME = 'Dependency vulnerabilities';
const CATEGORY = 'dependencies';

/** Advisory object nested inside npm audit's `via` array */
interface NpmAdvisory {
  readonly title: string;
  readonly url: string;
}

/** Single vulnerability entry from `npm audit --json` (v2 format) */
interface NpmVulnerability {
  readonly name: string;
  readonly severity: string;
  readonly via: readonly (NpmAdvisory | string)[];
}

/** Top-level structure of `npm audit --json` output */
interface NpmAuditReport {
  readonly vulnerabilities?: Readonly<Record<string, NpmVulnerability>>;
}

const SEVERITY_MAP: Readonly<Record<string, Severity>> = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
};

/** Map npm audit severity to Bastion severity */
function mapSeverity(npmSeverity: string): Severity {
  return SEVERITY_MAP[npmSeverity] ?? 'info';
}

/** Extract the first advisory object from a vulnerability's `via` array */
function findAdvisory(via: readonly (NpmAdvisory | string)[]): NpmAdvisory | undefined {
  return via.find((v): v is NpmAdvisory => typeof v !== 'string');
}

/** Run `npm audit --json` and return raw stdout */
function runNpmAudit(cwd: string): string {
  try {
    return execSync('npm audit --json', { cwd, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (error: unknown) {
    // npm audit exits non-zero when vulnerabilities exist — stdout still contains valid JSON
    if (error !== null && typeof error === 'object' && 'stdout' in error) {
      const stdout = String(error.stdout);
      if (stdout.trim()) return stdout;
    }
    throw error;
  }
}

/** Build a CheckResult for a single vulnerability */
function toCheckResult(vuln: NpmVulnerability): CheckResult {
  const advisory = findAdvisory(vuln.via);
  const severity = mapSeverity(vuln.severity);
  const title = advisory?.title ?? 'Vulnerability';
  const url = advisory?.url;

  const description = url
    ? `${vuln.name}: ${title} (${url})`
    : `${vuln.name}: ${title}`;

  return {
    id: `${CHECK_ID}-${vuln.name}`,
    name: CHECK_NAME,
    status: 'fail',
    severity,
    category: CATEGORY,
    description,
    fix: `Run \`npm audit fix\` or update the package: \`npm install ${vuln.name}@latest\``,
    aiPrompt: `I have a ${vuln.severity}-severity vulnerability in the npm package "${vuln.name}".${url ? ` Advisory: ${url}.` : ''} Help me fix this by running \`npm update ${vuln.name}\` or \`npm install ${vuln.name}@latest\`. If this requires a major version upgrade, help me understand what breaking changes to expect and how to migrate my code.`,
  };
}

const dependencyCheck: CheckFunction = async (context) => {
  if (!context.packageJson) {
    return [{
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'No package.json found — skipping dependency audit',
    }];
  }

  if (!existsSync(join(context.projectPath, 'node_modules'))) {
    return [{
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'warn',
      severity: 'medium',
      category: CATEGORY,
      description: 'node_modules not found — run npm install before scanning',
      fix: 'Run `npm install` to install dependencies before scanning.',
    }];
  }

  let output: string;
  try {
    output = runNpmAudit(context.projectPath);
  } catch {
    return [{
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'npm audit could not be run — ensure npm is installed and available',
    }];
  }

  let report: NpmAuditReport;
  try {
    report = JSON.parse(output) as NpmAuditReport;
  } catch {
    return [{
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'Failed to parse npm audit output',
    }];
  }

  const vulns = report.vulnerabilities;
  if (!vulns || Object.keys(vulns).length === 0) {
    return [{
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      description: 'No known vulnerabilities found in dependencies',
    }];
  }

  return Object.values(vulns).map(toCheckResult);
};

export default dependencyCheck;
