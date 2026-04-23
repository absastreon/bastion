/**
 * Markdown reporter — generates a security-report.md file with full findings
 */
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckResult, ScanContext, ScanReport, Severity } from '@bastion/shared';

/** Severity display order: most critical first */
const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Capitalize a severity label for display */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ---------------------------------------------------------------------------
// Markdown formatting (pure)
// ---------------------------------------------------------------------------

/**
 * Format a ScanReport as a Markdown string.
 * Pure function — caller is responsible for writing to disk.
 */
export function formatMarkdownReport(
  report: ScanReport,
  context: ScanContext,
  version: string,
): string {
  const lines: string[] = [];

  appendTitle(lines, report, context);
  appendStack(lines, context);

  const findings = report.results.filter((r) => r.status === 'fail' || r.status === 'warn');
  if (findings.length > 0) {
    appendFindings(lines, findings);
  }

  const passes = report.results.filter((r) => r.status === 'pass');
  if (passes.length > 0) {
    appendPassedChecks(lines, passes);
  }

  const notApplicable = report.results.filter((r) => r.status === 'not-applicable');
  if (notApplicable.length > 0) {
    appendNotApplicableChecks(lines, notApplicable);
  }

  appendRecommendations(lines, report);
  appendFooter(lines, version);

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/**
 * Generate the Markdown report and write it to disk.
 * Returns the resolved output path.
 */
export async function writeMarkdownReport(
  report: ScanReport,
  context: ScanContext,
  version: string,
  outputPath?: string,
): Promise<string> {
  const content = formatMarkdownReport(report, context, version);
  const filePath = outputPath ?? join(context.projectPath, 'security-report.md');
  await writeFile(filePath, content, 'utf-8');
  return filePath;
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

function appendTitle(lines: string[], report: ScanReport, context: ScanContext): void {
  const date = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  const { pass, fail, warn } = report.summary;

  lines.push('# Bastion Security Report');
  lines.push('');
  lines.push(`**Date:** ${date}  `);
  lines.push(`**Project:** \`${context.projectPath}\`  `);
  lines.push(`**Score:** ${report.score}/100  `);
  lines.push(`**Duration:** ${report.duration}ms`);
  lines.push('');
  lines.push(`> ${pass} passed, ${fail} failed, ${warn} warning${warn === 1 ? '' : 's'}`);
  lines.push('');
  lines.push('---');
  lines.push('');
}

function appendStack(lines: string[], context: ScanContext): void {
  const { stack } = context;
  const rows: Array<readonly [string, string]> = [['Language', stack.language]];

  if (stack.framework) rows.push(['Framework', stack.framework]);
  if (stack.packageManager) rows.push(['Package Manager', stack.packageManager]);
  if (stack.database) rows.push(['Database', stack.database]);
  if (stack.auth) rows.push(['Auth', stack.auth]);
  if (stack.hosting) rows.push(['Hosting', stack.hosting]);

  lines.push('## Detected Stack');
  lines.push('');
  lines.push('| Component | Value |');
  lines.push('|-----------|-------|');
  for (const [component, value] of rows) {
    lines.push(`| ${component} | ${value} |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');
}

function appendFindings(lines: string[], findings: readonly CheckResult[]): void {
  lines.push('## Findings');
  lines.push('');

  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((r) => r.severity === severity);
    if (group.length === 0) continue;

    lines.push(`### ${capitalize(severity)} (${group.length})`);
    lines.push('');

    for (const result of group) {
      lines.push(`#### ${result.name}`);
      lines.push('');
      lines.push(`- **Severity:** ${capitalize(result.severity)}`);
      if (result.location) {
        lines.push(`- **Location:** \`${result.location}\``);
      }
      lines.push(`- **Description:** ${result.description}`);
      if (result.fix) {
        lines.push(`- **Fix:** ${result.fix}`);
      }
      if (result.aiPrompt) {
        lines.push('- **AI Prompt:**');
        lines.push(`  > ${result.aiPrompt}`);
      }
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');
}

function appendPassedChecks(lines: string[], passes: readonly CheckResult[]): void {
  lines.push('## Passed Checks');
  lines.push('');
  for (const r of passes) {
    lines.push(`- ✓ **${r.name}** — ${r.description}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');
}

function appendNotApplicableChecks(lines: string[], results: readonly CheckResult[]): void {
  lines.push('## Not Applicable');
  lines.push('');
  for (const r of results) {
    lines.push(`- ○ **${r.name}** — ${r.description}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');
}

function appendRecommendations(lines: string[], report: ScanReport): void {
  const findings = report.results.filter((r) => r.status === 'fail');
  const hasCritical = findings.some((r) => r.severity === 'critical');
  const hasHigh = findings.some((r) => r.severity === 'high');
  const hasMedium = findings.some((r) => r.severity === 'medium');

  lines.push('## Recommendations');
  lines.push('');

  if (findings.length === 0) {
    lines.push('1. Great work! Your project has no security findings');
  } else {
    let n = 1;
    if (hasCritical) {
      lines.push(`${n}. Address all **critical** findings immediately — these represent severe security risks`);
      n++;
    }
    if (hasHigh) {
      lines.push(`${n}. Review and fix **high**-severity findings before your next deployment`);
      n++;
    }
    if (hasMedium) {
      lines.push(`${n}. Plan to resolve **medium**-severity findings in your next sprint`);
      n++;
    }
  }

  lines.push(`${findings.length === 0 ? 2 : (hasCritical ? 1 : 0) + (hasHigh ? 1 : 0) + (hasMedium ? 1 : 0) + 1}. Run \`npx bastion scan\` regularly to catch new issues early`);
  lines.push('');
  lines.push('---');
  lines.push('');
}

function appendFooter(lines: string[], version: string): void {
  lines.push(
    `*Generated by [Bastion](https://github.com/ABS-Projects-2026/Bastion) v${version} — Privacy-first security checker for AI-era builders*`,
  );
  lines.push('');
}
