/**
 * Terminal reporter — formatted console output for scan results
 */
import chalk from 'chalk';
import type { CheckResult, ScanReport, Severity } from '@bastion/shared';

/** Colour a string by severity (used for fail glyphs and severity tags) */
function severityColour(severity: Severity, text: string): string {
  switch (severity) {
    case 'critical':
      return chalk.red(text);
    case 'high':
      return chalk.yellow(text);
    case 'medium':
      return chalk.blue(text);
    case 'low':
    case 'info':
      return chalk.dim(text);
  }
}

/**
 * Icon for a check result. Glyph encodes STATUS; colour encodes severity on
 * failures (H-25 fix, 11 June 2026): every fail is ✕, warn-status is !, so
 * what you count on screen matches the footer's status counts. The old scheme
 * rendered fail/high and warn-status identically (yellow ⚠).
 */
function resultIcon(result: CheckResult): string {
  if (result.status === 'pass') return chalk.green('✓');
  if (result.status === 'skip') return chalk.dim('–');
  if (result.status === 'not-applicable') return chalk.dim('○');
  if (result.status === 'warn') return chalk.yellow('!');
  return severityColour(result.severity, '✕');
}

/** Severity tag appended to failed-check lines, e.g. "[critical]" */
function severityTag(result: CheckResult): string {
  if (result.status !== 'fail') return '';
  return ` ${severityColour(result.severity, `[${result.severity}]`)}`;
}

/** Severity breakdown for the footer, e.g. "2 critical · 3 high" (non-zero only) */
function failBreakdown(results: readonly CheckResult[]): string {
  const order: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const parts: string[] = [];
  for (const sev of order) {
    const n = results.filter((r) => r.status === 'fail' && r.severity === sev).length;
    if (n > 0) parts.push(severityColour(sev, `${n} ${sev}`));
  }
  return parts.join(' · ');
}

/** Format score with color: green ≥80, yellow ≥50, red <50 */
export function formatScore(score: number): string {
  const text = `${score}/100`;
  if (score >= 80) return chalk.green(text);
  if (score >= 50) return chalk.yellow(text);
  return chalk.red(text);
}

/** Group results by category (defaults to "General") */
function groupByCategory(
  results: readonly CheckResult[],
): ReadonlyMap<string, readonly CheckResult[]> {
  const groups = new Map<string, CheckResult[]>();
  for (const r of results) {
    const key = r.category ?? 'General';
    const list = groups.get(key);
    if (list) {
      list.push(r);
    } else {
      groups.set(key, [r]);
    }
  }
  return groups;
}

/**
 * Format a ScanReport as a coloured terminal string.
 * The caller is responsible for printing the returned string.
 */
export function formatTerminalReport(
  report: ScanReport,
  verbose: boolean,
): string {
  if (report.results.length === 0) {
    return [
      '',
      `  ${chalk.dim('No security checks were run. Add checks to get started.')}`,
      '',
    ].join('\n');
  }

  const lines: string[] = [];
  const grouped = groupByCategory(report.results);

  for (const [category, results] of grouped) {
    lines.push('');
    lines.push(`  ${chalk.bold.underline(category)}`);
    lines.push('');

    for (const r of results) {
      if (r.status === 'not-applicable') {
        lines.push(`    ${resultIcon(r)} ${chalk.dim(`${r.name} — not applicable (static site)`)}`);
        continue;
      }
      const loc = r.location ? chalk.dim(` ${r.location}`) : '';
      lines.push(`    ${resultIcon(r)} ${r.name}${severityTag(r)}${loc}`);
      lines.push(`      ${chalk.dim(r.description)}`);

      if (verbose && r.fix) {
        lines.push(`      ${chalk.cyan('Fix:')} ${r.fix}`);
      }
      if (verbose && r.aiPrompt) {
        lines.push(`      ${chalk.magenta('AI:')} ${r.aiPrompt}`);
      }
    }
  }

  const { pass, fail, warn, skip, notApplicable, checksRun, total } = report.summary;

  lines.push('');

  const parts = [
    `${pass} passed`,
    `${fail} failed`,
    `${warn} ${warn === 1 ? 'warning' : 'warnings'}`,
    `${skip} skipped`,
  ];
  if (notApplicable > 0) {
    parts.push(`${notApplicable} N/A`);
  }
  parts.push(`Score: ${formatScore(report.score)} (based on ${checksRun} of ${total} checks)`);
  lines.push(`  ${parts.join(' · ')}`);

  if (fail > 0) {
    lines.push(`  ${chalk.dim('failed by severity:')} ${failBreakdown(report.results)}`);
  }

  if (skip > 0 && skip > total / 2) {
    lines.push(
      `  ${chalk.yellow('⚠')} Score may not be representative — ${skip} checks could not run. Pass --url to enable HTTP checks.`,
    );
  }

  lines.push('');

  return lines.join('\n');
}
