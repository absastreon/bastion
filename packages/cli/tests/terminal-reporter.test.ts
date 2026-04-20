import { describe, it, expect, beforeAll } from 'vitest';
import chalk from 'chalk';
import { formatTerminalReport, formatScore } from '../src/reporters/terminal.js';
import type { CheckResult, ScanReport } from '@bastion/shared';

// Force ANSI output for consistent assertions
beforeAll(() => {
  chalk.level = 1;
});

/** Strip ANSI escape codes for plain-text assertions */
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\u001B\[[0-9;]*m/g;
const strip = (s: string): string => s.replace(ANSI_RE, '');

/** Build a CheckResult with sensible defaults */
function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    id: 'test',
    name: 'Test check',
    status: 'pass',
    severity: 'info',
    description: 'A test finding',
    ...overrides,
  };
}

/** Build a ScanReport from an array of results */
function makeReport(results: readonly CheckResult[], score?: number): ScanReport {
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
  return {
    results,
    score: score ?? 100,
    summary: { pass, fail, warn, skip, checksRun: pass + fail + warn, total: results.length },
    duration: 42,
  };
}

describe('formatTerminalReport', () => {
  it('shows friendly message for zero results', () => {
    const output = strip(formatTerminalReport(makeReport([]), false));
    expect(output).toContain('No security checks were run');
  });

  it('renders pass icon and check name', () => {
    const output = strip(
      formatTerminalReport(makeReport([makeResult({ name: 'Gitignore check' })]), false),
    );
    expect(output).toContain('✓');
    expect(output).toContain('Gitignore check');
  });

  it('renders correct severity icons for failures', () => {
    const output = strip(
      formatTerminalReport(
        makeReport(
          [
            makeResult({ status: 'fail', severity: 'critical', name: 'Crit' }),
            makeResult({ status: 'fail', severity: 'high', name: 'High' }),
            makeResult({ status: 'fail', severity: 'medium', name: 'Med' }),
            makeResult({ status: 'fail', severity: 'low', name: 'Low' }),
          ],
          50,
        ),
        false,
      ),
    );
    expect(output).toContain('✕');
    expect(output).toContain('⚠');
    expect(output).toContain('●');
    expect(output).toContain('○');
  });

  it('renders warn and skip icons', () => {
    const output = strip(
      formatTerminalReport(
        makeReport([
          makeResult({ status: 'warn', severity: 'medium', name: 'Warn check' }),
          makeResult({ status: 'skip', severity: 'info', name: 'Skip check' }),
        ]),
        false,
      ),
    );
    expect(output).toContain('⚠');
    expect(output).toContain('–');
  });

  it('shows location when present', () => {
    const output = strip(
      formatTerminalReport(
        makeReport([makeResult({ location: 'src/config.ts:42' })]),
        false,
      ),
    );
    expect(output).toContain('src/config.ts:42');
  });

  it('groups results by category', () => {
    const output = strip(
      formatTerminalReport(
        makeReport([
          makeResult({ category: 'Secrets', name: 'Key check' }),
          makeResult({ category: 'Config', name: 'Env check' }),
          makeResult({ category: 'Secrets', name: 'Token check' }),
        ]),
        false,
      ),
    );
    const secretsPos = output.indexOf('Secrets');
    const keyPos = output.indexOf('Key check');
    const tokenPos = output.indexOf('Token check');
    const configPos = output.indexOf('Config');
    expect(secretsPos).toBeLessThan(keyPos);
    expect(tokenPos).toBeLessThan(configPos);
    expect(keyPos).toBeLessThan(configPos);
  });

  it('defaults uncategorized to General', () => {
    const output = strip(formatTerminalReport(makeReport([makeResult()]), false));
    expect(output).toContain('General');
  });

  it('shows fix and AI prompt in verbose mode', () => {
    const output = strip(
      formatTerminalReport(
        makeReport([
          makeResult({ fix: 'Move key to .env', aiPrompt: 'Help me fix this secret' }),
        ]),
        true,
      ),
    );
    expect(output).toContain('Fix:');
    expect(output).toContain('Move key to .env');
    expect(output).toContain('AI:');
    expect(output).toContain('Help me fix this secret');
  });

  it('hides fix and AI prompt in non-verbose mode', () => {
    const output = strip(
      formatTerminalReport(
        makeReport([
          makeResult({ fix: 'Move key to .env', aiPrompt: 'Help me fix' }),
        ]),
        false,
      ),
    );
    expect(output).not.toContain('Fix:');
    expect(output).not.toContain('AI:');
  });

  it('renders correct summary counts', () => {
    const output = strip(
      formatTerminalReport(
        makeReport(
          [
            makeResult({ status: 'pass' }),
            makeResult({ status: 'pass' }),
            makeResult({ status: 'fail', severity: 'high' }),
            makeResult({ status: 'warn', severity: 'medium' }),
            makeResult({ status: 'skip', severity: 'info' }),
          ],
          90,
        ),
        false,
      ),
    );
    expect(output).toContain('2 passed');
    expect(output).toContain('1 failed');
    expect(output).toContain('1 warnings');
    expect(output).toContain('1 skipped');
    expect(output).toContain('90/100');
    expect(output).toContain('based on 4 of 5 checks');
  });

  it('shows skip note when more than half checks are skipped', () => {
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      ...Array.from({ length: 5 }, () => makeResult({ status: 'skip', severity: 'info' })),
    ];
    const output = strip(formatTerminalReport(makeReport(results, 50), false));
    expect(output).toContain('Score may not be representative');
    expect(output).toContain('5 checks could not run');
    expect(output).toContain('Pass --url to enable HTTP checks');
  });

  it('does not show skip note when fewer than half are skipped', () => {
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'skip', severity: 'info' }),
    ];
    const output = strip(formatTerminalReport(makeReport(results), false));
    expect(output).not.toContain('Score may not be representative');
  });
});

describe('formatScore', () => {
  it('applies green for score >= 80', () => {
    expect(formatScore(80)).toBe(chalk.green('80/100'));
    expect(formatScore(100)).toBe(chalk.green('100/100'));
  });

  it('applies yellow for 50 <= score < 80', () => {
    expect(formatScore(50)).toBe(chalk.yellow('50/100'));
    expect(formatScore(79)).toBe(chalk.yellow('79/100'));
  });

  it('applies red for score < 50', () => {
    expect(formatScore(0)).toBe(chalk.red('0/100'));
    expect(formatScore(49)).toBe(chalk.red('49/100'));
  });
});
