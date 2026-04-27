import { describe, it, expect, afterEach } from 'vitest';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { formatMarkdownReport, writeMarkdownReport } from '../../src/reporters/markdown.js';
import type { CheckResult, ScanContext, ScanReport } from 'bastion-shared';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

function makeReport(results: readonly CheckResult[], score?: number): ScanReport {
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
  return {
    results,
    score: score ?? 100,
    summary: { pass, fail, warn, skip, notApplicable, checksRun: pass + fail + warn, total: results.length },
    duration: 42,
  };
}

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/test-project',
    stack: {
      language: 'TypeScript',
      framework: 'Next.js',
      packageManager: 'npm',
    },
    files: ['src/index.ts', 'package.json'],
    verbose: false,
    projectType: 'unknown',
    projectTypeSource: 'auto',
    ...overrides,
  };
}

const VERSION = '0.1.0';

// ---------------------------------------------------------------------------
// formatMarkdownReport
// ---------------------------------------------------------------------------

describe('formatMarkdownReport', () => {
  it('starts with the report heading', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md.startsWith('# Bastion Security Report')).toBe(true);
  });

  it('includes a formatted date', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    // Match patterns like "April 15, 2026" or "January 1, 2025"
    expect(md).toMatch(/\*\*Date:\*\* \w+ \d{1,2}, \d{4}/);
  });

  it('includes the project path from context', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md).toContain('/tmp/test-project');
  });

  it('includes the security score', () => {
    const md = formatMarkdownReport(makeReport([], 85), makeContext(), VERSION);
    expect(md).toContain('85/100');
  });

  it('includes scan duration', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md).toContain('42ms');
  });

  it('renders detected stack as a table', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md).toContain('## Detected Stack');
    expect(md).toContain('TypeScript');
    expect(md).toContain('Next.js');
    expect(md).toContain('npm');
  });

  it('omits optional stack fields when not present', () => {
    const ctx = makeContext({ stack: { language: 'JavaScript' } });
    const md = formatMarkdownReport(makeReport([]), ctx, VERSION);
    expect(md).toContain('JavaScript');
    expect(md).not.toContain('Framework');
    expect(md).not.toContain('Package Manager');
  });

  it('includes database, auth, and hosting in stack when present', () => {
    const ctx = makeContext({
      stack: {
        language: 'TypeScript',
        framework: 'Next.js',
        packageManager: 'npm',
        database: 'PostgreSQL',
        auth: 'Clerk',
        hosting: 'Vercel',
      },
    });
    const md = formatMarkdownReport(makeReport([]), ctx, VERSION);
    expect(md).toContain('PostgreSQL');
    expect(md).toContain('Clerk');
    expect(md).toContain('Vercel');
  });

  it('groups failed findings by severity with critical first', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'medium', name: 'Medium issue' }),
      makeResult({ status: 'fail', severity: 'critical', name: 'Critical issue' }),
      makeResult({ status: 'fail', severity: 'high', name: 'High issue' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 50), makeContext(), VERSION);

    const criticalPos = md.indexOf('### Critical');
    const highPos = md.indexOf('### High');
    const mediumPos = md.indexOf('### Medium');

    expect(criticalPos).toBeGreaterThan(-1);
    expect(highPos).toBeGreaterThan(-1);
    expect(mediumPos).toBeGreaterThan(-1);
    expect(criticalPos).toBeLessThan(highPos);
    expect(highPos).toBeLessThan(mediumPos);
  });

  it('includes finding count in severity heading', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'high', name: 'Issue A' }),
      makeResult({ status: 'fail', severity: 'high', name: 'Issue B' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 80), makeContext(), VERSION);
    expect(md).toContain('### High (2)');
  });

  it('renders finding name, severity, and description', () => {
    const results: CheckResult[] = [
      makeResult({
        status: 'fail',
        severity: 'critical',
        name: 'Hardcoded API Key',
        description: 'Found hardcoded OpenAI API key',
      }),
    ];
    const md = formatMarkdownReport(makeReport(results, 85), makeContext(), VERSION);
    expect(md).toContain('#### Hardcoded API Key');
    expect(md).toContain('Critical');
    expect(md).toContain('Found hardcoded OpenAI API key');
  });

  it('renders finding location when present', () => {
    const results: CheckResult[] = [
      makeResult({
        status: 'fail',
        severity: 'high',
        name: 'Issue',
        location: 'src/config.ts:42',
      }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).toContain('`src/config.ts:42`');
  });

  it('omits location line when not present', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'high', name: 'Issue' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).not.toContain('**Location:**');
  });

  it('renders fix text when present', () => {
    const results: CheckResult[] = [
      makeResult({
        status: 'fail',
        severity: 'high',
        name: 'Issue',
        fix: 'Move key to .env file',
      }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).toContain('Move key to .env file');
  });

  it('renders AI prompt as blockquote when present', () => {
    const results: CheckResult[] = [
      makeResult({
        status: 'fail',
        severity: 'high',
        name: 'Issue',
        aiPrompt: 'Help me secure this API key',
      }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).toContain('> Help me secure this API key');
  });

  it('includes warnings in findings grouped by severity', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'warn', severity: 'medium', name: 'Warn issue' }),
    ];
    const md = formatMarkdownReport(makeReport(results), makeContext(), VERSION);
    expect(md).toContain('### Medium');
    expect(md).toContain('Warn issue');
  });

  it('shows passed checks in a separate section', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'pass', name: '.gitignore coverage', description: 'All patterns present' }),
      makeResult({ status: 'pass', name: 'security.txt', description: 'File exists' }),
    ];
    const md = formatMarkdownReport(makeReport(results), makeContext(), VERSION);
    expect(md).toContain('## Passed Checks');
    expect(md).toContain('.gitignore coverage');
    expect(md).toContain('security.txt');
  });

  it('omits passed checks section when there are none', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'high', name: 'Issue' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).not.toContain('## Passed Checks');
  });

  it('includes recommendations section', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md).toContain('## Recommendations');
  });

  it('recommends addressing critical findings when present', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'critical', name: 'Crit' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 85), makeContext(), VERSION);
    expect(md).toMatch(/critical/i);
    expect(md).toContain('immediately');
  });

  it('recommends reviewing high findings when present', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'fail', severity: 'high', name: 'High issue' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).toContain('high');
    expect(md).toContain('deployment');
  });

  it('congratulates when no findings exist', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'pass', name: 'All good' }),
    ];
    const md = formatMarkdownReport(makeReport(results), makeContext(), VERSION);
    expect(md).toContain('no security findings');
  });

  it('includes footer with Bastion version', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), '1.2.3');
    expect(md).toContain('Bastion');
    expect(md).toContain('v1.2.3');
    expect(md).toContain('Privacy-first security checker');
  });

  it('handles empty results gracefully', () => {
    const md = formatMarkdownReport(makeReport([]), makeContext(), VERSION);
    expect(md).toContain('# Bastion Security Report');
    expect(md).toContain('## Recommendations');
    expect(md).not.toContain('## Findings');
  });

  it('handles report with only passing checks', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'pass', name: 'Check A' }),
      makeResult({ status: 'pass', name: 'Check B' }),
    ];
    const md = formatMarkdownReport(makeReport(results), makeContext(), VERSION);
    expect(md).toContain('## Passed Checks');
    expect(md).not.toContain('## Findings');
    expect(md).toContain('100/100');
  });

  it('includes summary counts', () => {
    const results: CheckResult[] = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      makeResult({ status: 'warn', severity: 'medium' }),
      makeResult({ status: 'skip' }),
    ];
    const md = formatMarkdownReport(makeReport(results, 90), makeContext(), VERSION);
    expect(md).toContain('1 passed');
    expect(md).toContain('1 failed');
    expect(md).toContain('1 warning');
  });
});

// ---------------------------------------------------------------------------
// writeMarkdownReport
// ---------------------------------------------------------------------------

describe('writeMarkdownReport', () => {
  const tmpDir = join(tmpdir(), `bastion-md-test-${process.pid}`);

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('writes the report file to disk', async () => {
    await mkdir(tmpDir, { recursive: true });
    const outputPath = join(tmpDir, 'security-report.md');

    const result = await writeMarkdownReport(
      makeReport([makeResult({ status: 'fail', severity: 'high', name: 'Test finding' })], 90),
      makeContext({ projectPath: tmpDir }),
      VERSION,
      outputPath,
    );

    expect(result).toBe(outputPath);
    const content = await readFile(outputPath, 'utf-8');
    expect(content).toContain('# Bastion Security Report');
    expect(content).toContain('Test finding');
  });

  it('defaults to security-report.md in the project directory', async () => {
    await mkdir(tmpDir, { recursive: true });
    const expectedPath = join(tmpDir, 'security-report.md');

    const result = await writeMarkdownReport(
      makeReport([]),
      makeContext({ projectPath: tmpDir }),
      VERSION,
    );

    expect(result).toBe(expectedPath);
    const content = await readFile(expectedPath, 'utf-8');
    expect(content).toContain('# Bastion Security Report');
  });

  it('uses custom output path when provided', async () => {
    await mkdir(tmpDir, { recursive: true });
    const customPath = join(tmpDir, 'custom-report.md');

    const result = await writeMarkdownReport(
      makeReport([]),
      makeContext({ projectPath: '/some/other/path' }),
      VERSION,
      customPath,
    );

    expect(result).toBe(customPath);
    const content = await readFile(customPath, 'utf-8');
    expect(content).toContain('# Bastion Security Report');
  });

  it('written file contains correct score and findings', async () => {
    await mkdir(tmpDir, { recursive: true });
    const outputPath = join(tmpDir, 'report.md');

    const results: CheckResult[] = [
      makeResult({
        status: 'fail',
        severity: 'critical',
        name: 'Hardcoded Secret',
        description: 'API key found in source',
        fix: 'Use environment variables',
        aiPrompt: 'Help me fix this secret',
        location: 'src/app.ts:10',
      }),
      makeResult({ status: 'pass', name: 'Gitignore check' }),
    ];

    await writeMarkdownReport(makeReport(results, 85), makeContext(), VERSION, outputPath);

    const content = await readFile(outputPath, 'utf-8');
    expect(content).toContain('85/100');
    expect(content).toContain('Hardcoded Secret');
    expect(content).toContain('API key found in source');
    expect(content).toContain('Use environment variables');
    expect(content).toContain('> Help me fix this secret');
    expect(content).toContain('`src/app.ts:10`');
    expect(content).toContain('Gitignore check');
  });
});
