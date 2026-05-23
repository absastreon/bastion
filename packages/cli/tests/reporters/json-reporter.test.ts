import { describe, it, expect } from 'vitest';
import { formatJsonReport } from '../../src/reporters/json.js';
import type { JsonReportMetadata } from '../../src/reporters/json.js';
import type { CheckResult, ScanReport } from '@bastion/shared';

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

const defaultMetadata: JsonReportMetadata = {
  timestamp: '2026-04-15T00:00:00.000Z',
  version: '0.1.0',
  projectPath: '/test/project',
  detectedStack: { language: 'TypeScript', framework: 'Next.js' },
};

describe('formatJsonReport', () => {
  it('produces valid JSON', () => {
    const output = formatJsonReport(makeReport([makeResult()]), defaultMetadata);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('is parseable by standard JSON tools', () => {
    const output = formatJsonReport(
      makeReport([makeResult(), makeResult({ status: 'fail', severity: 'high' })], 90),
      defaultMetadata,
    );
    const parsed = JSON.parse(output) as Record<string, unknown>;
    expect(typeof parsed).toBe('object');
    expect(parsed).not.toBeNull();
  });

  it('includes score at top level', () => {
    const parsed = JSON.parse(formatJsonReport(makeReport([], 85), defaultMetadata));
    expect(parsed.score).toBe(85);
  });

  it('includes summary with all status counts', () => {
    const report = makeReport([
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      makeResult({ status: 'warn', severity: 'medium' }),
      makeResult({ status: 'skip' }),
    ], 90);
    const parsed = JSON.parse(formatJsonReport(report, defaultMetadata));

    expect(parsed.summary).toEqual({
      pass: 2,
      fail: 1,
      warn: 1,
      skip: 1,
      notApplicable: 0,
      checksRun: 4,
      total: 5,
    });
  });

  it('maps CheckResult.name to title in output', () => {
    const parsed = JSON.parse(
      formatJsonReport(makeReport([makeResult({ name: 'Gitignore coverage' })]), defaultMetadata),
    );
    expect(parsed.results[0].title).toBe('Gitignore coverage');
    expect(parsed.results[0]).not.toHaveProperty('name');
  });

  it('includes all required fields on each result', () => {
    const result = makeResult({
      id: 'secrets',
      name: 'Hardcoded secrets',
      status: 'fail',
      severity: 'critical',
      category: 'Secrets',
      location: 'src/config.ts:42',
      description: 'Found API key',
      fix: 'Move to .env',
      aiPrompt: 'Help me secure this',
    });
    const parsed = JSON.parse(formatJsonReport(makeReport([result]), defaultMetadata));
    const r = parsed.results[0];

    expect(r.id).toBe('secrets');
    expect(r.title).toBe('Hardcoded secrets');
    expect(r.severity).toBe('critical');
    expect(r.status).toBe('fail');
    expect(r.category).toBe('Secrets');
    expect(r.location).toBe('src/config.ts:42');
    expect(r.description).toBe('Found API key');
    expect(r.fix).toBe('Move to .env');
    expect(r.aiPrompt).toBe('Help me secure this');
  });

  it('uses null for optional fields when absent', () => {
    const result = makeResult({ category: undefined, location: undefined, fix: undefined, aiPrompt: undefined });
    const parsed = JSON.parse(formatJsonReport(makeReport([result]), defaultMetadata));
    const r = parsed.results[0];

    expect(r.location).toBeNull();
    expect(r.fix).toBeNull();
    expect(r.aiPrompt).toBeNull();
  });

  it('defaults category to General when not set', () => {
    const result = makeResult({ category: undefined });
    const parsed = JSON.parse(formatJsonReport(makeReport([result]), defaultMetadata));
    expect(parsed.results[0].category).toBe('General');
  });

  it('includes metadata with all required fields', () => {
    const parsed = JSON.parse(formatJsonReport(makeReport([]), defaultMetadata));

    expect(parsed.metadata.timestamp).toBe('2026-04-15T00:00:00.000Z');
    expect(parsed.metadata.version).toBe('0.1.0');
    expect(parsed.metadata.projectPath).toBe('/test/project');
    expect(parsed.metadata.detectedStack).toEqual({
      language: 'TypeScript',
      framework: 'Next.js',
    });
  });

  it('preserves full detected stack in metadata', () => {
    const fullStack = {
      language: 'TypeScript',
      framework: 'Express',
      packageManager: 'npm',
      database: 'PostgreSQL',
      auth: 'Clerk',
      hosting: 'Vercel',
    };
    const meta: JsonReportMetadata = { ...defaultMetadata, detectedStack: fullStack };
    const parsed = JSON.parse(formatJsonReport(makeReport([]), meta));
    expect(parsed.metadata.detectedStack).toEqual(fullStack);
  });

  it('includes projectType in metadata when provided', () => {
    const meta: JsonReportMetadata = {
      ...defaultMetadata,
      projectType: 'static',
      projectTypeSource: 'auto',
    };
    const parsed = JSON.parse(formatJsonReport(makeReport([]), meta));
    expect(parsed.metadata.projectType).toBe('static');
    expect(parsed.metadata.projectTypeSource).toBe('auto');
  });

  it('includes not-applicable status in results', () => {
    const result = makeResult({ status: 'not-applicable', name: 'Rate limiting' });
    const parsed = JSON.parse(formatJsonReport(makeReport([result]), defaultMetadata));
    expect(parsed.results[0].status).toBe('not-applicable');
  });

  it('returns results array matching input order', () => {
    const results = [
      makeResult({ id: 'a', name: 'First' }),
      makeResult({ id: 'b', name: 'Second' }),
      makeResult({ id: 'c', name: 'Third' }),
    ];
    const parsed = JSON.parse(formatJsonReport(makeReport(results), defaultMetadata));
    expect(parsed.results.map((r: { id: string }) => r.id)).toEqual(['a', 'b', 'c']);
  });

  it('handles empty results array', () => {
    const parsed = JSON.parse(formatJsonReport(makeReport([]), defaultMetadata));
    expect(parsed.results).toEqual([]);
    expect(parsed.summary.checksRun).toBe(0);
  });
});
