import { describe, it, expect } from 'vitest';
import { calculateScore, summarizeResults, runChecks, detectProjectType } from '../src/scanner.js';
import type { CheckFunction, CheckResult, ScanContext } from 'bastion-shared';

/** Minimal context for unit tests — no filesystem needed */
const mockContext: ScanContext = {
  projectPath: '/tmp/test-project',
  stack: { language: 'javascript' },
  files: [],
  verbose: false,
  projectType: 'unknown',
  projectTypeSource: 'auto',
};

/** Helper: build a CheckResult with sensible defaults */
function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    id: 'test',
    name: 'Test check',
    status: 'pass',
    severity: 'info',
    description: 'Test',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// calculateScore
// ---------------------------------------------------------------------------

describe('calculateScore', () => {
  it('returns 100 for empty results', () => {
    expect(calculateScore([])).toBe(100);
  });

  it('returns 100 when all checks pass', () => {
    const results = [makeResult({ status: 'pass' }), makeResult({ status: 'pass' })];
    expect(calculateScore(results)).toBe(100);
  });

  it('returns 0 when only check fails', () => {
    expect(calculateScore([makeResult({ status: 'fail', severity: 'critical' })])).toBe(0);
  });

  it('calculates pass-rate among checks that ran', () => {
    // 3 pass, 2 fail → 3/5 = 60%
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      makeResult({ status: 'fail', severity: 'medium' }),
    ];
    expect(calculateScore(results)).toBe(60);
  });

  it('treats warnings as non-failures', () => {
    // 1 pass + 1 warn = 2 non-fail out of 3 ran → 67%
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'warn', severity: 'medium' }),
      makeResult({ status: 'fail', severity: 'high' }),
    ];
    expect(calculateScore(results)).toBe(67);
  });

  it('excludes skipped checks from score calculation', () => {
    // 3 pass, 2 fail, 7 skip → 3/5 = 60% (skips ignored)
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      makeResult({ status: 'fail', severity: 'medium' }),
      ...Array.from({ length: 7 }, () => makeResult({ status: 'skip', severity: 'info' })),
    ];
    expect(calculateScore(results)).toBe(60);
  });

  it('returns 100 when only skipped checks exist', () => {
    const results = [
      makeResult({ status: 'skip' }),
      makeResult({ status: 'skip' }),
    ];
    expect(calculateScore(results)).toBe(100);
  });

  it('excludes not-applicable checks from score calculation', () => {
    // 2 pass, 1 fail, 2 not-applicable → 2/3 = 67% (N/A ignored)
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail', severity: 'high' }),
      makeResult({ status: 'not-applicable' }),
      makeResult({ status: 'not-applicable' }),
    ];
    expect(calculateScore(results)).toBe(67);
  });

  it('returns 100 when only not-applicable checks exist', () => {
    const results = [
      makeResult({ status: 'not-applicable' }),
      makeResult({ status: 'not-applicable' }),
    ];
    expect(calculateScore(results)).toBe(100);
  });

  it('floors at 0 when all checks fail', () => {
    const results = Array.from({ length: 5 }, () =>
      makeResult({ status: 'fail', severity: 'critical' }),
    );
    expect(calculateScore(results)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// summarizeResults
// ---------------------------------------------------------------------------

describe('summarizeResults', () => {
  it('returns zeros for empty array', () => {
    expect(summarizeResults([])).toEqual({ pass: 0, fail: 0, warn: 0, skip: 0, notApplicable: 0, checksRun: 0, total: 0 });
  });

  it('counts each status correctly', () => {
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'pass' }),
      makeResult({ status: 'fail' }),
      makeResult({ status: 'warn' }),
      makeResult({ status: 'skip' }),
    ];
    expect(summarizeResults(results)).toEqual({ pass: 2, fail: 1, warn: 1, skip: 1, notApplicable: 0, checksRun: 4, total: 5 });
  });

  it('counts not-applicable results separately', () => {
    const results = [
      makeResult({ status: 'pass' }),
      makeResult({ status: 'not-applicable' }),
      makeResult({ status: 'not-applicable' }),
    ];
    expect(summarizeResults(results)).toEqual({ pass: 1, fail: 0, warn: 0, skip: 0, notApplicable: 2, checksRun: 1, total: 3 });
  });
});

// ---------------------------------------------------------------------------
// runChecks
// ---------------------------------------------------------------------------

describe('runChecks', () => {
  it('returns score 100 and empty results for no checks', async () => {
    const report = await runChecks(mockContext, []);
    expect(report.results).toHaveLength(0);
    expect(report.score).toBe(100);
    expect(report.summary.checksRun).toBe(0);
    expect(report.duration).toBeGreaterThanOrEqual(0);
  });

  it('collects results from multiple checks', async () => {
    const check1: CheckFunction = async () => [makeResult({ id: 'a', status: 'pass' })];
    const check2: CheckFunction = async () => [
      makeResult({ id: 'b', status: 'fail', severity: 'high' }),
    ];

    const report = await runChecks(mockContext, [check1, check2]);

    expect(report.results).toHaveLength(2);
    expect(report.score).toBe(50); // 1 pass, 1 fail → 1/2 = 50%
    expect(report.summary.pass).toBe(1);
    expect(report.summary.fail).toBe(1);
  });

  it('handles a check that returns multiple results', async () => {
    const multi: CheckFunction = async () => [
      makeResult({ id: 'x', status: 'pass' }),
      makeResult({ id: 'y', status: 'fail', severity: 'medium' }),
    ];

    const report = await runChecks(mockContext, [multi]);

    expect(report.results).toHaveLength(2);
    expect(report.score).toBe(50); // 1 pass, 1 fail → 1/2 = 50%
  });

  it('gracefully handles a throwing check', async () => {
    const good: CheckFunction = async () => [makeResult({ id: 'ok', status: 'pass' })];
    const bad: CheckFunction = async () => {
      throw new Error('Kaboom');
    };

    const report = await runChecks(mockContext, [good, bad]);

    expect(report.results).toHaveLength(2);
    const skipped = report.results.find((r) => r.status === 'skip');
    expect(skipped).toBeDefined();
    expect(skipped?.description).toContain('Kaboom');
    // Skipped check should not affect score
    expect(report.score).toBe(100);
  });

  it('gracefully handles a check that throws a non-Error', async () => {
    const bad: CheckFunction = async () => {
      throw 'string error';
    };

    const report = await runChecks(mockContext, [bad]);

    const skipped = report.results.find((r) => r.status === 'skip');
    expect(skipped?.description).toContain('string error');
  });

  it('runs checks in parallel', async () => {
    const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

    const slow1: CheckFunction = async () => {
      await delay(80);
      return [makeResult({ id: 's1' })];
    };
    const slow2: CheckFunction = async () => {
      await delay(80);
      return [makeResult({ id: 's2' })];
    };

    const report = await runChecks(mockContext, [slow1, slow2]);

    expect(report.results).toHaveLength(2);
    // Sequential would be >=160ms; parallel should be ~80ms
    expect(report.duration).toBeLessThan(150);
  });

  it('measures duration', async () => {
    const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
    const slow: CheckFunction = async () => {
      await delay(50);
      return [makeResult()];
    };

    const report = await runChecks(mockContext, [slow]);
    expect(report.duration).toBeGreaterThanOrEqual(40);
  });
});

// ---------------------------------------------------------------------------
// detectProjectType
// ---------------------------------------------------------------------------

describe('detectProjectType', () => {
  it('returns static for no package.json and no code files', () => {
    expect(detectProjectType(undefined, ['index.html', 'style.css'])).toBe('static');
  });

  it('returns static for no package.json and no files at all', () => {
    expect(detectProjectType(undefined, [])).toBe('static');
  });

  it('returns unknown for code files but no package.json', () => {
    expect(detectProjectType(undefined, ['app.js', 'utils.ts'])).toBe('unknown');
  });

  it('returns api for server files without package.json', () => {
    expect(detectProjectType(undefined, ['server.ts', 'app.js'])).toBe('api');
  });

  it('returns static for package.json with no server deps', () => {
    const pkg = { dependencies: { tailwindcss: '^3.0.0' }, devDependencies: { typescript: '^5.0.0' } };
    expect(detectProjectType(pkg, ['index.html', 'style.css'])).toBe('static');
  });

  it('returns fullstack for Next.js projects', () => {
    const pkg = { dependencies: { next: '^14.0.0', react: '^18.0.0' } };
    expect(detectProjectType(pkg, ['src/app/page.tsx'])).toBe('fullstack');
  });

  it('returns fullstack for Nuxt projects', () => {
    const pkg = { dependencies: { nuxt: '^3.0.0' } };
    expect(detectProjectType(pkg, ['pages/index.vue'])).toBe('fullstack');
  });

  it('returns api for Express-only projects', () => {
    const pkg = { dependencies: { express: '^4.0.0' } };
    expect(detectProjectType(pkg, ['src/index.ts', 'src/middleware.ts'])).toBe('api');
  });

  it('returns fullstack for Express with frontend files', () => {
    const pkg = { dependencies: { express: '^4.0.0' } };
    expect(detectProjectType(pkg, ['src/server.ts', 'public/app.tsx'])).toBe('fullstack');
  });

  it('returns api for Fastify projects without frontend', () => {
    const pkg = { dependencies: { fastify: '^4.0.0' } };
    expect(detectProjectType(pkg, ['src/routes.ts'])).toBe('api');
  });

  it('returns static when package.json has only devDependencies and no server code', () => {
    const pkg = { devDependencies: { prettier: '^3.0.0', eslint: '^8.0.0' } };
    expect(detectProjectType(pkg, ['README.md', 'index.html'])).toBe('static');
  });

  it('detects api from api/ directory in files', () => {
    const pkg = { dependencies: {} };
    expect(detectProjectType(pkg, ['src/api/users.ts'])).toBe('api');
  });

  it('detects api from routes/ directory in files', () => {
    const pkg = { dependencies: {} };
    expect(detectProjectType(pkg, ['routes/index.ts'])).toBe('api');
  });
});
