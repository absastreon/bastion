import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanContext } from '@bastion/shared';

vi.mock('node:child_process', () => ({
  execSync: vi.fn(),
}));

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
}));

import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import dependencyCheck from '../../src/checks/dependencies.js';

const mockedExecSync = vi.mocked(execSync);
const mockedExistsSync = vi.mocked(existsSync);

/** Minimal context with package.json present */
const baseContext: ScanContext = {
  projectPath: '/tmp/test-project',
  stack: { language: 'javascript' },
  packageJson: { name: 'test-project' },
  files: [],
  verbose: false,
  projectType: 'unknown',
  projectTypeSource: 'auto',
};

/** Build npm audit JSON output string */
function makeAuditOutput(vulns: Record<string, unknown> = {}): string {
  return JSON.stringify({ vulnerabilities: vulns });
}

/** Build a single vulnerability entry for npm audit output */
function makeVuln(overrides: Record<string, unknown> = {}) {
  return {
    name: 'some-pkg',
    severity: 'high',
    via: [{
      source: 1,
      name: 'some-pkg',
      title: 'Prototype Pollution',
      url: 'https://github.com/advisories/GHSA-xxxx',
      severity: 'high',
      range: '<1.0.0',
    }],
    fixAvailable: true,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Edge cases: no package.json, no node_modules
// ---------------------------------------------------------------------------

describe('dependency vulnerability check', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('skips when no package.json exists', async () => {
    const ctx: ScanContext = { ...baseContext, packageJson: undefined };
    const results = await dependencyCheck(ctx);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('No package.json');
    expect(mockedExecSync).not.toHaveBeenCalled();
    expect(mockedExistsSync).not.toHaveBeenCalled();
  });

  it('warns when node_modules directory is missing', async () => {
    mockedExistsSync.mockReturnValue(false);

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('warn');
    expect(results[0]?.severity).toBe('medium');
    expect(results[0]?.description).toContain('node_modules');
    expect(results[0]?.fix).toContain('npm install');
    expect(mockedExecSync).not.toHaveBeenCalled();
  });

  // ---------------------------------------------------------------------------
  // Clean project
  // ---------------------------------------------------------------------------

  it('passes when npm audit reports no vulnerabilities', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({}));

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('No known vulnerabilities');
  });

  it('passes when vulnerabilities key is absent from audit output', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(JSON.stringify({ auditReportVersion: 2 }));

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  // ---------------------------------------------------------------------------
  // Vulnerability parsing
  // ---------------------------------------------------------------------------

  it('maps a single vulnerability to a fail result with all fields', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      lodash: makeVuln({ name: 'lodash', severity: 'high' }),
    }));

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
    expect(results[0]?.id).toBe('dep-vuln-lodash');
    expect(results[0]?.category).toBe('dependencies');
    expect(results[0]?.description).toContain('lodash');
    expect(results[0]?.description).toContain('Prototype Pollution');
    expect(results[0]?.description).toContain('GHSA-xxxx');
    expect(results[0]?.fix).toContain('npm install lodash@latest');
    expect(results[0]?.aiPrompt).toContain('npm update lodash');
  });

  it('maps multiple vulnerabilities to multiple results', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      'pkg-a': makeVuln({ name: 'pkg-a', severity: 'critical' }),
      'pkg-b': makeVuln({ name: 'pkg-b', severity: 'low' }),
    }));

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(2);
    const severities = results.map((r) => r.severity);
    expect(severities).toContain('critical');
    expect(severities).toContain('low');
  });

  // ---------------------------------------------------------------------------
  // Severity mapping
  // ---------------------------------------------------------------------------

  it.each([
    ['critical', 'critical'],
    ['high', 'high'],
    ['moderate', 'medium'],
    ['low', 'low'],
    ['info', 'info'],
  ] as const)('maps npm severity "%s" to Bastion severity "%s"', async (npmSev, bastionSev) => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      pkg: makeVuln({ name: 'pkg', severity: npmSev }),
    }));

    const results = await dependencyCheck(baseContext);
    expect(results[0]?.severity).toBe(bastionSev);
  });

  // ---------------------------------------------------------------------------
  // Via array handling
  // ---------------------------------------------------------------------------

  it('handles via with only string references (transitive dependency)', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      transitive: makeVuln({ name: 'transitive', via: ['other-pkg'] }),
    }));

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.description).toContain('transitive');
    expect(results[0]?.description).toContain('Vulnerability');
  });

  // ---------------------------------------------------------------------------
  // npm audit exit behavior
  // ---------------------------------------------------------------------------

  it('extracts stdout from non-zero exit code (vulnerabilities found)', async () => {
    mockedExistsSync.mockReturnValue(true);
    const output = makeAuditOutput({
      bad: makeVuln({ name: 'bad', severity: 'critical' }),
    });
    const error = Object.assign(new Error('exit code 1'), { stdout: output });
    mockedExecSync.mockImplementation(() => {
      throw error;
    });

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('critical');
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  it('skips gracefully when npm command fails entirely', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockImplementation(() => {
      throw new Error('ENOENT');
    });

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('npm audit could not be run');
  });

  it('skips gracefully when npm audit returns invalid JSON', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue('not json {{{');

    const results = await dependencyCheck(baseContext);

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('parse');
  });

  // ---------------------------------------------------------------------------
  // aiPrompt content
  // ---------------------------------------------------------------------------

  it('includes advisory URL in aiPrompt when available', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      pkg: makeVuln({
        name: 'pkg',
        via: [{
          source: 1, name: 'pkg', title: 'XSS',
          url: 'https://advisory.example.com', severity: 'high', range: '*',
        }],
      }),
    }));

    const results = await dependencyCheck(baseContext);
    expect(results[0]?.aiPrompt).toContain('https://advisory.example.com');
  });

  it('generates aiPrompt without URL for transitive vulnerabilities', async () => {
    mockedExistsSync.mockReturnValue(true);
    mockedExecSync.mockReturnValue(makeAuditOutput({
      transitive: makeVuln({ name: 'transitive', via: ['upstream'] }),
    }));

    const results = await dependencyCheck(baseContext);
    expect(results[0]?.aiPrompt).toContain('npm update transitive');
    expect(results[0]?.aiPrompt).not.toContain('Advisory:');
  });
});
