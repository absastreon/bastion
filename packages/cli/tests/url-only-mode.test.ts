import { describe, it, expect, vi } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanContext } from '@bastion/shared';

// This test verifies scan()'s ROUTING: that it calls getUrlOnlyChecks()
// when urlOnly is set and getAllChecks() otherwise. The check getters are
// mocked, so this does NOT verify the real getters' contents — each check's
// real behaviour is covered by its own dedicated test file. Stub IDs are
// internal to this test and chosen to be distinguishable, not to match
// production IDs exactly.
vi.mock('../src/checks/index.js', async (importActual) => {
  const actual = await importActual<typeof import('../src/checks/index.js')>();

  /** Factory: returns a CheckFunction that resolves immediately with the given ID */
  const stubCheck = (id: string) =>
    async () => [{
      id,
      name: `Stub: ${id}`,
      status: 'skip' as const,
      severity: 'info' as const,
      description: 'Stub check for routing test',
    }];

  return {
    ...actual,
    getUrlOnlyChecks: () => [
      stubCheck('headers'),
      stubCheck('ssl'),
      stubCheck('security-txt-url'),
      stubCheck('cookies'),
      stubCheck('server-disclosure'),
      stubCheck('dmarc'),
    ],
    getAllChecks: () => [
      stubCheck('headers'),
      stubCheck('ssl'),
      stubCheck('security-txt-url'),
      stubCheck('cookies'),
      stubCheck('server-disclosure'),
      stubCheck('dmarc'),
      stubCheck('gitignore'),
      stubCheck('secrets'),
      stubCheck('dep-vuln'),
      stubCheck('env-example'),
      stubCheck('security-txt'),
      stubCheck('code-patterns'),
      stubCheck('cors'),
      stubCheck('rate-limit'),
      stubCheck('auth'),
      stubCheck('ignore-scripts'),
      stubCheck('compromised-deps'),
      stubCheck('npm-ci'),
      stubCheck('self-hosted-runner'),
    ],
  };
});

import { buildContext, scan } from '../src/scanner.js';
import { computeUrlOnly } from '../src/cli.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(__dirname, 'fixtures');

/** IDs of checks that require source code — must not appear in URL-only mode */
const CODE_CHECK_IDS = [
  'gitignore', 'secrets', 'dep-vuln', 'env-example',
  'security-txt', 'code-patterns', 'cors', 'rate-limit', 'auth',
  'ignore-scripts', 'compromised-deps', 'npm-ci', 'self-hosted-runner',
];

/** Create a mock Command with a fixed getOptionValueSource response */
function mockCommand(pathSource: string): { getOptionValueSource(key: string): string | undefined } {
  return { getOptionValueSource: () => pathSource };
}

describe('URL-only mode (Bastion#1 regression)', () => {
  it('buildContext with urlOnly skips filesystem scanning', async () => {
    const context = await buildContext({
      path: resolve(FIXTURES, 'vulnerable-project'),
      url: 'https://example.com',
      verbose: false,
      urlOnly: true,
    });

    expect(context.urlOnly).toBe(true);
    expect(context.files).toEqual([]);
    expect(context.packageJson).toBeUndefined();
  });

  it('scan returns urlOnly report when context.urlOnly is set', async () => {
    const context: ScanContext = {
      projectPath: FIXTURES,
      url: 'https://example.com',
      stack: { language: 'unknown' },
      files: [],
      verbose: false,
      projectType: 'static',
      projectTypeSource: 'auto',
      urlOnly: true,
    };

    const report = await scan(context);

    expect(report.urlOnly).toBe(true);

    // Only URL checks should appear — no code-based checks
    const resultIds = report.results.map((r) => r.id);
    for (const codeId of CODE_CHECK_IDS) {
      expect(resultIds, `code check "${codeId}" should not run in URL-only mode`).not.toContain(codeId);
    }
  });

  it('scan runs all checks when url and path are both provided (urlOnly not set)', async () => {
    const context = await buildContext({
      path: resolve(FIXTURES, 'vulnerable-project'),
      url: 'https://example.com',
      verbose: false,
    });

    const report = await scan(context);

    expect(report.urlOnly).toBeFalsy();

    const resultIds = report.results.map((r) => r.id);
    expect(resultIds).toContain('gitignore');
    expect(resultIds).toContain('secrets');
  });
});

describe('computeUrlOnly', () => {
  it('returns true when url is set and path source is default', () => {
    expect(computeUrlOnly({ url: 'https://example.com' }, mockCommand('default'))).toBe(true);
  });

  it('returns false when url is set and path source is cli', () => {
    expect(computeUrlOnly({ url: 'https://example.com' }, mockCommand('cli'))).toBe(false);
  });

  it('returns false when url is not set regardless of path source', () => {
    expect(computeUrlOnly({}, mockCommand('default'))).toBe(false);
    expect(computeUrlOnly({ url: undefined }, mockCommand('cli'))).toBe(false);
  });
});
