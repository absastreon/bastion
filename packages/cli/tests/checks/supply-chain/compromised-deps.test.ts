import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import compromisedDepsCheck, {
  findCompromisedMatch,
  getDirectDeps,
  resolveVersionFromLockfile,
} from '../../../src/checks/supply-chain/compromised-deps.js';
import type { CompromisedPackage } from '../../../src/data/compromised-packages.js';
import type { ScanContext } from '@bastion/shared';

/** Build a minimal ScanContext pointing at a temp directory */
function makeContext(
  projectPath: string,
  packageJson?: Record<string, unknown>,
): ScanContext {
  return {
    projectPath,
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    projectType: 'unknown',
    projectTypeSource: 'auto',
    packageJson,
  };
}

/** Mock compromised list for testing */
const MOCK_LIST: readonly CompromisedPackage[] = [
  {
    name: 'evil-package',
    versionRange: '>=1.0.0 <1.3.0',
    advisoryId: 'GHSA-test-0001-xxxx',
    source: 'shai-hulud',
    dateAdded: '2026-05-16',
    description: 'Malicious postinstall exfiltrating environment variables.',
  },
  {
    name: 'compromised-util',
    versionRange: '2.0.0 - 2.1.0',
    advisoryId: 'GHSA-test-0002-yyyy',
    source: 'sha1-hulud',
    dateAdded: '2026-05-10',
    description: 'Worm-propagated package injecting backdoor into build output.',
  },
];

/** Minimal lockfile structure (npm v3 format) */
function makeLockfile(deps: Record<string, string>): Record<string, unknown> {
  const packages: Record<string, Record<string, unknown>> = {
    '': { name: 'test-project', version: '1.0.0' },
  };

  for (const [name, version] of Object.entries(deps)) {
    packages[`node_modules/${name}`] = { version };
  }

  return { lockfileVersion: 3, packages };
}

// ---------------------------------------------------------------------------
// getDirectDeps (pure unit tests)
// ---------------------------------------------------------------------------

describe('getDirectDeps', () => {
  it('returns names from dependencies and devDependencies', () => {
    const pkg = {
      dependencies: { foo: '^1.0.0', bar: '^2.0.0' },
      devDependencies: { baz: '^3.0.0' },
    };
    expect(getDirectDeps(pkg)).toEqual(['foo', 'bar', 'baz']);
  });

  it('returns empty array when no deps fields', () => {
    expect(getDirectDeps({ name: 'test' })).toEqual([]);
  });

  it('handles missing devDependencies', () => {
    const pkg = { dependencies: { foo: '^1.0.0' } };
    expect(getDirectDeps(pkg)).toEqual(['foo']);
  });
});

// ---------------------------------------------------------------------------
// resolveVersionFromLockfile (pure unit tests)
// ---------------------------------------------------------------------------

describe('resolveVersionFromLockfile', () => {
  it('resolves version from packages field', () => {
    const lockfile = makeLockfile({ foo: '1.2.3' });
    expect(resolveVersionFromLockfile(lockfile, 'foo')).toBe('1.2.3');
  });

  it('returns undefined for missing package', () => {
    const lockfile = makeLockfile({ foo: '1.0.0' });
    expect(resolveVersionFromLockfile(lockfile, 'bar')).toBeUndefined();
  });

  it('returns undefined when lockfile has no packages field', () => {
    expect(resolveVersionFromLockfile({}, 'foo')).toBeUndefined();
  });

  it('returns undefined when version field is not a string', () => {
    const lockfile = {
      packages: { 'node_modules/foo': { version: 123 } },
    };
    expect(resolveVersionFromLockfile(lockfile, 'foo')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// findCompromisedMatch (pure unit tests)
// ---------------------------------------------------------------------------

describe('findCompromisedMatch', () => {
  it('returns match when version satisfies range', () => {
    const match = findCompromisedMatch('evil-package', '1.2.0', MOCK_LIST);
    expect(match).toBeDefined();
    expect(match?.advisoryId).toBe('GHSA-test-0001-xxxx');
  });

  it('returns undefined when version is outside range', () => {
    const match = findCompromisedMatch('evil-package', '1.3.0', MOCK_LIST);
    expect(match).toBeUndefined();
  });

  it('returns undefined when package name not in list', () => {
    const match = findCompromisedMatch('safe-package', '1.0.0', MOCK_LIST);
    expect(match).toBeUndefined();
  });

  it('returns undefined for empty list', () => {
    const match = findCompromisedMatch('evil-package', '1.0.0', []);
    expect(match).toBeUndefined();
  });

  it('matches second entry in list', () => {
    const match = findCompromisedMatch('compromised-util', '2.0.5', MOCK_LIST);
    expect(match).toBeDefined();
    expect(match?.source).toBe('sha1-hulud');
  });
});

// ---------------------------------------------------------------------------
// compromisedDepsCheck (integration tests — uses temp directories)
// ---------------------------------------------------------------------------

describe('compromisedDepsCheck', () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), 'bastion-compromised-deps-'));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it('returns skip when no package.json in context', async () => {
    const results = await compromisedDepsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('compromised-deps');
    expect(results[0].status).toBe('skip');
  });

  it('returns skip when no package-lock.json on disk', async () => {
    const ctx = makeContext(testDir, { dependencies: { foo: '^1.0.0' } });
    const results = await compromisedDepsCheck(ctx);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('skip');
    expect(results[0].description).toContain('No package-lock.json');
  });

  it('returns skip when package-lock.json is malformed JSON', async () => {
    await writeFile(join(testDir, 'package-lock.json'), '{ not valid json !!!');
    const ctx = makeContext(testDir, { dependencies: { foo: '^1.0.0' } });
    const results = await compromisedDepsCheck(ctx);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('skip');
    expect(results[0].description).toContain('malformed JSON');
  });

  it('returns pass when compromised list is empty (current default)', async () => {
    const lockfile = makeLockfile({ foo: '1.0.0' });
    await writeFile(join(testDir, 'package-lock.json'), JSON.stringify(lockfile));
    const ctx = makeContext(testDir, { dependencies: { foo: '^1.0.0' } });
    const results = await compromisedDepsCheck(ctx);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].description).toContain('empty');
  });

  it('returns pass when no direct deps match compromised list', async () => {
    // This test uses the actual COMPROMISED_PACKAGES (currently empty),
    // so it should pass regardless of lockfile content
    const lockfile = makeLockfile({ 'safe-pkg': '3.0.0' });
    await writeFile(join(testDir, 'package-lock.json'), JSON.stringify(lockfile));
    const ctx = makeContext(testDir, { dependencies: { 'safe-pkg': '^3.0.0' } });
    const results = await compromisedDepsCheck(ctx);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('sets correct category on all results', async () => {
    const lockfile = makeLockfile({ foo: '1.0.0' });
    await writeFile(join(testDir, 'package-lock.json'), JSON.stringify(lockfile));
    const ctx = makeContext(testDir, { dependencies: { foo: '^1.0.0' } });
    const results = await compromisedDepsCheck(ctx);

    for (const r of results) {
      expect(r.category).toBe('supply-chain');
    }
  });
});
