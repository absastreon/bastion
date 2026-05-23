import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ignoreScriptsCheck, { parseNpmrc } from '../../../src/checks/supply-chain/ignore-scripts.js';
import type { ScanContext } from '@bastion/shared';

/** Build a minimal ScanContext pointing at a temp directory */
function makeContext(projectPath: string): ScanContext {
  return {
    projectPath,
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    projectType: 'unknown',
    projectTypeSource: 'auto',
  };
}

// ---------------------------------------------------------------------------
// parseNpmrc (pure unit tests — no filesystem)
// ---------------------------------------------------------------------------

describe('parseNpmrc', () => {
  it('parses simple key=value pairs', () => {
    expect(parseNpmrc('ignore-scripts=true\nregistry=https://registry.npmjs.org')).toEqual({
      'ignore-scripts': 'true',
      registry: 'https://registry.npmjs.org',
    });
  });

  it('skips comment lines starting with #', () => {
    expect(parseNpmrc('# this is a comment\nignore-scripts=true')).toEqual({
      'ignore-scripts': 'true',
    });
  });

  it('skips comment lines starting with ;', () => {
    expect(parseNpmrc('; this is a comment\nignore-scripts=true')).toEqual({
      'ignore-scripts': 'true',
    });
  });

  it('skips empty lines', () => {
    expect(parseNpmrc('\n\nignore-scripts=true\n\n')).toEqual({
      'ignore-scripts': 'true',
    });
  });

  it('trims whitespace around keys and values', () => {
    expect(parseNpmrc('  ignore-scripts = true  ')).toEqual({
      'ignore-scripts': 'true',
    });
  });

  it('handles Windows line endings', () => {
    expect(parseNpmrc('ignore-scripts=true\r\nregistry=https://r.npm.io')).toEqual({
      'ignore-scripts': 'true',
      registry: 'https://r.npm.io',
    });
  });

  it('returns empty object for empty content', () => {
    expect(parseNpmrc('')).toEqual({});
  });

  it('skips lines without = sign', () => {
    expect(parseNpmrc('no-equals-here\nignore-scripts=true')).toEqual({
      'ignore-scripts': 'true',
    });
  });
});

// ---------------------------------------------------------------------------
// ignoreScriptsCheck (integration tests — uses temp directories)
// ---------------------------------------------------------------------------

describe('ignoreScriptsCheck', () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), 'bastion-ignore-scripts-'));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it('returns pass when .npmrc has ignore-scripts=true', async () => {
    await writeFile(join(testDir, '.npmrc'), 'ignore-scripts=true\n');
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('ignore-scripts');
    expect(results[0].status).toBe('pass');
    expect(results[0].severity).toBe('info');
    expect(results[0].category).toBe('supply-chain');
    expect(results[0].location).toBe('.npmrc');
  });

  it('returns warn when .npmrc exists but lacks the setting', async () => {
    await writeFile(join(testDir, '.npmrc'), 'registry=https://registry.npmjs.org\n');
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('ignore-scripts');
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
    expect(results[0].category).toBe('supply-chain');
    expect(results[0].location).toBe('.npmrc');
    expect(results[0].fix).toBeDefined();
    expect(results[0].aiPrompt).toBeDefined();
  });

  it('returns warn when .npmrc has ignore-scripts=false', async () => {
    await writeFile(join(testDir, '.npmrc'), 'ignore-scripts=false\n');
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
    expect(results[0].description).toContain('malicious postinstall scripts');
  });

  it('returns warn when no .npmrc file exists', async () => {
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('ignore-scripts');
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
    expect(results[0].category).toBe('supply-chain');
    expect(results[0].location).toBe('.npmrc');
    expect(results[0].description).toContain('No .npmrc file found');
    expect(results[0].fix).toContain('ignore-scripts=true');
    expect(results[0].aiPrompt).toBeDefined();
  });

  it('handles .npmrc with ignore-scripts among other settings', async () => {
    const content = [
      '# npm config',
      'registry=https://registry.npmjs.org',
      'ignore-scripts=true',
      'save-exact=true',
    ].join('\n');
    await writeFile(join(testDir, '.npmrc'), content);
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('treats ignore-scripts with whitespace around = correctly', async () => {
    await writeFile(join(testDir, '.npmrc'), 'ignore-scripts = true\n');
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('includes Shai-Hulud reference in warn description', async () => {
    const results = await ignoreScriptsCheck(makeContext(testDir));

    expect(results[0].description).toContain('Shai-Hulud');
  });
});
