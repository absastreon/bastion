import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import gitignoreCheck, {
  isEntryCovered,
  parseGitignore,
} from '../../src/checks/gitignore.js';
import type { ScanContext } from 'bastion-shared';

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

/** All essential entries a complete .gitignore should have */
const COMPLETE_GITIGNORE = [
  '.env',
  '.env.local',
  'node_modules',
  '*.pem',
  '*.key',
  '.next',
  'dist',
  'build',
  '.DS_Store',
].join('\n');

// ---------------------------------------------------------------------------
// parseGitignore (pure unit tests — no filesystem)
// ---------------------------------------------------------------------------

describe('parseGitignore', () => {
  it('returns non-empty, non-comment lines', () => {
    const content = '.env\nnode_modules\n# comment\n\ndist';
    expect(parseGitignore(content)).toEqual(['.env', 'node_modules', 'dist']);
  });

  it('strips leading and trailing whitespace from lines', () => {
    expect(parseGitignore('  .env  \n  dist  ')).toEqual(['.env', 'dist']);
  });

  it('skips comment lines starting with #', () => {
    expect(parseGitignore('# dependencies\n# build')).toEqual([]);
  });

  it('skips empty lines', () => {
    expect(parseGitignore('\n\n\n')).toEqual([]);
  });

  it('handles a realistic .gitignore', () => {
    const content = [
      '# dependencies',
      'node_modules/',
      '',
      '# environment',
      '.env',
      '.env.local',
      '',
      '# build',
      'dist',
      'build',
      '.next',
    ].join('\n');
    expect(parseGitignore(content)).toEqual([
      'node_modules/',
      '.env',
      '.env.local',
      'dist',
      'build',
      '.next',
    ]);
  });
});

// ---------------------------------------------------------------------------
// isEntryCovered (pure unit tests — no filesystem)
// ---------------------------------------------------------------------------

describe('isEntryCovered', () => {
  it('matches exact entry', () => {
    expect(isEntryCovered('.env', ['.env'])).toBe(true);
  });

  it('matches line with trailing slash', () => {
    expect(isEntryCovered('node_modules', ['node_modules/'])).toBe(true);
  });

  it('matches line with leading slash (root anchor)', () => {
    expect(isEntryCovered('dist', ['/dist'])).toBe(true);
  });

  it('matches leading slash + trailing slash combined', () => {
    expect(isEntryCovered('node_modules', ['/node_modules/'])).toBe(true);
  });

  it('matches glob pattern .env* against .env', () => {
    expect(isEntryCovered('.env', ['.env*'])).toBe(true);
  });

  it('matches glob pattern .env* against .env.local', () => {
    expect(isEntryCovered('.env.local', ['.env*'])).toBe(true);
  });

  it('matches exact glob pattern *.pem', () => {
    expect(isEntryCovered('*.pem', ['*.pem'])).toBe(true);
  });

  it('matches exact glob pattern *.key', () => {
    expect(isEntryCovered('*.key', ['*.key'])).toBe(true);
  });

  it('does not match negation patterns', () => {
    expect(isEntryCovered('.env', ['!.env'])).toBe(false);
  });

  it('does not match unrelated entries', () => {
    expect(isEntryCovered('.env', ['node_modules', 'dist'])).toBe(false);
  });

  it('returns false for empty lines array', () => {
    expect(isEntryCovered('.env', [])).toBe(false);
  });

  it('does not match partial names', () => {
    expect(isEntryCovered('dist', ['distribute'])).toBe(false);
  });

  it('glob entry *.pem is not covered by a broader pattern like *', () => {
    // *.pem requires the exact pattern — a bare `*` does not satisfy it
    expect(isEntryCovered('*.pem', ['*'])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// gitignoreCheck (integration tests — uses temp directories)
// ---------------------------------------------------------------------------

describe('gitignoreCheck', () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), 'bastion-gitignore-'));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it('returns critical fail when .gitignore is missing', async () => {
    const results = await gitignoreCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('gitignore-missing');
    expect(results[0].status).toBe('fail');
    expect(results[0].severity).toBe('critical');
    expect(results[0].fix).toBeDefined();
    expect(results[0].aiPrompt).toContain('javascript');
  });

  it('returns single pass when all entries are covered', async () => {
    await writeFile(join(testDir, '.gitignore'), COMPLETE_GITIGNORE);
    const results = await gitignoreCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('gitignore-coverage');
    expect(results[0].status).toBe('pass');
  });

  it('returns fail for each missing entry', async () => {
    await writeFile(join(testDir, '.gitignore'), '# empty gitignore\n');
    const results = await gitignoreCheck(makeContext(testDir));

    // 9 required entries, all missing
    expect(results).toHaveLength(9);
    expect(results.every((r) => r.status === 'fail')).toBe(true);
  });

  it('uses .env* to cover both .env and .env.local', async () => {
    const content = ['.env*', 'node_modules', '*.pem', '*.key', '.next', 'dist', 'build', '.DS_Store'].join('\n');
    await writeFile(join(testDir, '.gitignore'), content);
    const results = await gitignoreCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('sets correct severity for .env (critical)', async () => {
    // Only include everything except .env
    const content = ['.env.local', 'node_modules', '*.pem', '*.key', '.next', 'dist', 'build', '.DS_Store'].join('\n');
    await writeFile(join(testDir, '.gitignore'), content);
    const results = await gitignoreCheck(makeContext(testDir));

    const envResult = results.find((r) => r.id === 'gitignore-env');
    expect(envResult).toBeDefined();
    expect(envResult?.severity).toBe('critical');
  });

  it('sets correct severity for node_modules (high)', async () => {
    const content = ['.env', '.env.local', '*.pem', '*.key', '.next', 'dist', 'build', '.DS_Store'].join('\n');
    await writeFile(join(testDir, '.gitignore'), content);
    const results = await gitignoreCheck(makeContext(testDir));

    const nmResult = results.find((r) => r.id === 'gitignore-node-modules');
    expect(nmResult).toBeDefined();
    expect(nmResult?.severity).toBe('high');
  });

  it('sets correct severity for .DS_Store (medium)', async () => {
    const content = ['.env', '.env.local', 'node_modules', '*.pem', '*.key', '.next', 'dist', 'build'].join('\n');
    await writeFile(join(testDir, '.gitignore'), content);
    const results = await gitignoreCheck(makeContext(testDir));

    const dsResult = results.find((r) => r.id === 'gitignore-ds-store');
    expect(dsResult).toBeDefined();
    expect(dsResult?.severity).toBe('medium');
  });

  it('includes fix and aiPrompt in every failure', async () => {
    await writeFile(join(testDir, '.gitignore'), '# empty\n');
    const results = await gitignoreCheck(makeContext(testDir));

    for (const r of results) {
      expect(r.fix).toBeDefined();
      expect(r.aiPrompt).toBeDefined();
    }
  });

  it('sets category and location on all results', async () => {
    await writeFile(join(testDir, '.gitignore'), COMPLETE_GITIGNORE);
    const results = await gitignoreCheck(makeContext(testDir));

    for (const r of results) {
      expect(r.category).toBe('configuration');
      expect(r.location).toBe('.gitignore');
    }
  });

  it('returns skip for unexpected read errors', async () => {
    // Create .gitignore as a directory — reading it as a file causes EISDIR
    await mkdir(join(testDir, '.gitignore'));
    const results = await gitignoreCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('gitignore-error');
    expect(results[0].status).toBe('skip');
    expect(results[0].severity).toBe('info');
  });

  it('handles trailing slashes in .gitignore entries', async () => {
    const content = [
      '.env',
      '.env.local',
      'node_modules/',
      '*.pem',
      '*.key',
      '.next/',
      'dist/',
      'build/',
      '.DS_Store',
    ].join('\n');
    await writeFile(join(testDir, '.gitignore'), content);
    const results = await gitignoreCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('uses stack language in aiPrompt for missing file', async () => {
    const ctx: ScanContext = {
      ...makeContext(testDir),
      stack: { language: 'python' },
    };
    const results = await gitignoreCheck(ctx);

    expect(results[0].aiPrompt).toContain('python');
  });
});
