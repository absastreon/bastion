import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import npmCiCheck, {
  extractRunCommands,
  isProblematicNpmCommand,
} from '../../../src/checks/supply-chain/npm-ci.js';
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
// isProblematicNpmCommand (pure unit tests)
// ---------------------------------------------------------------------------

describe('isProblematicNpmCommand', () => {
  it('flags bare npm install', () => {
    expect(isProblematicNpmCommand('npm install')).toBe(true);
  });

  it('flags npm install with package name', () => {
    expect(isProblematicNpmCommand('npm install typescript')).toBe(true);
  });

  it('flags npm install with --save-dev', () => {
    expect(isProblematicNpmCommand('npm install --save-dev typescript')).toBe(true);
  });

  it('skips npm install -g (global)', () => {
    expect(isProblematicNpmCommand('npm install -g typescript')).toBe(false);
  });

  it('skips npm install --global', () => {
    expect(isProblematicNpmCommand('npm install --global typescript')).toBe(false);
  });

  it('flags npm i (shorthand)', () => {
    expect(isProblematicNpmCommand('npm i typescript')).toBe(true);
  });

  it('skips npm i -g (global shorthand)', () => {
    expect(isProblematicNpmCommand('npm i -g typescript')).toBe(false);
  });

  it('does not flag npm ci', () => {
    expect(isProblematicNpmCommand('npm ci')).toBe(false);
  });

  it('skips sudo npm install -g (global with sudo)', () => {
    expect(isProblematicNpmCommand('sudo npm install -g typescript')).toBe(false);
  });

  it('does not flag unrelated commands', () => {
    expect(isProblematicNpmCommand('echo hello')).toBe(false);
  });

  it('does not flag npm run build', () => {
    expect(isProblematicNpmCommand('npm run build')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// extractRunCommands (pure unit tests)
// ---------------------------------------------------------------------------

describe('extractRunCommands', () => {
  it('extracts single-line run commands', () => {
    const yaml = {
      jobs: {
        build: {
          steps: [
            { name: 'Install', run: 'npm install' },
            { name: 'Build', run: 'npm run build' },
          ],
        },
      },
    };
    const commands = extractRunCommands(yaml);
    expect(commands).toHaveLength(2);
    expect(commands[0]).toEqual({ stepName: 'Install', command: 'npm install' });
    expect(commands[1]).toEqual({ stepName: 'Build', command: 'npm run build' });
  });

  it('extracts multi-line run commands as separate lines', () => {
    const yaml = {
      jobs: {
        build: {
          steps: [{ name: 'Setup', run: 'npm ci\nnpm run build\nnpm test' }],
        },
      },
    };
    const commands = extractRunCommands(yaml);
    expect(commands).toHaveLength(3);
    expect(commands[0].command).toBe('npm ci');
    expect(commands[1].command).toBe('npm run build');
    expect(commands[2].command).toBe('npm test');
  });

  it('handles unnamed steps', () => {
    const yaml = {
      jobs: {
        build: {
          steps: [{ run: 'npm ci' }],
        },
      },
    };
    const commands = extractRunCommands(yaml);
    expect(commands[0].stepName).toBeUndefined();
  });

  it('returns empty array for null input', () => {
    expect(extractRunCommands(null)).toEqual([]);
  });

  it('returns empty array when no jobs', () => {
    expect(extractRunCommands({ on: 'push' })).toEqual([]);
  });

  it('skips steps without run field (uses: actions)', () => {
    const yaml = {
      jobs: {
        build: {
          steps: [
            { uses: 'actions/checkout@v4' },
            { name: 'Install', run: 'npm ci' },
          ],
        },
      },
    };
    const commands = extractRunCommands(yaml);
    expect(commands).toHaveLength(1);
    expect(commands[0].command).toBe('npm ci');
  });
});

// ---------------------------------------------------------------------------
// npmCiCheck (integration tests — uses temp directories)
// ---------------------------------------------------------------------------

describe('npmCiCheck', () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), 'bastion-npm-ci-'));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  /** Helper to write a workflow file */
  async function writeWorkflow(filename: string, content: string): Promise<void> {
    const dir = join(testDir, '.github', 'workflows');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, filename), content);
  }

  it('returns skip when .github/workflows directory does not exist', async () => {
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('npm-ci');
    expect(results[0].status).toBe('skip');
    expect(results[0].description).toContain('No .github/workflows/');
  });

  it('returns skip when workflows directory exists but is empty', async () => {
    await mkdir(join(testDir, '.github', 'workflows'), { recursive: true });
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('skip');
    expect(results[0].description).toContain('No workflow files');
  });

  it('returns warn when workflow uses npm install', async () => {
    await writeWorkflow('ci.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install deps
        run: npm install
      - name: Build
        run: npm run build
`);
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
    expect(results[0].category).toBe('supply-chain');
    expect(results[0].location).toBe('.github/workflows/ci.yml');
    expect(results[0].description).toContain('npm install');
    expect(results[0].description).toContain('Install deps');
    expect(results[0].fix).toContain('npm ci');
    expect(results[0].aiPrompt).toBeDefined();
  });

  it('returns pass when workflow uses npm ci', async () => {
    await writeWorkflow('ci.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: npm ci
      - name: Build
        run: npm run build
`);
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('detects npm install in multi-line run block', async () => {
    await writeWorkflow('deploy.yaml', `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup
        run: |
          npm install
          npm run build
          npm run deploy
`);
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].description).toContain('npm install');
  });

  it('skips malformed YAML without crashing', async () => {
    await writeWorkflow('broken.yml', '{{{{not valid yaml at all!!!!');
    await writeWorkflow('good.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
`);
    const results = await npmCiCheck(makeContext(testDir));

    // Should still process the good file
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });

  it('flags npm install but not npm install -g in same workflow', async () => {
    await writeWorkflow('mixed.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Install global tool
        run: npm install -g vercel
      - name: Install project deps
        run: npm install
`);
    const results = await npmCiCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].description).toContain('Install project deps');
    expect(results[0].description).not.toContain('Install global tool');
  });
});
