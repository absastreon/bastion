import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import selfHostedRunnerCheck, {
  categorizeRunner,
  extractRunsOn,
} from '../../../src/checks/supply-chain/self-hosted-runner.js';
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
// categorizeRunner (pure unit tests)
// ---------------------------------------------------------------------------

describe('categorizeRunner', () => {
  it('identifies ubuntu-latest as github-hosted', () => {
    expect(categorizeRunner('ubuntu-latest')).toBe('github-hosted');
  });

  it('identifies ubuntu-22.04 as github-hosted', () => {
    expect(categorizeRunner('ubuntu-22.04')).toBe('github-hosted');
  });

  it('identifies macos-latest as github-hosted', () => {
    expect(categorizeRunner('macos-latest')).toBe('github-hosted');
  });

  it('identifies windows-2022 as github-hosted', () => {
    expect(categorizeRunner('windows-2022')).toBe('github-hosted');
  });

  it('identifies self-hosted as self-hosted', () => {
    expect(categorizeRunner('self-hosted')).toBe('self-hosted');
  });

  it('identifies SHA1HULUD as ioc-match', () => {
    expect(categorizeRunner('SHA1HULUD')).toBe('ioc-match');
  });

  it('identifies sha1hulud (lowercase) as ioc-match', () => {
    expect(categorizeRunner('sha1hulud')).toBe('ioc-match');
  });

  it('identifies shai-hulud-runner as ioc-match (substring)', () => {
    expect(categorizeRunner('shai-hulud-runner')).toBe('ioc-match');
  });

  it('identifies my-custom-runner as unknown', () => {
    expect(categorizeRunner('my-custom-runner')).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// extractRunsOn (pure unit tests)
// ---------------------------------------------------------------------------

describe('extractRunsOn', () => {
  it('extracts runs-on string as single-element array', () => {
    const yaml = {
      jobs: {
        build: { 'runs-on': 'ubuntu-latest', steps: [] },
      },
    };
    const result = extractRunsOn(yaml);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ jobName: 'build', runsOn: ['ubuntu-latest'] });
  });

  it('extracts runs-on array as-is', () => {
    const yaml = {
      jobs: {
        build: { 'runs-on': ['self-hosted', 'linux'], steps: [] },
      },
    };
    const result = extractRunsOn(yaml);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ jobName: 'build', runsOn: ['self-hosted', 'linux'] });
  });

  it('extracts multiple jobs', () => {
    const yaml = {
      jobs: {
        build: { 'runs-on': 'ubuntu-latest', steps: [] },
        deploy: { 'runs-on': 'self-hosted', steps: [] },
      },
    };
    const result = extractRunsOn(yaml);
    expect(result).toHaveLength(2);
  });

  it('returns empty array for null input', () => {
    expect(extractRunsOn(null)).toEqual([]);
  });

  it('returns empty array when no jobs', () => {
    expect(extractRunsOn({ on: 'push' })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// selfHostedRunnerCheck (integration tests — uses temp directories)
// ---------------------------------------------------------------------------

describe('selfHostedRunnerCheck', () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), 'bastion-self-hosted-'));
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
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('self-hosted-runner');
    expect(results[0].status).toBe('skip');
  });

  it('returns pass when workflow uses only github-hosted runners', async () => {
    await writeWorkflow('ci.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].description).toContain('GitHub-hosted runners');
  });

  it('returns warn for self-hosted runner', async () => {
    await writeWorkflow('deploy.yml', `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
    expect(results[0].category).toBe('supply-chain');
    expect(results[0].location).toBe('.github/workflows/deploy.yml');
    expect(results[0].description).toContain('Self-hosted runner');
    expect(results[0].fix).toBeDefined();
    expect(results[0].aiPrompt).toBeDefined();
  });

  it('returns high for IoC label (SHA1HULUD)', async () => {
    await writeWorkflow('suspicious.yml', `
name: Suspicious
on: push
jobs:
  build:
    runs-on: SHA1HULUD
    steps:
      - uses: actions/checkout@v4
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('fail');
    expect(results[0].severity).toBe('high');
    expect(results[0].description).toContain('IoC');
    expect(results[0].description).toContain('Shai-Hulud');
    expect(results[0].fix).toContain('IMMEDIATE ACTION');
  });

  it('returns info for custom unrecognized label', async () => {
    await writeWorkflow('custom.yml', `
name: Custom
on: push
jobs:
  build:
    runs-on: my-org-runner
    steps:
      - uses: actions/checkout@v4
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].severity).toBe('info');
    expect(results[0].description).toContain('Custom/unrecognized');
  });

  it('uses highest severity when runs-on is array with mixed labels', async () => {
    await writeWorkflow('mixed.yml', `
name: Mixed
on: push
jobs:
  build:
    runs-on:
      - self-hosted
      - my-custom-name
    steps:
      - uses: actions/checkout@v4
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('warn');
    expect(results[0].severity).toBe('medium');
  });

  it('skips malformed YAML without crashing', async () => {
    await writeWorkflow('broken.yml', '{{{{not yaml!!!!');
    await writeWorkflow('good.yml', `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`);
    const results = await selfHostedRunnerCheck(makeContext(testDir));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('pass');
  });
});
