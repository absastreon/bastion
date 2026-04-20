import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext } from '@bastion/shared';
import envExampleCheck from '../../src/checks/env-example.js';

let tempDir: string;

function makeContext(files: readonly string[]): ScanContext {
  return {
    projectPath: tempDir,
    stack: { language: 'javascript' },
    files,
    verbose: false,
  };
}

describe('env-example check', () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'bastion-env-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // Skip cases — not our responsibility
  // -------------------------------------------------------------------------

  it('skips when no .gitignore exists', async () => {
    const results = await envExampleCheck(makeContext([]));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.id).toBe('env-example');
  });

  it('skips when .env is not in .gitignore', async () => {
    await writeFile(join(tempDir, '.gitignore'), 'node_modules\ndist\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('skips when .gitignore only mentions .env in comments', async () => {
    await writeFile(join(tempDir, '.gitignore'), '# .env\nnode_modules\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  // -------------------------------------------------------------------------
  // Fail: .env gitignored but no template file
  // -------------------------------------------------------------------------

  it('fails when .env is gitignored but no .env.example exists', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
    expect(results[0]?.category).toBe('configuration');
    expect(results[0]?.fix).toBeDefined();
    expect(results[0]?.aiPrompt).toBeDefined();
    expect(results[0]?.description).toContain('.env.example');
  });

  // -------------------------------------------------------------------------
  // Gitignore pattern variations
  // -------------------------------------------------------------------------

  it('recognizes .env* glob pattern in .gitignore', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env*\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
  });

  it('recognizes anchored /.env pattern in .gitignore', async () => {
    await writeFile(join(tempDir, '.gitignore'), '/.env\nnode_modules\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results[0]?.status).toBe('fail');
  });

  it('handles .gitignore with mixed whitespace and empty lines', async () => {
    await writeFile(join(tempDir, '.gitignore'), '\n  \n  .env  \n\nnode_modules\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results[0]?.status).toBe('fail');
  });

  it('handles .gitignore with Windows line endings', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\r\nnode_modules\r\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results[0]?.status).toBe('fail');
  });

  // -------------------------------------------------------------------------
  // Pass: template file exists with safe placeholders
  // -------------------------------------------------------------------------

  it('passes when .env.example exists with placeholder values', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'DATABASE_URL=your_database_url_here\nAPI_KEY=\nSECRET=changeme\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('passes when .env.sample exists as alternative', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(join(tempDir, '.env.sample'), 'API_KEY=YOUR_API_KEY_HERE\n');
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.sample']));

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('passes when values are empty strings', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(join(tempDir, '.env.example'), 'API_KEY=\nDB_URL=\nSECRET=\n');
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('pass');
  });

  it('passes with quoted placeholder values', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'API_KEY="YOUR_API_KEY_HERE"\nDB="changeme"\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('pass');
  });

  it('passes when values contain placeholder keywords like xxx', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(join(tempDir, '.env.example'), 'STRIPE_KEY=sk-xxx-replace-me\n');
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('pass');
  });

  it('passes with comment-only and empty lines in .env.example', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      '# Database config\n\nDB_HOST=localhost\nDB_PORT=5432\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('pass');
  });

  // -------------------------------------------------------------------------
  // Fail: template file has real secrets
  // -------------------------------------------------------------------------

  it('fails when .env.example contains an OpenAI-style key', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'OPENAI_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
    expect(results[0]?.description).toContain('OPENAI_KEY');
    expect(results[0]?.location).toBe('.env.example');
  });

  it('fails when .env.example contains an AWS access key', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.description).toContain('AWS_ACCESS_KEY_ID');
  });

  it('fails when .env.example contains a GitHub PAT', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.description).toContain('GH_TOKEN');
  });

  it('fails when .env.example contains a long random string', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'SECRET=abcdef1234567890abcdef1234567890abcdef12345\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('fail');
  });

  it('reports all keys with real secrets in description', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      [
        'SAFE_KEY=your_api_key_here',
        'BAD_KEY1=sk-aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk',
        'BAD_KEY2=AKIAIOSFODNN7EXAMPLE',
        'ANOTHER_SAFE=',
      ].join('\n'),
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.description).toContain('BAD_KEY1');
    expect(results[0]?.description).toContain('BAD_KEY2');
    expect(results[0]?.description).not.toContain('SAFE_KEY');
    expect(results[0]?.description).not.toContain('ANOTHER_SAFE');
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it('prefers .env.example over .env.sample when both exist', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(join(tempDir, '.env.example'), 'KEY=\n');
    await writeFile(join(tempDir, '.env.sample'), 'KEY=\n');
    const results = await envExampleCheck(
      makeContext(['.gitignore', '.env.example', '.env.sample']),
    );

    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('.env.example');
  });

  it('does not flag short non-secret values', async () => {
    await writeFile(join(tempDir, '.gitignore'), '.env\n');
    await writeFile(
      join(tempDir, '.env.example'),
      'NODE_ENV=development\nPORT=3000\nDEBUG=true\nDB_HOST=localhost\n',
    );
    const results = await envExampleCheck(makeContext(['.gitignore', '.env.example']));

    expect(results[0]?.status).toBe('pass');
  });

  it('does not treat negation patterns as gitignoring .env', async () => {
    await writeFile(join(tempDir, '.gitignore'), '!.env\nnode_modules\n');
    const results = await envExampleCheck(makeContext(['.gitignore']));

    expect(results[0]?.status).toBe('skip');
  });
});
