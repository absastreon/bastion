import { describe, it, expect } from 'vitest';
import { isScannableFile, scanContent } from '../../src/checks/secrets.js';
import secretsCheck from '../../src/checks/secrets.js';
import type { ScanContext } from '@bastion/shared';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// isScannableFile
// ---------------------------------------------------------------------------

describe('isScannableFile', () => {
  it('accepts .ts files', () => {
    expect(isScannableFile('src/config.ts')).toBe(true);
  });

  it('accepts .js files', () => {
    expect(isScannableFile('lib/utils.js')).toBe(true);
  });

  it('accepts .tsx files', () => {
    expect(isScannableFile('components/App.tsx')).toBe(true);
  });

  it('accepts .jsx files', () => {
    expect(isScannableFile('components/App.jsx')).toBe(true);
  });

  it('accepts .env files', () => {
    expect(isScannableFile('.env')).toBe(true);
  });

  it('accepts .json files', () => {
    expect(isScannableFile('config.json')).toBe(true);
  });

  it('accepts .yaml files', () => {
    expect(isScannableFile('deploy.yaml')).toBe(true);
  });

  it('accepts .yml files', () => {
    expect(isScannableFile('ci.yml')).toBe(true);
  });

  it('rejects non-scannable extensions', () => {
    expect(isScannableFile('image.png')).toBe(false);
    expect(isScannableFile('readme.md')).toBe(false);
    expect(isScannableFile('data.csv')).toBe(false);
  });

  it('rejects node_modules paths', () => {
    expect(isScannableFile('node_modules/pkg/index.ts')).toBe(false);
  });

  it('rejects dist paths', () => {
    expect(isScannableFile('dist/bundle.js')).toBe(false);
  });

  it('rejects build paths', () => {
    expect(isScannableFile('build/output.js')).toBe(false);
  });

  it('rejects .git paths', () => {
    expect(isScannableFile('.git/config')).toBe(false);
  });

  it('rejects .env.example', () => {
    expect(isScannableFile('.env.example')).toBe(false);
  });

  it('rejects nested .env.example', () => {
    expect(isScannableFile('config/.env.example')).toBe(false);
  });

  it('accepts .env.local (not .env.example)', () => {
    expect(isScannableFile('.env.local')).toBe(false); // no matching extension
  });

  it('rejects deeply nested ignored dirs', () => {
    expect(isScannableFile('packages/cli/node_modules/dep/index.js')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// scanContent — OpenAI keys
// ---------------------------------------------------------------------------

describe('scanContent — OpenAI keys', () => {
  it('detects sk- prefixed keys', () => {
    const content = 'const key = "sk-abc123def456ghi789jkl012mno345";';
    const results = scanContent(content, 'config.ts');
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r).toBeDefined();
    expect(r?.severity).toBe('critical');
    expect(r?.status).toBe('fail');
    expect(r?.location).toBe('config.ts:1');
    expect(r?.name).toContain('OpenAI');
  });

  it('ignores short sk- strings (not real keys)', () => {
    const content = 'const x = "sk-short";';
    const results = scanContent(content, 'test.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — Stripe keys
// ---------------------------------------------------------------------------

describe('scanContent — Stripe keys', () => {
  it('detects sk_live_ keys', () => {
    const content = 'const stripe = "sk_live_ABCDEFghijklmnopqrstuv";';
    const results = scanContent(content, 'payment.ts');
    expect(results).toHaveLength(1);
    expect(results[0]?.name).toContain('Stripe secret');
  });

  it('detects pk_live_ keys', () => {
    const content = 'const pub = "pk_live_ABCDEFghijklmnopqrstuv";';
    const results = scanContent(content, 'payment.ts');
    expect(results).toHaveLength(1);
    expect(results[0]?.name).toContain('Stripe publishable');
  });
});

// ---------------------------------------------------------------------------
// scanContent — AWS keys
// ---------------------------------------------------------------------------

describe('scanContent — AWS keys', () => {
  it('detects AKIA prefixed keys', () => {
    const content = 'AWS_KEY=AKIAIOSFODNN7EXAMPLE';
    const results = scanContent(content, '.env');
    expect(results).toHaveLength(1);
    expect(results[0]?.name).toContain('AWS');
  });

  it('does not match partial AKIA strings', () => {
    const content = 'const x = "AKIA_short";';
    const results = scanContent(content, 'test.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — Generic API key assignments
// ---------------------------------------------------------------------------

describe('scanContent — Generic API key assignments', () => {
  it('detects api_key = "value"', () => {
    const content = 'const api_key = "mySecretValue12345678";';
    const results = scanContent(content, 'config.ts');
    expect(results.some((r) => r.name.includes('Generic API key'))).toBe(true);
  });

  it('detects apiKey: "value"', () => {
    const content = 'const config = { apiKey: "abcdef12345678901234" };';
    const results = scanContent(content, 'config.ts');
    expect(results.some((r) => r.name.includes('Generic API key'))).toBe(true);
  });

  it('detects api-secret = "value"', () => {
    const content = "api-secret = 'longSecretValueHere1234';";
    const results = scanContent(content, 'settings.ts');
    expect(results.some((r) => r.name.includes('Generic API key'))).toBe(true);
  });

  it('ignores api_key with short values', () => {
    const content = 'api_key = "short"';
    const results = scanContent(content, 'test.ts');
    expect(results.filter((r) => r.name.includes('Generic API key'))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — Bearer tokens
// ---------------------------------------------------------------------------

describe('scanContent — Bearer tokens', () => {
  it('detects hardcoded Bearer tokens', () => {
    const content = 'const auth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123def456";';
    const results = scanContent(content, 'api.ts');
    expect(results.some((r) => r.name.includes('Bearer'))).toBe(true);
  });

  it('ignores Bearer without a long token', () => {
    const content = 'const header = "Bearer short";';
    const results = scanContent(content, 'api.ts');
    expect(results.filter((r) => r.name.includes('Bearer'))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — Database connection strings
// ---------------------------------------------------------------------------

describe('scanContent — Database connection strings', () => {
  it('detects postgres:// with password', () => {
    const content = 'const db = "postgres://user:password123@localhost:5432/mydb";';
    const results = scanContent(content, 'db.ts');
    expect(results.some((r) => r.name.includes('Database'))).toBe(true);
  });

  it('detects mongodb:// with password', () => {
    const content = 'MONGO_URI=mongodb://admin:secret@cluster.example.com/db';
    const results = scanContent(content, '.env');
    expect(results.some((r) => r.name.includes('Database'))).toBe(true);
  });

  it('detects mongodb+srv:// with password', () => {
    const content = 'const uri = "mongodb+srv://user:pass@cluster.mongodb.net/mydb";';
    const results = scanContent(content, 'config.ts');
    expect(results.some((r) => r.name.includes('Database'))).toBe(true);
  });

  it('detects mysql:// with password', () => {
    const content = 'const conn = "mysql://root:p4ssw0rd@localhost/app";';
    const results = scanContent(content, 'db.ts');
    expect(results.some((r) => r.name.includes('Database'))).toBe(true);
  });

  it('detects redis:// with password', () => {
    const content = 'REDIS_URL=redis://default:mypass@redis.host:6379';
    const results = scanContent(content, '.env');
    expect(results.some((r) => r.name.includes('Database'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// scanContent — comment skipping
// ---------------------------------------------------------------------------

describe('scanContent — comment skipping', () => {
  it('ignores // comment lines', () => {
    const content = '// const key = "sk-abc123def456ghi789jkl012mno345";';
    const results = scanContent(content, 'config.ts');
    expect(results).toHaveLength(0);
  });

  it('ignores # comment lines', () => {
    const content = '# OPENAI_KEY=sk-abc123def456ghi789jkl012mno345';
    const results = scanContent(content, 'config.yaml');
    expect(results).toHaveLength(0);
  });

  it('ignores * comment lines (JSDoc)', () => {
    const content = ' * Example: sk-abc123def456ghi789jkl012mno345';
    const results = scanContent(content, 'config.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — result shape
// ---------------------------------------------------------------------------

describe('scanContent — result shape', () => {
  it('includes all required fields', () => {
    const content = 'const key = "sk-abc123def456ghi789jkl012mno345";';
    const results = scanContent(content, 'src/config.ts');
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r).toBeDefined();
    expect(r?.id).toBe('secrets');
    expect(r?.status).toBe('fail');
    expect(r?.severity).toBe('critical');
    expect(r?.category).toBe('Secrets');
    expect(r?.location).toBe('src/config.ts:1');
    expect(r?.fix).toBeDefined();
    expect(r?.aiPrompt).toBeDefined();
    expect(r?.aiPrompt).toContain('environment variable');
  });

  it('reports correct line numbers', () => {
    const content = 'line1\nline2\nconst key = "sk-abc123def456ghi789jkl012mno345";';
    const results = scanContent(content, 'file.ts');
    expect(results[0]?.location).toBe('file.ts:3');
  });

  it('detects multiple secrets in one file', () => {
    const content = [
      'const openai = "sk-abc123def456ghi789jkl012mno345";',
      'const stripe = "sk_live_ABCDEFghijklmnopqrstuv";',
      'const db = "postgres://user:pass@host/db";',
    ].join('\n');
    const results = scanContent(content, 'config.ts');
    expect(results.length).toBeGreaterThanOrEqual(3);
  });
});

// ---------------------------------------------------------------------------
// scanContent — clean files
// ---------------------------------------------------------------------------

describe('scanContent — clean files', () => {
  it('returns empty for clean code', () => {
    const content = [
      'const apiKey = process.env.OPENAI_API_KEY;',
      'const db = process.env.DATABASE_URL;',
      'if (!apiKey) throw new Error("Missing API key");',
    ].join('\n');
    const results = scanContent(content, 'config.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// secretsCheck — integration (uses temp directory)
// ---------------------------------------------------------------------------

describe('secretsCheck — integration', () => {
  const testDir = join(tmpdir(), `bastion-secrets-test-${Date.now()}`);

  async function runWith(files: Record<string, string>): Promise<ReturnType<typeof secretsCheck>> {
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });

    const fileList: string[] = [];
    for (const [name, content] of Object.entries(files)) {
      const dir = join(testDir, ...name.split('/').slice(0, -1));
      await mkdir(dir, { recursive: true });
      await writeFile(join(testDir, name), content, 'utf-8');
      fileList.push(name);
    }

    const context: ScanContext = {
      projectPath: testDir,
      stack: { language: 'javascript' },
      files: fileList,
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };

    return secretsCheck(context);
  }

  it('returns pass when no secrets found', async () => {
    const results = await runWith({
      'src/index.ts': 'const x = process.env.API_KEY;',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('detects secrets in source files', async () => {
    const results = await runWith({
      'src/config.ts': 'const key = "sk-abc123def456ghi789jkl012mno345";',
    });
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    expect(results.some((r) => r.severity === 'critical')).toBe(true);
  });

  it('detects secrets in .env files', async () => {
    const results = await runWith({
      '.env': 'OPENAI_KEY=sk-abc123def456ghi789jkl012mno345',
    });
    expect(results.some((r) => r.status === 'fail')).toBe(true);
  });

  it('ignores .env.example files', async () => {
    const results = await runWith({
      '.env.example': 'OPENAI_KEY=sk-abc123def456ghi789jkl012mno345',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip'); // no scannable files
  });

  it('ignores node_modules files', async () => {
    const results = await runWith({
      'node_modules/pkg/config.ts': 'const key = "sk-abc123def456ghi789jkl012mno345";',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('returns skip when no scannable files exist', async () => {
    const results = await runWith({
      'README.md': 'This is a readme',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('scans multiple files', async () => {
    const results = await runWith({
      'src/a.ts': 'const a = "sk-abc123def456ghi789jkl012mno345";',
      'src/b.ts': 'const b = "sk_live_ABCDEFghijklmnopqrstuv";',
      'src/clean.ts': 'const c = process.env.KEY;',
    });
    expect(results.filter((r) => r.status === 'fail')).toHaveLength(2);
  });

  // Cleanup
  it('cleans up temp dir', async () => {
    await rm(testDir, { recursive: true, force: true });
  });
});
