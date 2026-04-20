import { describe, it, expect, afterAll } from 'vitest';
import authCheck, {
  findCustomAuthDeps,
  scanFileForAuthPatterns,
  hasUserFacingFeatures,
  isLibraryOrCli,
  getRecommendedProvider,
} from '../../src/checks/auth.js';
import type { ScanContext, DetectedStack } from '@bastion/shared';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/test',
    stack: { language: 'typescript' },
    files: [],
    verbose: false,
    ...overrides,
  };
}

function makeStack(overrides: Partial<DetectedStack> = {}): DetectedStack {
  return {
    language: 'typescript',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// findCustomAuthDeps
// ---------------------------------------------------------------------------

describe('findCustomAuthDeps', () => {
  it('finds bcrypt', () => {
    expect(findCustomAuthDeps(['express', 'bcrypt', 'cors'])).toEqual(['bcrypt']);
  });

  it('finds bcryptjs', () => {
    expect(findCustomAuthDeps(['bcryptjs'])).toEqual(['bcryptjs']);
  });

  it('finds argon2', () => {
    expect(findCustomAuthDeps(['argon2'])).toEqual(['argon2']);
  });

  it('finds jsonwebtoken', () => {
    expect(findCustomAuthDeps(['jsonwebtoken'])).toEqual(['jsonwebtoken']);
  });

  it('finds multiple custom auth deps', () => {
    expect(findCustomAuthDeps(['bcrypt', 'jsonwebtoken', 'express'])).toEqual([
      'bcrypt',
      'jsonwebtoken',
    ]);
  });

  it('returns empty for no custom auth deps', () => {
    expect(findCustomAuthDeps(['express', 'react', 'next'])).toEqual([]);
  });

  it('returns empty for empty deps', () => {
    expect(findCustomAuthDeps([])).toEqual([]);
  });

  it('does not match auth provider packages', () => {
    expect(
      findCustomAuthDeps(['@clerk/nextjs', 'next-auth', 'passport']),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// scanFileForAuthPatterns
// ---------------------------------------------------------------------------

describe('scanFileForAuthPatterns', () => {
  it('detects crypto.scrypt usage', () => {
    const content = 'crypto.scrypt(password, salt, 64, (err, key) => {});';
    expect(scanFileForAuthPatterns(content)).toContain('crypto.scrypt');
  });

  it('detects crypto.scryptSync usage', () => {
    const content = 'const key = crypto.scryptSync(password, salt, 64);';
    expect(scanFileForAuthPatterns(content)).toContain('crypto.scrypt');
  });

  it('detects crypto.pbkdf2 usage', () => {
    const content = "crypto.pbkdf2(password, salt, 100000, 64, 'sha512', cb);";
    expect(scanFileForAuthPatterns(content)).toContain('crypto.pbkdf2');
  });

  it('detects crypto.pbkdf2Sync usage', () => {
    const content =
      "const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');";
    expect(scanFileForAuthPatterns(content)).toContain('crypto.pbkdf2');
  });

  it('detects jwt.sign calls', () => {
    const content =
      'const token = jwt.sign({ userId: user.id }, secret);';
    expect(scanFileForAuthPatterns(content)).toContain('jwt.sign');
  });

  it('detects jwt.verify calls', () => {
    const content = 'const decoded = jwt.verify(token, secret);';
    expect(scanFileForAuthPatterns(content)).toContain('jwt.verify');
  });

  it('detects hashPassword function', () => {
    const content =
      'async function hashPassword(password: string) { return hash(password); }';
    expect(scanFileForAuthPatterns(content)).toContain('password hashing');
  });

  it('detects comparePassword function', () => {
    const content = 'const isValid = await comparePassword(input, stored);';
    expect(scanFileForAuthPatterns(content)).toContain('password hashing');
  });

  it('detects verifyPassword function', () => {
    const content = 'export async function verifyPassword(password, hash) {}';
    expect(scanFileForAuthPatterns(content)).toContain('password hashing');
  });

  it('detects passwordHash assignment', () => {
    const content = 'const passwordHash = await hash(password);';
    expect(scanFileForAuthPatterns(content)).toContain('password hashing');
  });

  it('returns empty for clean code', () => {
    expect(
      scanFileForAuthPatterns('const x = 1;\nexport default x;'),
    ).toEqual([]);
  });

  it('returns empty for auth provider imports', () => {
    const content = "import { ClerkProvider } from '@clerk/nextjs';";
    expect(scanFileForAuthPatterns(content)).toEqual([]);
  });

  it('detects multiple patterns in one file', () => {
    const content = [
      'crypto.scrypt(password, salt, 64, cb);',
      'const token = jwt.sign(payload, secret);',
    ].join('\n');
    const result = scanFileForAuthPatterns(content);
    expect(result).toContain('crypto.scrypt');
    expect(result).toContain('jwt.sign');
  });
});

// ---------------------------------------------------------------------------
// hasUserFacingFeatures
// ---------------------------------------------------------------------------

describe('hasUserFacingFeatures', () => {
  it('returns true when framework is detected', () => {
    const ctx = makeContext({ stack: makeStack({ framework: 'next.js' }) });
    expect(hasUserFacingFeatures(ctx)).toBe(true);
  });

  it('returns true when api/ directory exists', () => {
    const ctx = makeContext({ files: ['src/api/users.ts'] });
    expect(hasUserFacingFeatures(ctx)).toBe(true);
  });

  it('returns true when routes/ directory exists', () => {
    const ctx = makeContext({ files: ['routes/index.ts'] });
    expect(hasUserFacingFeatures(ctx)).toBe(true);
  });

  it('returns true when pages/ directory exists', () => {
    const ctx = makeContext({ files: ['pages/index.tsx'] });
    expect(hasUserFacingFeatures(ctx)).toBe(true);
  });

  it('returns true when views/ directory exists', () => {
    const ctx = makeContext({ files: ['views/home.ejs'] });
    expect(hasUserFacingFeatures(ctx)).toBe(true);
  });

  it('returns false for library with no user-facing dirs', () => {
    const ctx = makeContext({ files: ['src/index.ts', 'src/utils.ts'] });
    expect(hasUserFacingFeatures(ctx)).toBe(false);
  });

  it('returns false for empty project', () => {
    expect(hasUserFacingFeatures(makeContext())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isLibraryOrCli
// ---------------------------------------------------------------------------

describe('isLibraryOrCli', () => {
  it('returns true when package.json has bin field', () => {
    const ctx = makeContext({ packageJson: { bin: './dist/cli.js' } });
    expect(isLibraryOrCli(ctx)).toBe(true);
  });

  it('returns true when has main but no framework', () => {
    const ctx = makeContext({ packageJson: { main: './dist/index.js' } });
    expect(isLibraryOrCli(ctx)).toBe(true);
  });

  it('returns true when has exports but no framework', () => {
    const ctx = makeContext({
      packageJson: { exports: { '.': './dist/index.js' } },
    });
    expect(isLibraryOrCli(ctx)).toBe(true);
  });

  it('returns false when has main WITH framework', () => {
    const ctx = makeContext({
      stack: makeStack({ framework: 'next.js' }),
      packageJson: { main: './dist/index.js' },
    });
    expect(isLibraryOrCli(ctx)).toBe(false);
  });

  it('returns false when no package.json', () => {
    expect(isLibraryOrCli(makeContext())).toBe(false);
  });

  it('returns false for bare package.json', () => {
    const ctx = makeContext({ packageJson: { name: 'my-app' } });
    expect(isLibraryOrCli(ctx)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getRecommendedProvider
// ---------------------------------------------------------------------------

describe('getRecommendedProvider', () => {
  it('recommends Clerk/NextAuth for Next.js', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'next.js' }));
    expect(result).toContain('Clerk');
    expect(result).toContain('NextAuth');
  });

  it('recommends Supabase Auth for Next.js + Supabase', () => {
    const result = getRecommendedProvider(
      makeStack({ framework: 'next.js', database: 'supabase' }),
    );
    expect(result).toBe('Supabase Auth');
  });

  it('recommends Auth0/Passport for Express', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'express' }));
    expect(result).toContain('Auth0');
    expect(result).toContain('Passport');
  });

  it('recommends Auth0/Passport for Fastify', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'fastify' }));
    expect(result).toContain('Auth0');
  });

  it('recommends Auth0/Passport for Hono', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'hono' }));
    expect(result).toContain('Auth0');
  });

  it('recommends Auth0/Lucia for Remix', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'remix' }));
    expect(result).toContain('Auth0');
    expect(result).toContain('Lucia');
  });

  it('recommends Lucia for SvelteKit', () => {
    const result = getRecommendedProvider(
      makeStack({ framework: 'sveltekit' }),
    );
    expect(result).toContain('Lucia');
  });

  it('recommends Auth0 for Nuxt', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'nuxt' }));
    expect(result).toContain('Auth0');
  });

  it('recommends Lucia for Astro', () => {
    const result = getRecommendedProvider(makeStack({ framework: 'astro' }));
    expect(result).toContain('Lucia');
  });

  it('recommends Clerk/Auth0 for unknown framework', () => {
    const result = getRecommendedProvider(makeStack());
    expect(result).toContain('Clerk');
    expect(result).toContain('Auth0');
  });
});

// ---------------------------------------------------------------------------
// authCheck — integration tests
// ---------------------------------------------------------------------------

describe('authCheck', () => {
  const testDir = join(tmpdir(), `bastion-auth-test-${Date.now()}`);

  async function runWith(
    opts: {
      stack?: Partial<DetectedStack>;
      packageJson?: Record<string, unknown>;
      sourceFiles?: Record<string, string>;
    } = {},
  ) {
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });

    const fileList: string[] = [];

    if (opts.sourceFiles) {
      for (const [name, content] of Object.entries(opts.sourceFiles)) {
        const dirParts = name.split('/').slice(0, -1);
        if (dirParts.length > 0) {
          await mkdir(join(testDir, ...dirParts), { recursive: true });
        }
        await writeFile(join(testDir, name), content, 'utf-8');
        fileList.push(name);
      }
    }

    const context: ScanContext = {
      projectPath: testDir,
      stack: { language: 'typescript', ...opts.stack },
      packageJson: opts.packageJson,
      files: fileList,
      verbose: false,
    };

    return authCheck(context);
  }

  afterAll(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  // --- Established provider ---

  it('returns pass when established auth provider is detected', async () => {
    const results = await runWith({
      stack: { framework: 'next.js', auth: 'clerk' },
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('Clerk');
  });

  it('includes correct provider name for each provider', async () => {
    const providers: [string, string][] = [
      ['clerk', 'Clerk'],
      ['auth0', 'Auth0'],
      ['next-auth', 'NextAuth.js'],
      ['supabase-auth', 'Supabase Auth'],
      ['passport', 'Passport.js'],
      ['lucia', 'Lucia'],
    ];

    for (const [key, name] of providers) {
      const results = await runWith({ stack: { auth: key } });
      expect(results[0]?.description).toContain(name);
    }
  });

  it('handles unknown auth provider gracefully', async () => {
    const results = await runWith({ stack: { auth: 'firebase-auth' } });
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('firebase-auth');
  });

  it('includes aiPrompt with provider and stack in pass result', async () => {
    const results = await runWith({
      stack: { framework: 'next.js', auth: 'clerk' },
    });
    expect(results[0]?.aiPrompt).toBeDefined();
    expect(results[0]?.aiPrompt).toContain('Clerk');
    expect(results[0]?.aiPrompt).toContain('next.js');
  });

  // --- Custom auth via dependencies ---

  it('returns warn when bcrypt dependency found', async () => {
    const results = await runWith({
      stack: { framework: 'express', dependencies: ['express', 'bcrypt'] },
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('warn');
    expect(results[0]?.severity).toBe('medium');
    expect(results[0]?.description).toContain('bcrypt');
  });

  it('returns warn when jsonwebtoken dependency found', async () => {
    const results = await runWith({
      stack: { dependencies: ['jsonwebtoken'] },
    });
    expect(results[0]?.status).toBe('warn');
    expect(results[0]?.description).toContain('jsonwebtoken');
  });

  it('includes recommended provider in fix for custom auth deps', async () => {
    const results = await runWith({
      stack: { framework: 'next.js', dependencies: ['bcrypt'] },
    });
    expect(results[0]?.fix).toContain('Clerk');
  });

  it('includes aiPrompt in warn result for custom auth deps', async () => {
    const results = await runWith({
      stack: { framework: 'express', dependencies: ['bcrypt'] },
    });
    expect(results[0]?.aiPrompt).toBeDefined();
    expect(results[0]?.aiPrompt).toContain('bcrypt');
    expect(results[0]?.aiPrompt).toContain('Auth0');
  });

  // --- Custom auth via file scan ---

  it('returns warn when crypto.scrypt found in source files', async () => {
    const results = await runWith({
      sourceFiles: {
        'src/auth.ts':
          "import crypto from 'node:crypto';\ncrypto.scrypt(password, salt, 64, cb);",
      },
    });
    expect(results[0]?.status).toBe('warn');
    expect(results[0]?.description).toContain('crypto.scrypt');
  });

  it('returns warn when jwt.sign found in source files', async () => {
    const results = await runWith({
      sourceFiles: {
        'src/token.ts': 'const token = jwt.sign({ id: 1 }, secret);',
      },
    });
    expect(results[0]?.status).toBe('warn');
    expect(results[0]?.description).toContain('jwt.sign');
  });

  it('deduplicates patterns found across multiple files', async () => {
    const results = await runWith({
      sourceFiles: {
        'src/auth.ts': 'crypto.scrypt(password, salt, 64, cb);',
        'src/utils.ts': 'crypto.scrypt(pw, s, 64, callback);',
      },
    });
    expect(results[0]?.status).toBe('warn');
    const desc = results[0]?.description ?? '';
    const matches = desc.match(/crypto\.scrypt/g);
    expect(matches).toHaveLength(1);
  });

  // --- No auth + user-facing features ---

  it('returns fail when no auth and framework detected', async () => {
    const results = await runWith({
      stack: { framework: 'next.js', dependencies: ['next', 'react'] },
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
  });

  it('returns fail when no auth and API routes exist', async () => {
    const results = await runWith({
      sourceFiles: {
        'src/api/users.ts': 'export function getUsers() { return []; }',
      },
    });
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
  });

  it('includes recommended provider in fix for no auth', async () => {
    const results = await runWith({
      stack: { framework: 'express', dependencies: ['express'] },
    });
    expect(results[0]?.fix).toContain('Auth0');
  });

  it('includes aiPrompt in fail result', async () => {
    const results = await runWith({
      stack: { framework: 'express', dependencies: ['express'] },
    });
    expect(results[0]?.aiPrompt).toBeDefined();
    expect(results[0]?.aiPrompt).toContain('Auth0');
    expect(results[0]?.aiPrompt).toContain('authentication');
  });

  // --- Library/CLI skip ---

  it('returns skip for CLI tool (has bin field)', async () => {
    const results = await runWith({
      packageJson: { name: 'my-cli', bin: './dist/cli.js' },
    });
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('library or CLI');
  });

  it('returns skip for library (has main, no framework)', async () => {
    const results = await runWith({
      packageJson: { name: 'my-lib', main: './dist/index.js' },
    });
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('library or CLI');
  });

  // --- No user-facing features skip ---

  it('returns skip when no user-facing features detected', async () => {
    const results = await runWith({
      sourceFiles: {
        'src/index.ts': 'export const x = 1;',
        'src/utils.ts': 'export const add = (a: number, b: number) => a + b;',
      },
    });
    expect(results[0]?.status).toBe('skip');
    expect(results[0]?.description).toContain('No user-facing features');
  });

  // --- Result shape ---

  it('sets id and category on all results', async () => {
    const results = await runWith({ stack: { auth: 'clerk' } });
    expect(results[0]?.id).toBe('auth');
    expect(results[0]?.category).toBe('Authentication');
  });
});
