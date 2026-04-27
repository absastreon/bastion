import { describe, it, expect, afterEach } from 'vitest';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ConfigSnippet, DetectedStack } from 'bastion-shared';
import {
  generateConfigs,
  formatConfigSnippet,
  formatConfigOutput,
  writeConfigFiles,
} from '../../src/generators/config.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeStack(overrides: Partial<DetectedStack> = {}): DetectedStack {
  return {
    language: 'typescript',
    ...overrides,
  };
}

function snippetNames(snippets: readonly ConfigSnippet[]): readonly string[] {
  return snippets.map((s) => s.name);
}

/** Find a snippet by name or filename, failing the test if not found */
function findSnippet(
  snippets: readonly ConfigSnippet[],
  match: { name?: string; filename?: string },
): ConfigSnippet {
  const result = snippets.find(
    (s) =>
      (match.name === undefined || s.name === match.name) &&
      (match.filename === undefined || s.filename === match.filename),
  );
  expect(result, `Expected snippet matching ${JSON.stringify(match)}`).toBeDefined();
  // After the expect above, TypeScript still sees `result` as possibly undefined.
  // We use a type guard cast that's safe because the assertion above would have
  // already failed the test if result was undefined.
  return result as ConfigSnippet;
}

// ---------------------------------------------------------------------------
// generateConfigs — generic (always present)
// ---------------------------------------------------------------------------

describe('generateConfigs', () => {
  describe('generic configs', () => {
    it('always includes .gitignore additions', () => {
      const snippets = generateConfigs(makeStack());
      const names = snippetNames(snippets);
      expect(names).toContain('.gitignore Security Additions');
    });

    it('always includes .env.example template', () => {
      const snippets = generateConfigs(makeStack());
      const names = snippetNames(snippets);
      expect(names).toContain('.env.example Template');
    });

    it('returns generic configs when no framework detected', () => {
      const snippets = generateConfigs(makeStack({ framework: undefined }));
      expect(snippets).toHaveLength(2);
    });

    it('returns generic configs when unknown framework detected', () => {
      const snippets = generateConfigs(makeStack({ framework: 'hono' }));
      expect(snippets).toHaveLength(2);
    });

    it('.gitignore snippet includes .env and node_modules patterns', () => {
      const snippets = generateConfigs(makeStack());
      const gitignore = findSnippet(snippets, { filename: '.gitignore-additions' });
      expect(gitignore.code).toContain('.env');
      expect(gitignore.code).toContain('node_modules/');
      expect(gitignore.code).toContain('*.pem');
      expect(gitignore.code).toContain('*.key');
    });

    it('.env.example snippet includes placeholder variables', () => {
      const snippets = generateConfigs(makeStack());
      const env = findSnippet(snippets, { filename: '.env.example' });
      expect(env.code).toContain('NODE_ENV');
      expect(env.code).toContain('PORT');
      expect(env.code).toContain('NEVER commit .env');
    });
  });

  // ---------------------------------------------------------------------------
  // Express
  // ---------------------------------------------------------------------------

  describe('Express stack', () => {
    const expressStack = makeStack({ framework: 'express' });

    it('generates 5 snippets (3 express + 2 generic)', () => {
      const snippets = generateConfigs(expressStack);
      expect(snippets).toHaveLength(5);
    });

    it('includes helmet.js config', () => {
      const snippets = generateConfigs(expressStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Helmet.js Security Headers');
    });

    it('includes CORS config', () => {
      const snippets = generateConfigs(expressStack);
      const names = snippetNames(snippets);
      expect(names).toContain('CORS Configuration');
    });

    it('includes rate limiter config', () => {
      const snippets = generateConfigs(expressStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Rate Limiter Setup');
    });

    it('helmet snippet imports from helmet', () => {
      const snippets = generateConfigs(expressStack);
      const helmet = findSnippet(snippets, { name: 'Helmet.js Security Headers' });
      expect(helmet.code).toContain("import helmet from 'helmet'");
      expect(helmet.code).toContain('contentSecurityPolicy');
      expect(helmet.code).toContain('hsts');
    });

    it('CORS snippet uses explicit origin list', () => {
      const snippets = generateConfigs(expressStack);
      const cors = findSnippet(snippets, { name: 'CORS Configuration' });
      expect(cors.code).toContain('ALLOWED_ORIGINS');
      expect(cors.code).toContain('credentials: true');
      // Config uses a callback function for origin, not a wildcard string
      expect(cors.code).toContain('origin: (origin, callback)');
    });

    it('rate limiter snippet includes auth limiter', () => {
      const snippets = generateConfigs(expressStack);
      const rl = findSnippet(snippets, { name: 'Rate Limiter Setup' });
      expect(rl.code).toContain('apiLimiter');
      expect(rl.code).toContain('authLimiter');
      expect(rl.code).toContain('Too many requests');
    });

    it('framework-specific snippets come before generic ones', () => {
      const snippets = generateConfigs(expressStack);
      const helmetIdx = snippets.findIndex((s) => s.name === 'Helmet.js Security Headers');
      const gitignoreIdx = snippets.findIndex((s) => s.name === '.gitignore Security Additions');
      expect(helmetIdx).toBeLessThan(gitignoreIdx);
    });
  });

  // ---------------------------------------------------------------------------
  // Next.js
  // ---------------------------------------------------------------------------

  describe('Next.js stack', () => {
    const nextStack = makeStack({ framework: 'next.js' });

    it('generates 4 snippets (2 next.js + 2 generic)', () => {
      const snippets = generateConfigs(nextStack);
      expect(snippets).toHaveLength(4);
    });

    it('includes security headers config', () => {
      const snippets = generateConfigs(nextStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Next.js Security Headers');
    });

    it('includes rate limiting middleware', () => {
      const snippets = generateConfigs(nextStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Next.js Rate Limiting Middleware');
    });

    it('security headers snippet includes CSP and HSTS', () => {
      const snippets = generateConfigs(nextStack);
      const headers = findSnippet(snippets, { name: 'Next.js Security Headers' });
      expect(headers.code).toContain('Content-Security-Policy');
      expect(headers.code).toContain('Strict-Transport-Security');
      expect(headers.code).toContain('X-Frame-Options');
    });

    it('rate limit middleware uses NextResponse', () => {
      const snippets = generateConfigs(nextStack);
      const rl = findSnippet(snippets, { name: 'Next.js Rate Limiting Middleware' });
      expect(rl.code).toContain('NextResponse');
      expect(rl.code).toContain('middleware');
      expect(rl.language).toBe('typescript');
    });

    it('rate limit middleware mentions @upstash/ratelimit for production', () => {
      const snippets = generateConfigs(nextStack);
      const rl = findSnippet(snippets, { name: 'Next.js Rate Limiting Middleware' });
      expect(rl.code).toContain('@upstash/ratelimit');
    });
  });

  // ---------------------------------------------------------------------------
  // Fastify
  // ---------------------------------------------------------------------------

  describe('Fastify stack', () => {
    const fastifyStack = makeStack({ framework: 'fastify' });

    it('generates 5 snippets (3 fastify + 2 generic)', () => {
      const snippets = generateConfigs(fastifyStack);
      expect(snippets).toHaveLength(5);
    });

    it('includes @fastify/helmet config', () => {
      const snippets = generateConfigs(fastifyStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Fastify Helmet Plugin');
    });

    it('includes @fastify/cors config', () => {
      const snippets = generateConfigs(fastifyStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Fastify CORS Plugin');
    });

    it('includes @fastify/rate-limit config', () => {
      const snippets = generateConfigs(fastifyStack);
      const names = snippetNames(snippets);
      expect(names).toContain('Fastify Rate Limit Plugin');
    });

    it('helmet snippet uses @fastify/helmet import', () => {
      const snippets = generateConfigs(fastifyStack);
      const helmet = findSnippet(snippets, { name: 'Fastify Helmet Plugin' });
      expect(helmet.code).toContain("from '@fastify/helmet'");
      expect(helmet.code).toContain('fastify.register');
    });

    it('CORS snippet uses @fastify/cors import', () => {
      const snippets = generateConfigs(fastifyStack);
      const cors = findSnippet(snippets, { name: 'Fastify CORS Plugin' });
      expect(cors.code).toContain("from '@fastify/cors'");
      expect(cors.code).toContain('ALLOWED_ORIGINS');
    });

    it('rate limit snippet uses @fastify/rate-limit import', () => {
      const snippets = generateConfigs(fastifyStack);
      const rl = findSnippet(snippets, { name: 'Fastify Rate Limit Plugin' });
      expect(rl.code).toContain("from '@fastify/rate-limit'");
      expect(rl.code).toContain('429');
    });
  });

  // ---------------------------------------------------------------------------
  // ConfigSnippet shape
  // ---------------------------------------------------------------------------

  describe('snippet shape', () => {
    it('every snippet has all required fields', () => {
      const stacks: DetectedStack[] = [
        makeStack({ framework: 'express' }),
        makeStack({ framework: 'next.js' }),
        makeStack({ framework: 'fastify' }),
        makeStack(),
      ];

      for (const stack of stacks) {
        for (const snippet of generateConfigs(stack)) {
          expect(snippet.name).toBeTruthy();
          expect(snippet.filename).toBeTruthy();
          expect(snippet.language).toBeTruthy();
          expect(snippet.code).toBeTruthy();
          expect(snippet.description).toBeTruthy();
        }
      }
    });

    it('no duplicate filenames within a stack', () => {
      const stacks: DetectedStack[] = [
        makeStack({ framework: 'express' }),
        makeStack({ framework: 'next.js' }),
        makeStack({ framework: 'fastify' }),
        makeStack(),
      ];

      for (const stack of stacks) {
        const filenames = generateConfigs(stack).map((s) => s.filename);
        expect(new Set(filenames).size).toBe(filenames.length);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// formatConfigSnippet
// ---------------------------------------------------------------------------

describe('formatConfigSnippet', () => {
  const snippet: ConfigSnippet = {
    name: 'Test Config',
    filename: 'test.js',
    language: 'javascript',
    code: 'console.log("hello");',
    description: 'A test config snippet',
  };

  it('includes snippet name', () => {
    const output = formatConfigSnippet(snippet);
    expect(output).toContain('Test Config');
  });

  it('includes snippet description', () => {
    const output = formatConfigSnippet(snippet);
    expect(output).toContain('A test config snippet');
  });

  it('includes filename', () => {
    const output = formatConfigSnippet(snippet);
    expect(output).toContain('test.js');
  });

  it('wraps code in fenced code block with language', () => {
    const output = formatConfigSnippet(snippet);
    expect(output).toContain('```javascript');
    expect(output).toContain('console.log("hello");');
    expect(output).toContain('```');
  });
});

// ---------------------------------------------------------------------------
// formatConfigOutput
// ---------------------------------------------------------------------------

describe('formatConfigOutput', () => {
  it('returns message when no snippets', () => {
    const output = formatConfigOutput([]);
    expect(output).toContain('No configuration snippets');
  });

  it('includes snippet count', () => {
    const snippets = generateConfigs(makeStack({ framework: 'express' }));
    const output = formatConfigOutput(snippets);
    expect(output).toContain('5 snippets');
  });

  it('includes all snippet names', () => {
    const snippets = generateConfigs(makeStack({ framework: 'express' }));
    const output = formatConfigOutput(snippets);
    expect(output).toContain('Helmet.js Security Headers');
    expect(output).toContain('CORS Configuration');
    expect(output).toContain('Rate Limiter Setup');
    expect(output).toContain('.gitignore Security Additions');
    expect(output).toContain('.env.example Template');
  });

  it('uses singular for 1 snippet', () => {
    const output = formatConfigOutput([{
      name: 'Test',
      filename: 'test.js',
      language: 'javascript',
      code: '// test',
      description: 'test',
    }]);
    expect(output).toContain('1 snippet for');
  });
});

// ---------------------------------------------------------------------------
// writeConfigFiles
// ---------------------------------------------------------------------------

describe('writeConfigFiles', () => {
  const tmpDir = join(tmpdir(), `bastion-config-test-${process.pid}`);

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('creates the output directory if it does not exist', async () => {
    const outDir = join(tmpDir, 'configs');
    const snippets = generateConfigs(makeStack());
    await writeConfigFiles(snippets, outDir);

    const content = await readFile(join(outDir, '.gitignore-additions'), 'utf-8');
    expect(content).toContain('.env');
  });

  it('writes all snippets as individual files', async () => {
    const outDir = join(tmpDir, 'express-configs');
    const snippets = generateConfigs(makeStack({ framework: 'express' }));
    const paths = await writeConfigFiles(snippets, outDir);

    expect(paths).toHaveLength(5);
    for (const p of paths) {
      const content = await readFile(p, 'utf-8');
      expect(content.length).toBeGreaterThan(0);
    }
  });

  it('returns correct file paths', async () => {
    const outDir = join(tmpDir, 'paths-test');
    const snippets = generateConfigs(makeStack());
    const paths = await writeConfigFiles(snippets, outDir);

    expect(paths).toContain(join(outDir, '.gitignore-additions'));
    expect(paths).toContain(join(outDir, '.env.example'));
  });

  it('file content matches snippet code with trailing newline', async () => {
    const outDir = join(tmpDir, 'content-test');
    const snippets = generateConfigs(makeStack({ framework: 'next.js' }));
    await writeConfigFiles(snippets, outDir);

    for (const snippet of snippets) {
      const content = await readFile(join(outDir, snippet.filename), 'utf-8');
      expect(content).toBe(snippet.code + '\n');
    }
  });

  it('handles empty snippets array', async () => {
    const outDir = join(tmpDir, 'empty-test');
    const paths = await writeConfigFiles([], outDir);
    expect(paths).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// CLI flag tests (option parsing)
// ---------------------------------------------------------------------------

describe('CLI --generate-configs flag', () => {
  async function parseScanOptions(args: string[]): Promise<Record<string, unknown>> {
    const { createProgram } = await import('../../src/cli.js');
    const program = createProgram('0.0.0-test');
    program.exitOverride();

    let captured: Record<string, unknown> = {};
    const scan = program.commands.find((c) => c.name() === 'scan');
    if (!scan) throw new Error('scan command not found');
    scan.action((opts: Record<string, unknown>) => {
      captured = opts;
    });

    program.parse(args, { from: 'user' });
    return captured;
  }

  it('defaults --generate-configs to false', async () => {
    const opts = await parseScanOptions(['scan']);
    expect(opts['generateConfigs']).toBe(false);
  });

  it('parses --generate-configs flag', async () => {
    const opts = await parseScanOptions(['scan', '--generate-configs']);
    expect(opts['generateConfigs']).toBe(true);
  });

  it('parses --output-dir option', async () => {
    const opts = await parseScanOptions(['scan', '--output-dir', './configs']);
    expect(opts['outputDir']).toBe('./configs');
  });

  it('parses both flags together', async () => {
    const opts = await parseScanOptions(['scan', '--generate-configs', '--output-dir', '/tmp/out']);
    expect(opts['generateConfigs']).toBe(true);
    expect(opts['outputDir']).toBe('/tmp/out');
  });
});
