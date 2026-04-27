import { describe, it, expect } from 'vitest';
import { isScannableFile, scanContent, buildAiPrompt } from '../../src/checks/cors.js';
import corsCheck from '../../src/checks/cors.js';
import type { ScanContext, DetectedStack } from 'bastion-shared';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

/** Helper: create a minimal stack for testing */
function makeStack(framework?: string): DetectedStack {
  return { language: 'typescript', framework };
}

// ---------------------------------------------------------------------------
// isScannableFile
// ---------------------------------------------------------------------------

describe('isScannableFile', () => {
  it('accepts .ts files', () => {
    expect(isScannableFile('src/server.ts')).toBe(true);
  });

  it('accepts .js files', () => {
    expect(isScannableFile('lib/cors.js')).toBe(true);
  });

  it('accepts .tsx files', () => {
    expect(isScannableFile('app/api/route.tsx')).toBe(true);
  });

  it('accepts .jsx files', () => {
    expect(isScannableFile('pages/api/hello.jsx')).toBe(true);
  });

  it('accepts .mjs files', () => {
    expect(isScannableFile('next.config.mjs')).toBe(true);
  });

  it('accepts .cjs files', () => {
    expect(isScannableFile('server.cjs')).toBe(true);
  });

  it('rejects non-source extensions', () => {
    expect(isScannableFile('readme.md')).toBe(false);
    expect(isScannableFile('data.json')).toBe(false);
    expect(isScannableFile('image.png')).toBe(false);
    expect(isScannableFile('style.css')).toBe(false);
  });

  it('rejects node_modules paths', () => {
    expect(isScannableFile('node_modules/cors/index.js')).toBe(false);
  });

  it('rejects dist paths', () => {
    expect(isScannableFile('dist/server.js')).toBe(false);
  });

  it('rejects build paths', () => {
    expect(isScannableFile('build/index.js')).toBe(false);
  });

  it('rejects .git paths', () => {
    expect(isScannableFile('.git/hooks/pre-commit.js')).toBe(false);
  });

  it('rejects .next paths', () => {
    expect(isScannableFile('.next/server/app.js')).toBe(false);
  });

  it('rejects deeply nested ignored dirs', () => {
    expect(isScannableFile('packages/api/node_modules/cors/index.js')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// scanContent — wildcard origin headers (Express res.setHeader / res.header)
// ---------------------------------------------------------------------------

describe('scanContent — wildcard origin headers', () => {
  const stack = makeStack('express');

  it('detects res.setHeader with wildcard', () => {
    const content = "res.setHeader('Access-Control-Allow-Origin', '*');";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.location).toBe('server.ts:1');
  });

  it('detects res.header with wildcard', () => {
    const content = 'res.header("Access-Control-Allow-Origin", "*");';
    const results = scanContent(content, 'api.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects headers.set with wildcard (Next.js / Web API)', () => {
    const content = "headers.set('Access-Control-Allow-Origin', '*');";
    const results = scanContent(content, 'route.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects headers.append with wildcard', () => {
    const content = "headers.append('Access-Control-Allow-Origin', '*');";
    const results = scanContent(content, 'route.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects object literal wildcard (Next.js response headers)', () => {
    const content = "const headers = { 'Access-Control-Allow-Origin': '*' };";
    const results = scanContent(content, 'api.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects double-quoted object literal wildcard', () => {
    const content = 'return new Response(body, { headers: { "Access-Control-Allow-Origin": "*" } });';
    const results = scanContent(content, 'route.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('ignores restrictive origin header', () => {
    const content = "res.setHeader('Access-Control-Allow-Origin', 'https://example.com');";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('ignores null origin header', () => {
    const content = "res.setHeader('Access-Control-Allow-Origin', 'null');";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — cors() with no configuration
// ---------------------------------------------------------------------------

describe('scanContent — cors() with no configuration', () => {
  const stack = makeStack('express');

  it('detects bare cors() call', () => {
    const content = 'app.use(cors());';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
    expect(results[0]?.status).toBe('fail');
  });

  it('detects standalone cors() assignment', () => {
    const content = 'const middleware = cors();';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('detects cors( ) with whitespace', () => {
    const content = 'app.use(cors( ));';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('does not match cors(options)', () => {
    const content = 'app.use(cors(corsOptions));';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('does not match cors({ origin: ... })', () => {
    const content = "app.use(cors({ origin: 'https://example.com' }));";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('does not match require("cors")', () => {
    const content = "const cors = require('cors');";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — wildcard origin in CORS config (Express/Fastify)
// ---------------------------------------------------------------------------

describe('scanContent — wildcard origin in config', () => {
  const stack = makeStack('express');

  it("detects origin: '*' with single quotes", () => {
    const content = "app.use(cors({ origin: '*' }));";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects origin: "*" with double quotes', () => {
    const content = 'app.use(cors({ origin: "*" }));';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects Fastify CORS plugin wildcard', () => {
    const content = "fastify.register(cors, { origin: '*' });";
    const results = scanContent(content, 'server.ts', makeStack('fastify'));
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('ignores origin: true (Fastify reflect mode)', () => {
    const content = 'fastify.register(cors, { origin: true });';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('ignores specific origin string', () => {
    const content = "app.use(cors({ origin: 'https://example.com' }));";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('ignores origin with variable reference', () => {
    const content = 'app.use(cors({ origin: allowedOrigins }));';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — credentials escalation
// ---------------------------------------------------------------------------

describe('scanContent — credentials escalation', () => {
  const stack = makeStack('express');

  it('escalates wildcard header to critical when credentials: true exists', () => {
    const content = [
      "res.setHeader('Access-Control-Allow-Origin', '*');",
      'const opts = { credentials: true };',
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('critical');
    expect(results[0]?.name).toContain('Credentials');
  });

  it('escalates wildcard config to critical when credentials: true exists', () => {
    const content = "app.use(cors({ origin: '*', credentials: true }));";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('critical');
  });

  it('includes credentials warning in description when escalated', () => {
    const content = "app.use(cors({ origin: '*', credentials: true }));";
    const results = scanContent(content, 'server.ts', stack);
    expect(results[0]?.description).toContain('credentials');
  });

  it('does not escalate bare cors() — stays medium', () => {
    const content = [
      'app.use(cors());',
      'const opts = { credentials: true };',
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('does not escalate when credentials: true is in a comment', () => {
    const content = [
      "// credentials: true is dangerous with wildcards",
      "res.setHeader('Access-Control-Allow-Origin', '*');",
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// scanContent — comment skipping
// ---------------------------------------------------------------------------

describe('scanContent — comment skipping', () => {
  const stack = makeStack();

  it('ignores // comment lines', () => {
    const content = "// res.setHeader('Access-Control-Allow-Origin', '*');";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('ignores * comment lines (JSDoc)', () => {
    const content = " * cors() example with wildcard origin: '*'";
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('ignores # comment lines', () => {
    const content = "# origin: '*'";
    const results = scanContent(content, 'config.ts', stack);
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — clean files
// ---------------------------------------------------------------------------

describe('scanContent — clean files', () => {
  const stack = makeStack('express');

  it('returns empty for restrictive CORS config', () => {
    const content = [
      "import cors from 'cors';",
      "app.use(cors({ origin: 'https://myapp.com' }));",
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('returns empty for code with no CORS', () => {
    const content = [
      "import express from 'express';",
      'const app = express();',
      "app.get('/', (req, res) => res.json({ ok: true }));",
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });

  it('returns empty for dynamic origin function', () => {
    const content = 'app.use(cors({ origin: (origin, callback) => callback(null, isAllowed(origin)) }));';
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanContent — result shape
// ---------------------------------------------------------------------------

describe('scanContent — result shape', () => {
  const stack = makeStack('express');

  it('includes all required fields for wildcard finding', () => {
    const content = "app.use(cors({ origin: '*' }));";
    const results = scanContent(content, 'src/server.ts', stack);
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r).toBeDefined();
    expect(r?.id).toBe('cors');
    expect(r?.status).toBe('fail');
    expect(r?.severity).toBe('high');
    expect(r?.category).toBe('CORS');
    expect(r?.location).toBe('src/server.ts:1');
    expect(r?.fix).toBeDefined();
    expect(r?.aiPrompt).toBeDefined();
    expect(r?.aiPrompt).toContain('Express');
  });

  it('includes all required fields for bare cors() finding', () => {
    const content = 'app.use(cors());';
    const results = scanContent(content, 'src/app.ts', stack);
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r).toBeDefined();
    expect(r?.id).toBe('cors');
    expect(r?.status).toBe('fail');
    expect(r?.severity).toBe('medium');
    expect(r?.fix).toContain('origin');
  });

  it('reports correct line numbers', () => {
    const content = "line1\nline2\napp.use(cors({ origin: '*' }));";
    const results = scanContent(content, 'file.ts', stack);
    expect(results[0]?.location).toBe('file.ts:3');
  });

  it('detects multiple issues in one file', () => {
    const content = [
      'app.use(cors());',
      "res.setHeader('Access-Control-Allow-Origin', '*');",
    ].join('\n');
    const results = scanContent(content, 'server.ts', stack);
    expect(results).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// buildAiPrompt
// ---------------------------------------------------------------------------

describe('buildAiPrompt', () => {
  it('returns Express-specific prompt', () => {
    const prompt = buildAiPrompt(makeStack('express'));
    expect(prompt).toContain('Express');
    expect(prompt).toContain('cors({');
  });

  it('returns Next.js-specific prompt', () => {
    const prompt = buildAiPrompt(makeStack('next.js'));
    expect(prompt).toContain('Next.js');
    expect(prompt).toContain('API route');
  });

  it('returns Fastify-specific prompt', () => {
    const prompt = buildAiPrompt(makeStack('fastify'));
    expect(prompt).toContain('Fastify');
    expect(prompt).toContain('@fastify/cors');
  });

  it('returns generic prompt for unknown framework', () => {
    const prompt = buildAiPrompt(makeStack());
    expect(prompt).toContain('CORS');
    expect(prompt).toContain('Access-Control-Allow-Origin');
  });

  it('returns generic prompt for non-covered framework', () => {
    const prompt = buildAiPrompt(makeStack('remix'));
    expect(prompt).toContain('CORS');
    expect(prompt).not.toContain('Express');
  });
});

// ---------------------------------------------------------------------------
// corsCheck — integration (uses temp directory)
// ---------------------------------------------------------------------------

describe('corsCheck — integration', () => {
  const testDir = join(tmpdir(), `bastion-cors-test-${Date.now()}`);

  async function runWith(
    files: Record<string, string>,
    framework?: string,
  ): Promise<ReturnType<typeof corsCheck>> {
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
      stack: makeStack(framework),
      files: fileList,
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };

    return corsCheck(context);
  }

  it('returns pass when no CORS issues found', async () => {
    const results = await runWith({
      'src/server.ts': "app.use(cors({ origin: 'https://example.com' }));",
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('detects wildcard origin in source files', async () => {
    const results = await runWith(
      { 'src/server.ts': "app.use(cors({ origin: '*' }));" },
      'express',
    );
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    expect(results.some((r) => r.severity === 'high')).toBe(true);
  });

  it('detects bare cors() call', async () => {
    const results = await runWith(
      { 'src/app.ts': 'app.use(cors());' },
      'express',
    );
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    expect(results.some((r) => r.severity === 'medium')).toBe(true);
  });

  it('detects credentials with wildcard as critical', async () => {
    const results = await runWith(
      { 'src/server.ts': "app.use(cors({ origin: '*', credentials: true }));" },
      'express',
    );
    expect(results.some((r) => r.severity === 'critical')).toBe(true);
  });

  it('returns skip when no scannable files exist', async () => {
    const results = await runWith({ 'README.md': '# Hello' });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('ignores node_modules files', async () => {
    const results = await runWith({
      'node_modules/cors/index.js': "module.exports = cors({ origin: '*' });",
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('scans multiple files and reports all issues', async () => {
    const results = await runWith({
      'src/a.ts': 'app.use(cors());',
      'src/b.ts': "res.setHeader('Access-Control-Allow-Origin', '*');",
      'src/clean.ts': "app.use(cors({ origin: 'https://example.com' }));",
    });
    expect(results.filter((r) => r.status === 'fail')).toHaveLength(2);
  });

  it('uses stack-specific AI prompt', async () => {
    const results = await runWith(
      { 'src/server.ts': 'app.use(cors());' },
      'fastify',
    );
    const failing = results.find((r) => r.status === 'fail');
    expect(failing?.aiPrompt).toContain('Fastify');
  });

  it('detects Next.js response header pattern', async () => {
    const results = await runWith(
      {
        'app/api/route.ts':
          "return new Response(body, { headers: { 'Access-Control-Allow-Origin': '*' } });",
      },
      'next.js',
    );
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    const failing = results.find((r) => r.status === 'fail');
    expect(failing?.aiPrompt).toContain('Next.js');
  });

  // Cleanup
  it('cleans up temp dir', async () => {
    await rm(testDir, { recursive: true, force: true });
  });
});
