import { describe, it, expect } from 'vitest';
import {
  findRateLimitDependency,
  hasRateLimitPattern,
  getRecommendation,
  isScannableFile,
  buildAiPrompt,
  RATE_LIMIT_PACKAGES,
} from '../../src/checks/rate-limit.js';
import rateLimitCheck from '../../src/checks/rate-limit.js';
import type { ScanContext, DetectedStack } from '@bastion/shared';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// findRateLimitDependency
// ---------------------------------------------------------------------------

describe('findRateLimitDependency', () => {
  it('finds express-rate-limit', () => {
    expect(findRateLimitDependency(['express', 'express-rate-limit'])).toBe(
      'express-rate-limit',
    );
  });

  it('finds @upstash/ratelimit', () => {
    expect(findRateLimitDependency(['next', '@upstash/ratelimit'])).toBe(
      '@upstash/ratelimit',
    );
  });

  it('finds rate-limiter-flexible', () => {
    expect(findRateLimitDependency(['rate-limiter-flexible'])).toBe(
      'rate-limiter-flexible',
    );
  });

  it('finds @fastify/rate-limit', () => {
    expect(findRateLimitDependency(['fastify', '@fastify/rate-limit'])).toBe(
      '@fastify/rate-limit',
    );
  });

  it('finds fastify-rate-limit (legacy)', () => {
    expect(findRateLimitDependency(['fastify-rate-limit'])).toBe(
      'fastify-rate-limit',
    );
  });

  it('returns undefined when no match', () => {
    expect(
      findRateLimitDependency(['express', 'cors', 'helmet']),
    ).toBeUndefined();
  });

  it('returns undefined for empty array', () => {
    expect(findRateLimitDependency([])).toBeUndefined();
  });

  it('returns first match when multiple present', () => {
    const result = findRateLimitDependency([
      'express-rate-limit',
      '@upstash/ratelimit',
    ]);
    expect(RATE_LIMIT_PACKAGES).toContain(result);
  });
});

// ---------------------------------------------------------------------------
// hasRateLimitPattern
// ---------------------------------------------------------------------------

describe('hasRateLimitPattern', () => {
  it('detects ESM import of express-rate-limit', () => {
    expect(
      hasRateLimitPattern('import rateLimit from "express-rate-limit"'),
    ).toBe(true);
  });

  it('detects CJS require of express-rate-limit', () => {
    expect(
      hasRateLimitPattern('const rateLimit = require("express-rate-limit")'),
    ).toBe(true);
  });

  it('detects ESM import of @upstash/ratelimit', () => {
    expect(
      hasRateLimitPattern(
        'import { Ratelimit } from "@upstash/ratelimit"',
      ),
    ).toBe(true);
  });

  it('detects CJS require of @upstash/ratelimit', () => {
    expect(
      hasRateLimitPattern(
        'const { Ratelimit } = require("@upstash/ratelimit")',
      ),
    ).toBe(true);
  });

  it('detects ESM import of rate-limiter-flexible', () => {
    expect(
      hasRateLimitPattern(
        'import { RateLimiterMemory } from "rate-limiter-flexible"',
      ),
    ).toBe(true);
  });

  it('detects CJS require of rate-limiter-flexible', () => {
    expect(
      hasRateLimitPattern(
        'const { RateLimiterMemory } = require("rate-limiter-flexible")',
      ),
    ).toBe(true);
  });

  it('detects ESM import of @fastify/rate-limit', () => {
    expect(
      hasRateLimitPattern(
        'import fastifyRateLimit from "@fastify/rate-limit"',
      ),
    ).toBe(true);
  });

  it('detects CJS require of @fastify/rate-limit', () => {
    expect(
      hasRateLimitPattern(
        'const fastifyRateLimit = require("@fastify/rate-limit")',
      ),
    ).toBe(true);
  });

  it('detects import from hono/rate-limit', () => {
    expect(
      hasRateLimitPattern(
        'import { rateLimiter } from "hono/rate-limit"',
      ),
    ).toBe(true);
  });

  it('detects rateLimit() function call', () => {
    expect(
      hasRateLimitPattern(
        'app.use(rateLimit({ windowMs: 60000, max: 100 }))',
      ),
    ).toBe(true);
  });

  it('detects RateLimiterMemory class', () => {
    expect(
      hasRateLimitPattern(
        'const limiter = new RateLimiterMemory({ points: 10, duration: 1 })',
      ),
    ).toBe(true);
  });

  it('detects RateLimiterRedis class', () => {
    expect(
      hasRateLimitPattern(
        'const limiter = new RateLimiterRedis({ storeClient: redis })',
      ),
    ).toBe(true);
  });

  it('detects RateLimiterMongo class', () => {
    expect(
      hasRateLimitPattern(
        'const limiter = new RateLimiterMongo({ storeClient: mongo })',
      ),
    ).toBe(true);
  });

  it('returns false for unrelated code', () => {
    expect(hasRateLimitPattern('const express = require("express")')).toBe(
      false,
    );
  });

  it('returns false for empty content', () => {
    expect(hasRateLimitPattern('')).toBe(false);
  });

  it('returns false for plain TODO comments', () => {
    expect(hasRateLimitPattern('// TODO: add rate limiting')).toBe(false);
  });

  it('detects single-quoted imports', () => {
    expect(
      hasRateLimitPattern("import rateLimit from 'express-rate-limit'"),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getRecommendation
// ---------------------------------------------------------------------------

describe('getRecommendation', () => {
  it('recommends express-rate-limit for Express', () => {
    const rec = getRecommendation({
      language: 'typescript',
      framework: 'express',
    });
    expect(rec.packageName).toBe('express-rate-limit');
    expect(rec.install).toContain('express-rate-limit');
  });

  it('recommends @fastify/rate-limit for Fastify', () => {
    const rec = getRecommendation({
      language: 'typescript',
      framework: 'fastify',
    });
    expect(rec.packageName).toBe('@fastify/rate-limit');
    expect(rec.install).toContain('@fastify/rate-limit');
  });

  it('recommends built-in rate limiter for Hono', () => {
    const rec = getRecommendation({
      language: 'typescript',
      framework: 'hono',
    });
    expect(rec.packageName).toContain('hono');
    expect(rec.install).toContain('hono/rate-limit');
  });

  it('recommends @upstash/ratelimit for Next.js', () => {
    const rec = getRecommendation({
      language: 'typescript',
      framework: 'next.js',
    });
    expect(rec.packageName).toBe('@upstash/ratelimit');
    expect(rec.install).toContain('@upstash/ratelimit');
  });

  it('recommends rate-limiter-flexible for unknown framework', () => {
    const rec = getRecommendation({ language: 'typescript' });
    expect(rec.packageName).toBe('rate-limiter-flexible');
    expect(rec.install).toContain('rate-limiter-flexible');
  });

  it('recommends rate-limiter-flexible for Remix', () => {
    const rec = getRecommendation({
      language: 'typescript',
      framework: 'remix',
    });
    expect(rec.packageName).toBe('rate-limiter-flexible');
  });
});

// ---------------------------------------------------------------------------
// buildAiPrompt
// ---------------------------------------------------------------------------

describe('buildAiPrompt', () => {
  it('includes the framework name', () => {
    const prompt = buildAiPrompt({
      language: 'typescript',
      framework: 'express',
    });
    expect(prompt).toContain('express');
  });

  it('includes the recommended package', () => {
    const prompt = buildAiPrompt({
      language: 'typescript',
      framework: 'next.js',
    });
    expect(prompt).toContain('@upstash/ratelimit');
  });

  it('includes 429 response guidance', () => {
    const prompt = buildAiPrompt({
      language: 'typescript',
      framework: 'express',
    });
    expect(prompt).toContain('429');
    expect(prompt).toContain('Retry-After');
  });

  it('uses generic description when no framework', () => {
    const prompt = buildAiPrompt({ language: 'javascript' });
    expect(prompt).toContain('my web application');
  });
});

// ---------------------------------------------------------------------------
// isScannableFile
// ---------------------------------------------------------------------------

describe('isScannableFile', () => {
  it('accepts .ts files', () => {
    expect(isScannableFile('src/app.ts')).toBe(true);
  });

  it('accepts .js files', () => {
    expect(isScannableFile('src/server.js')).toBe(true);
  });

  it('accepts .tsx files', () => {
    expect(isScannableFile('src/App.tsx')).toBe(true);
  });

  it('accepts .jsx files', () => {
    expect(isScannableFile('src/App.jsx')).toBe(true);
  });

  it('rejects .md files', () => {
    expect(isScannableFile('README.md')).toBe(false);
  });

  it('rejects .json files', () => {
    expect(isScannableFile('package.json')).toBe(false);
  });

  it('rejects .css files', () => {
    expect(isScannableFile('styles.css')).toBe(false);
  });

  it('rejects node_modules paths', () => {
    expect(isScannableFile('node_modules/express/index.js')).toBe(false);
  });

  it('rejects dist paths', () => {
    expect(isScannableFile('dist/index.js')).toBe(false);
  });

  it('rejects build paths', () => {
    expect(isScannableFile('build/server.js')).toBe(false);
  });

  it('rejects .git paths', () => {
    expect(isScannableFile('.git/hooks/pre-commit')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// rateLimitCheck — integration (uses temp directory)
// ---------------------------------------------------------------------------

describe('rateLimitCheck — integration', () => {
  const testDir = join(tmpdir(), `bastion-rate-limit-test-${Date.now()}`);

  async function runWith(
    files: Record<string, string>,
    stack: DetectedStack,
  ): Promise<ReturnType<typeof rateLimitCheck>> {
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
      stack,
      files: fileList,
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };

    return rateLimitCheck(context);
  }

  it('returns pass when rate limit package is in dependencies', async () => {
    const results = await runWith(
      { 'src/index.ts': 'const app = express();' },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express', 'express-rate-limit'],
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('express-rate-limit');
  });

  it('returns pass when @upstash/ratelimit is in dependencies', async () => {
    const results = await runWith(
      { 'src/index.ts': 'export default {}' },
      {
        language: 'typescript',
        framework: 'next.js',
        dependencies: ['next', '@upstash/ratelimit'],
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('@upstash/ratelimit');
  });

  it('returns pass when rate limiting pattern found in source', async () => {
    const results = await runWith(
      {
        'src/middleware.ts':
          'import rateLimit from "express-rate-limit";\napp.use(rateLimit({ max: 100 }));',
      },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express'],
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('source code');
  });

  it('returns pass when hono rate limiter is used in source', async () => {
    const results = await runWith(
      {
        'src/app.ts':
          'import { rateLimiter } from "hono/rate-limit";\napp.use(rateLimiter({ limit: 10 }));',
      },
      { language: 'typescript', framework: 'hono', dependencies: ['hono'] },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('returns fail when no rate limiting found', async () => {
    const results = await runWith(
      {
        'src/index.ts':
          'const app = express();\napp.get("/", (req, res) => res.send("hi"));',
      },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express'],
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
    expect(results[0]?.severity).toBe('high');
  });

  it('fail result includes fix text', async () => {
    const results = await runWith(
      { 'src/index.ts': 'export default {}' },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express'],
      },
    );
    expect(results[0]?.fix).toBeDefined();
    expect(results[0]?.fix).toContain('express-rate-limit');
  });

  it('fail result includes aiPrompt', async () => {
    const results = await runWith(
      { 'src/index.ts': 'export default {}' },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express'],
      },
    );
    expect(results[0]?.aiPrompt).toBeDefined();
    expect(results[0]?.aiPrompt).toContain('express');
    expect(results[0]?.aiPrompt).toContain('429');
  });

  it('tailors recommendation for Next.js', async () => {
    const results = await runWith(
      { 'src/app.ts': 'export default {}' },
      {
        language: 'typescript',
        framework: 'next.js',
        dependencies: ['next'],
      },
    );
    expect(results[0]?.fix).toContain('@upstash/ratelimit');
  });

  it('tailors recommendation for Fastify', async () => {
    const results = await runWith(
      { 'src/server.ts': 'const fastify = Fastify();' },
      {
        language: 'typescript',
        framework: 'fastify',
        dependencies: ['fastify'],
      },
    );
    expect(results[0]?.fix).toContain('@fastify/rate-limit');
  });

  it('returns fail with correct id and category', async () => {
    const results = await runWith(
      { 'src/index.ts': 'export default {}' },
      { language: 'typescript', dependencies: [] },
    );
    expect(results[0]?.id).toBe('rate-limit');
    expect(results[0]?.category).toBe('API Security');
  });

  it('handles empty file list', async () => {
    const context: ScanContext = {
      projectPath: testDir,
      stack: { language: 'typescript', dependencies: [] },
      files: [],
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });
    const results = await rateLimitCheck(context);
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
  });

  it('handles undefined dependencies', async () => {
    const results = await runWith(
      { 'src/index.ts': 'export default {}' },
      { language: 'typescript' },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
  });

  it('skips non-scannable files during source scan', async () => {
    const results = await runWith(
      {
        'README.md': 'rateLimit(',
        'data.json': '{ "rateLimit": true }',
      },
      { language: 'typescript', dependencies: [] },
    );
    expect(results[0]?.status).toBe('fail');
  });

  it('detects RateLimiterMemory in source', async () => {
    const results = await runWith(
      {
        'src/limiter.ts':
          'const limiter = new RateLimiterMemory({ points: 10, duration: 1 });',
      },
      { language: 'typescript', dependencies: [] },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('dependency check takes priority over source scan', async () => {
    const results = await runWith(
      { 'src/app.ts': 'import rateLimit from "express-rate-limit"' },
      {
        language: 'typescript',
        framework: 'express',
        dependencies: ['express', 'express-rate-limit'],
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
    expect(results[0]?.description).toContain('express-rate-limit');
    expect(results[0]?.description).not.toContain('source code');
  });

  it('gracefully handles unreadable files', async () => {
    // File listed but doesn't exist on disk — Promise.allSettled handles it
    const context: ScanContext = {
      projectPath: testDir,
      stack: { language: 'typescript', dependencies: [] },
      files: ['src/ghost.ts'],
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });
    const results = await rateLimitCheck(context);
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('fail');
  });

  // Cleanup
  it('cleans up temp dir', async () => {
    await rm(testDir, { recursive: true, force: true });
  });
});
