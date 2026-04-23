import { describe, it, expect } from 'vitest';
import {
  buildStackDescription,
  generatePrompt,
  enrichWithAiPrompts,
  findGenerator,
} from '../../src/education/prompts.js';
import type { CheckResult, ScanContext, DetectedStack } from '@bastion/shared';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/test',
    stack: { language: 'typescript' },
    files: [],
    verbose: false,
    projectType: 'unknown',
    projectTypeSource: 'auto',
    ...overrides,
  };
}

function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    id: 'test',
    name: 'Test check',
    status: 'fail',
    severity: 'high',
    description: 'Test description',
    ...overrides,
  };
}

function nextJsContext(extra: Partial<DetectedStack> = {}): ScanContext {
  return makeContext({
    stack: {
      language: 'typescript',
      framework: 'next.js',
      database: 'supabase',
      hosting: 'vercel',
      ...extra,
    },
  });
}

function expressContext(extra: Partial<DetectedStack> = {}): ScanContext {
  return makeContext({
    stack: {
      language: 'typescript',
      framework: 'express',
      ...extra,
    },
  });
}

// ---------------------------------------------------------------------------
// buildStackDescription
// ---------------------------------------------------------------------------

describe('buildStackDescription', () => {
  it('returns empty string for unknown language with no other info', () => {
    expect(buildStackDescription({ language: 'unknown' })).toBe('');
  });

  it('includes framework when present', () => {
    const desc = buildStackDescription({ language: 'typescript', framework: 'next.js' });
    expect(desc).toContain('next.js');
    expect(desc).toMatch(/^I'm using/);
  });

  it('falls back to language when no framework', () => {
    const desc = buildStackDescription({ language: 'typescript' });
    expect(desc).toContain('typescript');
  });

  it('includes database', () => {
    const desc = buildStackDescription({
      language: 'typescript',
      framework: 'next.js',
      database: 'supabase',
    });
    expect(desc).toContain('supabase');
  });

  it('includes auth provider', () => {
    const desc = buildStackDescription({
      language: 'typescript',
      framework: 'next.js',
      auth: 'clerk',
    });
    expect(desc).toContain('clerk');
    expect(desc).toContain('authentication');
  });

  it('includes hosting', () => {
    const desc = buildStackDescription({
      language: 'typescript',
      framework: 'next.js',
      hosting: 'vercel',
    });
    expect(desc).toContain('vercel');
  });

  it('joins multiple parts with "with"', () => {
    const desc = buildStackDescription({
      language: 'typescript',
      framework: 'next.js',
      database: 'supabase',
      auth: 'clerk',
      hosting: 'vercel',
    });
    expect(desc).toContain(' with ');
    expect(desc).toContain('next.js');
    expect(desc).toContain('supabase');
    expect(desc).toContain('clerk');
    expect(desc).toContain('vercel');
  });
});

// ---------------------------------------------------------------------------
// findGenerator
// ---------------------------------------------------------------------------

describe('findGenerator', () => {
  it('finds generator for exact ID match', () => {
    expect(findGenerator('secrets')).toBeDefined();
    expect(findGenerator('cors')).toBeDefined();
    expect(findGenerator('auth')).toBeDefined();
    expect(findGenerator('rate-limit')).toBeDefined();
  });

  it('finds generator for prefix match', () => {
    expect(findGenerator('gitignore-env')).toBeDefined();
    expect(findGenerator('gitignore-missing')).toBeDefined();
    expect(findGenerator('headers-content-security-policy')).toBeDefined();
    expect(findGenerator('ssl-cert')).toBeDefined();
    expect(findGenerator('dep-vuln-lodash')).toBeDefined();
  });

  it('matches security-txt-url before security-txt', () => {
    const urlGen = findGenerator('security-txt-url-contact');
    const txtGen = findGenerator('security-txt-contact');
    expect(urlGen).toBeDefined();
    expect(txtGen).toBeDefined();
  });

  it('returns undefined for unknown check ID', () => {
    expect(findGenerator('unknown-check')).toBeUndefined();
    expect(findGenerator('foobar')).toBeUndefined();
  });

  it('does not match partial ID without hyphen separator', () => {
    // 'corsair' should NOT match 'cors'
    expect(findGenerator('corsair')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — gitignore
// ---------------------------------------------------------------------------

describe('generatePrompt — gitignore', () => {
  it('generates .gitignore-missing prompt with framework', () => {
    const result = makeResult({
      id: 'gitignore-missing',
      name: '.gitignore coverage',
      description: 'No .gitignore file found',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('.next');
    expect(prompt).toContain('.gitignore');
  });

  it('generates missing-pattern prompt', () => {
    const result = makeResult({
      id: 'gitignore-env',
      name: '.gitignore coverage',
      description: 'Environment file (.env) is not gitignored — secrets may be committed',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('.env');
    expect(prompt).toContain('git rm --cached');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — secrets
// ---------------------------------------------------------------------------

describe('generatePrompt — secrets', () => {
  it('includes stack context and secret type', () => {
    const result = makeResult({
      id: 'secrets',
      name: 'Hardcoded secret: OpenAI API key',
      description: 'OpenAI API key detected',
      location: 'src/config.ts:15',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('OpenAI API key');
    expect(prompt).toContain('src/config.ts:15');
    expect(prompt).toContain('.env');
    expect(prompt).toContain('process.env');
  });

  it('uses Node.js fallback when no framework', () => {
    const result = makeResult({
      id: 'secrets',
      name: 'Hardcoded secret: Generic API key assignment',
      description: 'Hardcoded API key detected',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('Node.js');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — dep-vuln
// ---------------------------------------------------------------------------

describe('generatePrompt — dep-vuln', () => {
  it('includes stack context and vulnerability description', () => {
    const result = makeResult({
      id: 'dep-vuln-lodash',
      name: 'Dependency vulnerability',
      description: 'lodash: Prototype Pollution (https://example.com)',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('express');
    expect(prompt).toContain('lodash');
    expect(prompt).toContain('npm audit fix');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — env-example
// ---------------------------------------------------------------------------

describe('generatePrompt — env-example', () => {
  it('generates prompt for missing .env.example', () => {
    const result = makeResult({
      id: 'env-example',
      description: '.env is gitignored but no .env.example exists',
    });
    const ctx = nextJsContext({ auth: 'clerk' });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('supabase');
    expect(prompt).toContain('clerk');
    expect(prompt).toContain('.env.example');
  });

  it('generates prompt for real secrets in template', () => {
    const result = makeResult({
      id: 'env-example',
      description: '.env.example appears to contain real secret values for: STRIPE_KEY',
      location: '.env.example',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('real secret values');
    expect(prompt).toContain('placeholder');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — security-txt
// ---------------------------------------------------------------------------

describe('generatePrompt — security-txt', () => {
  it('handles missing Contact field', () => {
    const result = makeResult({
      id: 'security-txt-contact',
      description: 'security.txt is missing the required Contact field',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('Contact');
    expect(prompt).toContain('RFC 9116');
  });

  it('handles expired Expires field', () => {
    const result = makeResult({
      id: 'security-txt-expired',
      description: 'security.txt Expires field is in the past',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('expired');
    expect(prompt).toContain('RFC 3339');
  });

  it('handles generic security.txt issue', () => {
    const result = makeResult({
      id: 'security-txt-md',
      description: 'No SECURITY.md found',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('security.txt');
    expect(prompt).toContain('next.js');
  });

  it('handles security-txt-url variant', () => {
    const result = makeResult({
      id: 'security-txt-url-contact',
      description: 'security.txt is missing the required Contact field',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('Contact');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — headers
// ---------------------------------------------------------------------------

describe('generatePrompt — headers', () => {
  it('recommends helmet for Express', () => {
    const result = makeResult({
      id: 'headers-content-security-policy',
      name: 'Missing Content-Security-Policy',
      description: 'CSP header is missing',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('helmet');
    expect(prompt).toContain('Content-Security-Policy');
  });

  it('recommends next.config.js for Next.js', () => {
    const result = makeResult({
      id: 'headers-strict-transport-security',
      name: 'Missing Strict-Transport-Security',
      description: 'HSTS header is missing',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('next.config.js');
    expect(prompt).toContain('headers()');
  });

  it('uses generic advice for unknown framework', () => {
    const result = makeResult({
      id: 'headers-x-frame-options',
      name: 'Missing X-Frame-Options',
      description: 'X-Frame-Options header is missing',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('X-Frame-Options');
    expect(prompt).toContain('framework');
  });

  it('handles Fastify', () => {
    const result = makeResult({
      id: 'headers-referrer-policy',
      name: 'Missing Referrer-Policy',
      description: 'Referrer-Policy header is missing',
    });
    const ctx = makeContext({ stack: { language: 'typescript', framework: 'fastify' } });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('fastify');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — ssl
// ---------------------------------------------------------------------------

describe('generatePrompt — ssl', () => {
  it('suggests Let\'s Encrypt for unmanaged hosting', () => {
    const result = makeResult({
      id: 'ssl-cert',
      description: 'SSL certificate error',
    });
    const ctx = makeContext({ stack: { language: 'typescript', hosting: 'docker' } });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain("Let's Encrypt");
    expect(prompt).toContain('Certbot');
  });

  it('suggests managed SSL check for Vercel', () => {
    const result = makeResult({
      id: 'ssl-cert',
      description: 'SSL certificate error',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('vercel');
    expect(prompt).toContain('automatically');
  });

  it('handles redirect issue on Netlify', () => {
    const result = makeResult({
      id: 'ssl-redirect',
      description: 'No HTTPS redirect',
    });
    const ctx = makeContext({ stack: { language: 'typescript', hosting: 'netlify' } });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('netlify');
    expect(prompt).toContain('automatic');
  });

  it('handles redirect issue on unmanaged hosting', () => {
    const result = makeResult({
      id: 'ssl-redirect',
      description: 'No HTTPS redirect',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('301');
    expect(prompt).toContain('HSTS');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — code-patterns
// ---------------------------------------------------------------------------

describe('generatePrompt — code-patterns', () => {
  it('includes pattern name and framework', () => {
    const result = makeResult({
      id: 'code-patterns',
      name: 'Insecure pattern: eval() or new Function()',
      description: 'eval() detected',
      fix: 'Replace eval() with JSON.parse for data.',
      location: 'src/parser.ts:42',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('eval()');
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('src/parser.ts:42');
    expect(prompt).toContain('ESLint');
  });

  it('includes SQL injection context', () => {
    const result = makeResult({
      id: 'code-patterns',
      name: 'Insecure pattern: SQL string concatenation',
      description: 'SQL concat detected',
      fix: 'Use parameterized queries.',
      location: 'src/db.ts:10',
    });
    const ctx = makeContext({
      stack: { language: 'typescript', framework: 'express', database: 'prisma' },
    });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('SQL');
    expect(prompt).toContain('express');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — cors
// ---------------------------------------------------------------------------

describe('generatePrompt — cors', () => {
  it('includes framework-specific CORS advice', () => {
    const result = makeResult({
      id: 'cors',
      name: 'CORS: Wildcard origin',
      description: 'Access-Control-Allow-Origin is set to "*". Any website can read responses.',
      location: 'src/server.ts:5',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('express');
    expect(prompt).toContain('wildcard');
    expect(prompt).toContain('OPTIONS');
    expect(prompt).toContain('src/server.ts:5');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — rate-limit
// ---------------------------------------------------------------------------

describe('generatePrompt — rate-limit', () => {
  it('recommends @upstash/ratelimit for Next.js', () => {
    const result = makeResult({
      id: 'rate-limit',
      description: 'No rate limiting middleware detected',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('@upstash/ratelimit');
    expect(prompt).toContain('App Router');
    expect(prompt).toContain('429');
    expect(prompt).toContain('Retry-After');
  });

  it('recommends express-rate-limit for Express', () => {
    const result = makeResult({
      id: 'rate-limit',
      description: 'No rate limiting middleware detected',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('express-rate-limit');
    expect(prompt).not.toContain('App Router');
  });

  it('recommends @fastify/rate-limit for Fastify', () => {
    const result = makeResult({
      id: 'rate-limit',
      description: 'No rate limiting middleware detected',
    });
    const ctx = makeContext({ stack: { language: 'typescript', framework: 'fastify' } });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('@fastify/rate-limit');
  });

  it('recommends rate-limiter-flexible for unknown framework', () => {
    const result = makeResult({
      id: 'rate-limit',
      description: 'No rate limiting middleware detected',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('rate-limiter-flexible');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — auth
// ---------------------------------------------------------------------------

describe('generatePrompt — auth', () => {
  it('suggests migration for warn (custom auth)', () => {
    const result = makeResult({
      id: 'auth',
      status: 'warn',
      severity: 'medium',
      description: 'Custom auth detected via bcrypt',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('Supabase Auth');
    expect(prompt).toContain('migrate');
  });

  it('suggests Clerk for Next.js without Supabase', () => {
    const result = makeResult({
      id: 'auth',
      status: 'fail',
      description: 'No authentication detected',
    });
    const ctx = makeContext({
      stack: { language: 'typescript', framework: 'next.js' },
    });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('Clerk');
  });

  it('suggests Passport.js with Auth0 for Express', () => {
    const result = makeResult({
      id: 'auth',
      status: 'fail',
      description: 'No authentication detected',
    });
    const prompt = generatePrompt(result, expressContext());
    expect(prompt).toContain('Passport.js');
    expect(prompt).toContain('Auth0');
  });

  it('suggests Lucia for Remix', () => {
    const result = makeResult({
      id: 'auth',
      status: 'fail',
      description: 'No authentication detected',
    });
    const ctx = makeContext({
      stack: { language: 'typescript', framework: 'remix' },
    });
    const prompt = generatePrompt(result, ctx);
    expect(prompt).toContain('Lucia');
  });
});

// ---------------------------------------------------------------------------
// generatePrompt — generic fallback
// ---------------------------------------------------------------------------

describe('generatePrompt — generic fallback', () => {
  it('uses description and fix for unknown check IDs', () => {
    const result = makeResult({
      id: 'unknown-future-check',
      description: 'Something is wrong',
      fix: 'Do this to fix it',
      location: 'src/bad.ts:99',
    });
    const prompt = generatePrompt(result, nextJsContext());
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('Something is wrong');
    expect(prompt).toContain('Do this to fix it');
    expect(prompt).toContain('src/bad.ts:99');
  });

  it('handles missing fix gracefully', () => {
    const result = makeResult({
      id: 'unknown-check',
      description: 'Issue found',
    });
    const prompt = generatePrompt(result, makeContext());
    expect(prompt).toContain('Issue found');
    expect(prompt).not.toContain('undefined');
  });
});

// ---------------------------------------------------------------------------
// enrichWithAiPrompts
// ---------------------------------------------------------------------------

describe('enrichWithAiPrompts', () => {
  it('does not modify pass results', () => {
    const results: readonly CheckResult[] = [
      makeResult({ status: 'pass', aiPrompt: 'original prompt' }),
    ];
    const enriched = enrichWithAiPrompts(results, makeContext());
    expect(enriched[0]?.aiPrompt).toBe('original prompt');
  });

  it('does not modify skip results', () => {
    const results: readonly CheckResult[] = [
      makeResult({ status: 'skip', severity: 'info' }),
    ];
    const enriched = enrichWithAiPrompts(results, makeContext());
    expect(enriched[0]?.aiPrompt).toBeUndefined();
  });

  it('enriches fail results with stack-aware prompt', () => {
    const results: readonly CheckResult[] = [
      makeResult({ id: 'rate-limit', status: 'fail' }),
    ];
    const enriched = enrichWithAiPrompts(results, nextJsContext());
    expect(enriched[0]?.aiPrompt).toContain('next.js');
    expect(enriched[0]?.aiPrompt).toContain('@upstash/ratelimit');
  });

  it('enriches warn results', () => {
    const results: readonly CheckResult[] = [
      makeResult({ id: 'auth', status: 'warn', severity: 'medium' }),
    ];
    const enriched = enrichWithAiPrompts(results, expressContext());
    expect(enriched[0]?.aiPrompt).toBeDefined();
    expect(enriched[0]?.aiPrompt).toContain('express');
  });

  it('overrides existing aiPrompt on fail results', () => {
    const results: readonly CheckResult[] = [
      makeResult({
        id: 'secrets',
        status: 'fail',
        aiPrompt: 'old generic prompt',
      }),
    ];
    const enriched = enrichWithAiPrompts(results, nextJsContext());
    expect(enriched[0]?.aiPrompt).not.toBe('old generic prompt');
    expect(enriched[0]?.aiPrompt).toContain('next.js');
  });

  it('returns new array — does not mutate input', () => {
    const results: readonly CheckResult[] = [
      makeResult({ id: 'secrets', status: 'fail' }),
    ];
    const enriched = enrichWithAiPrompts(results, makeContext());
    expect(enriched).not.toBe(results);
    expect(enriched[0]).not.toBe(results[0]);
  });

  it('preserves array length', () => {
    const results: readonly CheckResult[] = [
      makeResult({ id: 'secrets', status: 'fail' }),
      makeResult({ id: 'gitignore-env', status: 'fail' }),
      makeResult({ id: 'auth', status: 'pass', aiPrompt: 'keep' }),
      makeResult({ id: 'rate-limit', status: 'skip', severity: 'info' }),
    ];
    const enriched = enrichWithAiPrompts(results, makeContext());
    expect(enriched).toHaveLength(4);
  });

  it('handles empty results array', () => {
    const enriched = enrichWithAiPrompts([], makeContext());
    expect(enriched).toEqual([]);
  });

  it('preserves all non-aiPrompt fields', () => {
    const original = makeResult({
      id: 'cors',
      name: 'CORS: wildcard',
      status: 'fail',
      severity: 'high',
      category: 'CORS',
      location: 'src/app.ts:1',
      description: 'Wildcard origin',
      fix: 'Fix it',
    });
    const enriched = enrichWithAiPrompts([original], makeContext());
    expect(enriched).toHaveLength(1);
    const result = enriched[0];
    expect(result?.id).toBe(original.id);
    expect(result?.name).toBe(original.name);
    expect(result?.status).toBe(original.status);
    expect(result?.severity).toBe(original.severity);
    expect(result?.category).toBe(original.category);
    expect(result?.location).toBe(original.location);
    expect(result?.description).toBe(original.description);
    expect(result?.fix).toBe(original.fix);
    expect(result?.aiPrompt).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Full stack context — end-to-end prompt quality
// ---------------------------------------------------------------------------

describe('end-to-end prompt quality', () => {
  it('rate-limit prompt for Next.js + Supabase matches example quality', () => {
    const result = makeResult({
      id: 'rate-limit',
      description: 'No rate limiting middleware detected',
    });
    const ctx = nextJsContext();
    const prompt = generatePrompt(result, ctx);

    // Should match the spirit of the example in the feature spec
    expect(prompt).toContain('next.js');
    expect(prompt).toContain('supabase');
    expect(prompt).toContain('@upstash/ratelimit');
    expect(prompt).toContain('10 per 15 seconds');
    expect(prompt).toContain('429');
    expect(prompt).toContain('Retry-After');
    expect(prompt).toContain('App Router');
  });

  it('secrets prompt includes complete remediation steps', () => {
    const result = makeResult({
      id: 'secrets',
      name: 'Hardcoded secret: Stripe secret key',
      description: 'Stripe secret key detected',
      location: 'src/billing.ts:22',
    });
    const ctx = nextJsContext();
    const prompt = generatePrompt(result, ctx);

    expect(prompt).toContain('Stripe secret key');
    expect(prompt).toContain('.env');
    expect(prompt).toContain('process.env');
    expect(prompt).toContain('.env.example');
    expect(prompt).toContain('startup check');
    expect(prompt).toContain('src/billing.ts:22');
  });

  it('all prompts are non-empty for fail results', () => {
    const checkIds = [
      'gitignore-missing',
      'gitignore-env',
      'secrets',
      'dep-vuln-react',
      'env-example',
      'security-txt-contact',
      'security-txt-url-contact',
      'headers-content-security-policy',
      'ssl-cert',
      'ssl-redirect',
      'code-patterns',
      'cors',
      'rate-limit',
      'auth',
    ];

    for (const id of checkIds) {
      const result = makeResult({ id, description: 'Issue found' });
      const prompt = generatePrompt(result, nextJsContext());
      expect(prompt.length).toBeGreaterThan(50);
    }
  });
});
