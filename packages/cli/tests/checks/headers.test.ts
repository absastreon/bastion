import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanContext } from 'bastion-shared';

/** Create a minimal ScanContext with overrides */
function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/bastion-test-nonexistent',
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    projectType: 'unknown',
    projectTypeSource: 'auto',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock fetch globally so tests never make real HTTP requests
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Helper to build a Response with given headers */
function fakeResponse(
  headers: Record<string, string>,
  status = 200,
): Response {
  return new Response(null, { status, headers });
}

// Lazy import so the module picks up our global mock
async function loadCheck() {
  const mod = await import('../../src/checks/headers.js');
  return mod.default;
}

// ---------------------------------------------------------------------------
// No URL → skip
// ---------------------------------------------------------------------------

describe('headers check', () => {
  describe('when no URL is provided', () => {
    it('returns a skip result', async () => {
      const check = await loadCheck();
      const results = await check(makeContext());

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'headers',
        status: 'skip',
        severity: 'info',
      });
    });
  });

  // ---------------------------------------------------------------------------
  // All headers present → pass
  // ---------------------------------------------------------------------------

  describe('when all security headers are present', () => {
    it('returns a pass result', async () => {
      mockFetch.mockResolvedValueOnce(
        fakeResponse({
          'content-security-policy': "default-src 'self'",
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        }),
      );

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'headers',
        status: 'pass',
        severity: 'info',
        category: 'headers',
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Missing individual headers
  // ---------------------------------------------------------------------------

  describe('when headers are missing', () => {
    it('returns a fail for each missing header', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}));

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      const fails = results.filter((r) => r.status === 'fail');
      expect(fails).toHaveLength(6);
      expect(fails.every((r) => r.severity === 'high')).toBe(true);
      expect(fails.every((r) => r.category === 'headers')).toBe(true);
    });

    it('returns fail for missing CSP with explanation', async () => {
      mockFetch.mockResolvedValueOnce(
        fakeResponse({
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        }),
      );

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      const csp = results.find((r) => r.id === 'headers-content-security-policy');
      expect(csp).toBeDefined();
      expect(csp?.status).toBe('fail');
      expect(csp?.fix).toBeDefined();
      expect(csp?.description).toContain('Content-Security-Policy');
    });

    it('returns fail for missing HSTS', async () => {
      mockFetch.mockResolvedValueOnce(
        fakeResponse({
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        }),
      );

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      const hsts = results.find((r) => r.id === 'headers-strict-transport-security');
      expect(hsts).toBeDefined();
      expect(hsts?.status).toBe('fail');
      expect(hsts?.description).toContain('Strict-Transport-Security');
    });

    it('includes fix and aiPrompt for every failing header', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}));

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      const fails = results.filter((r) => r.status === 'fail');
      for (const result of fails) {
        expect(result.fix).toBeDefined();
        expect(result.aiPrompt).toBeDefined();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Stack-aware AI prompts
  // ---------------------------------------------------------------------------

  describe('AI prompt tailoring by stack', () => {
    it('mentions helmet.js for Express stack', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}));

      const check = await loadCheck();
      const results = await check(
        makeContext({ url: 'https://example.com', stack: { language: 'javascript', framework: 'express' } }),
      );

      const fails = results.filter((r) => r.status === 'fail');
      expect(fails.some((r) => r.aiPrompt?.toLowerCase().includes('helmet'))).toBe(true);
    });

    it('mentions next.config.js for Next.js stack', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}));

      const check = await loadCheck();
      const results = await check(
        makeContext({ url: 'https://example.com', stack: { language: 'typescript', framework: 'next' } }),
      );

      const fails = results.filter((r) => r.status === 'fail');
      expect(fails.some((r) => r.aiPrompt?.includes('next.config'))).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('returns skip after 2 failed connection attempts', async () => {
      const abortError = new DOMException('The operation was aborted', 'AbortError');
      mockFetch
        .mockRejectedValueOnce(abortError)
        .mockRejectedValueOnce(abortError);

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://unreachable.invalid' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'headers',
        status: 'skip',
        severity: 'info',
        category: 'headers',
      });
      expect(results[0]?.description).toContain('after 2 attempts');
      expect(results[0]?.description).toContain('unreachable.invalid');
    });

    it('retries once on connection error then succeeds', async () => {
      const abortError = new DOMException('The operation was aborted', 'AbortError');
      mockFetch
        .mockRejectedValueOnce(abortError)
        .mockResolvedValueOnce(fakeResponse({
          'content-security-policy': "default-src 'self'",
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        }));

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]?.status).toBe('pass');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('returns skip on non-200 response (no retry for HTTP errors)', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}, 503));

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'headers',
        status: 'skip',
      });
      expect(results[0]?.description).toContain('503');
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  // ---------------------------------------------------------------------------
  // Partial headers
  // ---------------------------------------------------------------------------

  describe('partial headers', () => {
    it('returns pass for present headers and fail for missing ones', async () => {
      mockFetch.mockResolvedValueOnce(
        fakeResponse({
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
        }),
      );

      const check = await loadCheck();
      const results = await check(makeContext({ url: 'https://example.com' }));

      // 4 missing headers → 4 fails
      const fails = results.filter((r) => r.status === 'fail');
      expect(fails).toHaveLength(4);

      // No overall pass result when some headers are missing
      const passes = results.filter((r) => r.status === 'pass');
      expect(passes).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Fetch is called with correct options
  // ---------------------------------------------------------------------------

  describe('fetch options', () => {
    it('passes an AbortSignal with 10s timeout', async () => {
      mockFetch.mockResolvedValueOnce(
        fakeResponse({
          'content-security-policy': "default-src 'self'",
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        }),
      );

      const check = await loadCheck();
      await check(makeContext({ url: 'https://example.com' }));

      expect(mockFetch).toHaveBeenCalledOnce();
      const call = mockFetch.mock.calls[0];
      expect(call).toBeDefined();
      const [, init] = call as [string, RequestInit];
      expect(init?.signal).toBeInstanceOf(AbortSignal);
    });

    it('fetches the provided URL', async () => {
      mockFetch.mockResolvedValueOnce(fakeResponse({}));

      const check = await loadCheck();
      await check(makeContext({ url: 'https://my-site.dev' }));

      expect(mockFetch).toHaveBeenCalledWith('https://my-site.dev', expect.any(Object));
    });
  });
});
