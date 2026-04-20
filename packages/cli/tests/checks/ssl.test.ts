import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ScanContext } from '@bastion/shared';

// ---------------------------------------------------------------------------
// Mock node:tls and node:http before importing the check module
// ---------------------------------------------------------------------------

vi.mock('node:tls', () => ({
  connect: vi.fn(),
}));

vi.mock('node:http', () => ({
  request: vi.fn(),
}));

import { connect as tlsConnect } from 'node:tls';
import { request as httpRequest } from 'node:http';
import sslCheck from '../../src/checks/ssl.js';

const mockedTlsConnect = vi.mocked(tlsConnect);
const mockedHttpRequest = vi.mocked(httpRequest);

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Create a minimal ScanContext with overrides */
function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/bastion-test',
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    ...overrides,
  };
}

/** Create a mock EventEmitter with socket-like methods */
function createMockSocket(): EventEmitter & {
  destroy: ReturnType<typeof vi.fn>;
  setTimeout: ReturnType<typeof vi.fn>;
} {
  const socket = new EventEmitter() as EventEmitter & {
    destroy: ReturnType<typeof vi.fn>;
    setTimeout: ReturnType<typeof vi.fn>;
  };
  socket.destroy = vi.fn();
  socket.setTimeout = vi.fn();
  return socket;
}

/** Create a mock EventEmitter with request-like methods */
function createMockRequest(): EventEmitter & {
  end: ReturnType<typeof vi.fn>;
  destroy: ReturnType<typeof vi.fn>;
  setTimeout: ReturnType<typeof vi.fn>;
} {
  const req = new EventEmitter() as EventEmitter & {
    end: ReturnType<typeof vi.fn>;
    destroy: ReturnType<typeof vi.fn>;
    setTimeout: ReturnType<typeof vi.fn>;
  };
  req.end = vi.fn();
  req.destroy = vi.fn();
  req.setTimeout = vi.fn();
  return req;
}

/** Mock tls.connect to succeed (valid certificate) */
function setupTlsSuccess(): void {
  mockedTlsConnect.mockImplementation(
    (_options: unknown, callback?: () => void) => {
      const socket = createMockSocket();
      if (callback) process.nextTick(callback);
      return socket as ReturnType<typeof tlsConnect>;
    },
  );
}

/** Mock tls.connect to fail with a specific error code */
function setupTlsError(code: string, message: string): void {
  mockedTlsConnect.mockImplementation(() => {
    const socket = createMockSocket();
    const error = Object.assign(new Error(message), { code });
    process.nextTick(() => socket.emit('error', error));
    return socket as ReturnType<typeof tlsConnect>;
  });
}

/** Mock http.request to return a redirect response */
function setupHttpRedirect(statusCode: number, location: string): void {
  mockedHttpRequest.mockImplementation(
    (_options: unknown, callback?: (res: unknown) => void) => {
      const req = createMockRequest();
      if (callback) {
        process.nextTick(() =>
          callback({ statusCode, headers: { location } }),
        );
      }
      return req as ReturnType<typeof httpRequest>;
    },
  );
}

/** Mock http.request to return a 200 OK (no redirect) */
function setupHttpNoRedirect(): void {
  mockedHttpRequest.mockImplementation(
    (_options: unknown, callback?: (res: unknown) => void) => {
      const req = createMockRequest();
      if (callback) {
        process.nextTick(() => callback({ statusCode: 200, headers: {} }));
      }
      return req as ReturnType<typeof httpRequest>;
    },
  );
}

/** Mock http.request to fail with a connection error */
function setupHttpError(): void {
  mockedHttpRequest.mockImplementation(() => {
    const req = createMockRequest();
    process.nextTick(() => req.emit('error', new Error('ECONNREFUSED')));
    return req as ReturnType<typeof httpRequest>;
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ssl check', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // Skip conditions
  // -------------------------------------------------------------------------

  describe('when no URL is provided', () => {
    it('returns a skip result', async () => {
      const results = await sslCheck(makeContext());

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'ssl',
        status: 'skip',
        severity: 'info',
      });
      expect(results[0]?.description).toContain('No URL provided');
    });

    it('does not attempt any network calls', async () => {
      await sslCheck(makeContext());

      expect(mockedTlsConnect).not.toHaveBeenCalled();
      expect(mockedHttpRequest).not.toHaveBeenCalled();
    });
  });

  describe('when URL is invalid', () => {
    it('returns a skip result', async () => {
      const results = await sslCheck(makeContext({ url: 'not-a-url' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'ssl',
        status: 'skip',
      });
      expect(results[0]?.description).toContain('Invalid URL');
    });
  });

  // -------------------------------------------------------------------------
  // HTTP URL (no HTTPS)
  // -------------------------------------------------------------------------

  describe('when URL uses HTTP', () => {
    it('returns a critical finding for no HTTPS', async () => {
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'http://example.com' }),
      );

      const noHttps = results.find((r) => r.id === 'ssl-no-https');
      expect(noHttps).toBeDefined();
      expect(noHttps?.status).toBe('fail');
      expect(noHttps?.severity).toBe('critical');
      expect(noHttps?.description).toContain('plain HTTP');
    });

    it('does not attempt TLS certificate verification', async () => {
      setupHttpNoRedirect();
      await sslCheck(makeContext({ url: 'http://example.com' }));

      expect(mockedTlsConnect).not.toHaveBeenCalled();
    });

    it('still checks for HTTP→HTTPS redirect', async () => {
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'http://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect).toBeDefined();
      expect(redirect?.status).toBe('pass');
    });

    it('includes fix and aiPrompt mentioning Let\'s Encrypt', async () => {
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'http://example.com' }),
      );

      const noHttps = results.find((r) => r.id === 'ssl-no-https');
      expect(noHttps?.fix).toContain("Let's Encrypt");
      expect(noHttps?.aiPrompt).toContain('Certbot');
    });
  });

  // -------------------------------------------------------------------------
  // HTTPS URL — certificate verification
  // -------------------------------------------------------------------------

  describe('when URL uses HTTPS with valid certificate', () => {
    it('returns a pass result for the certificate', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert).toBeDefined();
      expect(cert?.status).toBe('pass');
      expect(cert?.description).toContain('valid and trusted');
    });

    it('connects to the correct hostname and default port', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      await sslCheck(makeContext({ url: 'https://example.com' }));

      expect(mockedTlsConnect).toHaveBeenCalledWith(
        expect.objectContaining({
          host: 'example.com',
          port: 443,
          servername: 'example.com',
          rejectUnauthorized: true,
        }),
        expect.any(Function),
      );
    });

    it('uses a custom port when specified in the URL', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      await sslCheck(makeContext({ url: 'https://example.com:8443' }));

      expect(mockedTlsConnect).toHaveBeenCalledWith(
        expect.objectContaining({ port: 8443 }),
        expect.any(Function),
      );
    });
  });

  describe('when HTTPS certificate is self-signed', () => {
    it('returns a critical failure', async () => {
      setupTlsError(
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'self-signed certificate',
      );
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert).toBeDefined();
      expect(cert?.status).toBe('fail');
      expect(cert?.severity).toBe('critical');
      expect(cert?.description).toContain('Self-signed certificate');
    });

    it('includes fix and aiPrompt for certificate errors', async () => {
      setupTlsError(
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'self-signed certificate',
      );
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.fix).toContain("Let's Encrypt");
      expect(cert?.aiPrompt).toContain('Certbot');
    });
  });

  describe('when HTTPS certificate has expired', () => {
    it('returns a critical failure', async () => {
      setupTlsError('CERT_HAS_EXPIRED', 'certificate has expired');
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('fail');
      expect(cert?.severity).toBe('critical');
      expect(cert?.description).toContain('expired');
    });
  });

  describe('when HTTPS certificate hostname mismatches', () => {
    it('returns a critical failure', async () => {
      setupTlsError(
        'ERR_TLS_CERT_ALTNAME_INVALID',
        'hostname mismatch',
      );
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('fail');
      expect(cert?.severity).toBe('critical');
      expect(cert?.description).toContain('hostname does not match');
    });
  });

  describe('when certificate chain is untrusted', () => {
    it('returns a critical failure', async () => {
      setupTlsError(
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'unable to verify the first certificate',
      );
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('fail');
      expect(cert?.severity).toBe('critical');
      expect(cert?.description).toContain('Unable to verify');
    });
  });

  describe('when an unknown certificate error occurs', () => {
    it('includes the error message in the description', async () => {
      setupTlsError('SOME_UNKNOWN_CODE', 'unusual TLS failure');
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('fail');
      expect(cert?.severity).toBe('critical');
      expect(cert?.description).toContain('unusual TLS failure');
    });
  });

  // -------------------------------------------------------------------------
  // Connection errors (not certificate issues)
  // -------------------------------------------------------------------------

  describe('when connection is refused', () => {
    it('retries once then returns skip after 2 attempts', async () => {
      setupTlsError('ECONNREFUSED', 'connect ECONNREFUSED');
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('skip');
      expect(cert?.description).toContain('after 2 attempts');
      // Should have been called twice (initial + retry)
      expect(mockedTlsConnect).toHaveBeenCalledTimes(2);
    });
  });

  describe('when connection times out', () => {
    it('retries once then returns skip', async () => {
      setupTlsError('ETIMEDOUT', 'Connection timed out');
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('skip');
      expect(cert?.description).toContain('after 2 attempts');
      expect(mockedTlsConnect).toHaveBeenCalledTimes(2);
    });
  });

  describe('when hostname cannot be resolved', () => {
    it('retries once then returns skip', async () => {
      setupTlsError('ENOTFOUND', 'getaddrinfo ENOTFOUND');
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://nonexistent.example' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('skip');
      expect(cert?.description).toContain('after 2 attempts');
      expect(mockedTlsConnect).toHaveBeenCalledTimes(2);
    });
  });

  describe('when connection fails once then succeeds', () => {
    it('returns pass after retry', async () => {
      // First call fails, second succeeds
      let callCount = 0;
      mockedTlsConnect.mockImplementation(
        (_options: unknown, callback?: () => void) => {
          const socket = createMockSocket();
          callCount++;
          if (callCount === 1) {
            const error = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
            process.nextTick(() => socket.emit('error', error));
          } else if (callback) {
            process.nextTick(callback);
          }
          return socket as ReturnType<typeof tlsConnect>;
        },
      );
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const cert = results.find((r) => r.id === 'ssl-cert');
      expect(cert?.status).toBe('pass');
      expect(mockedTlsConnect).toHaveBeenCalledTimes(2);
    });
  });

  // -------------------------------------------------------------------------
  // HTTP → HTTPS redirect
  // -------------------------------------------------------------------------

  describe('HTTP to HTTPS redirect', () => {
    it('passes when server returns 301 redirect to HTTPS', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('pass');
      expect(redirect?.description).toContain('redirected to HTTPS');
    });

    it('passes when server returns 302 redirect to HTTPS', async () => {
      setupTlsSuccess();
      setupHttpRedirect(302, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('pass');
    });

    it('passes when server returns 307 redirect to HTTPS', async () => {
      setupTlsSuccess();
      setupHttpRedirect(307, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('pass');
    });

    it('passes when server returns 308 redirect to HTTPS', async () => {
      setupTlsSuccess();
      setupHttpRedirect(308, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('pass');
    });

    it('fails when server returns 200 (no redirect)', async () => {
      setupTlsSuccess();
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('fail');
      expect(redirect?.severity).toBe('medium');
      expect(redirect?.description).toContain('not redirected');
    });

    it('fails when redirect target is HTTP (not HTTPS)', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'http://example.com/other');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('fail');
      expect(redirect?.severity).toBe('medium');
    });

    it('fails gracefully when HTTP connection errors', async () => {
      setupTlsSuccess();
      setupHttpError();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.status).toBe('fail');
      expect(redirect?.severity).toBe('medium');
    });

    it('includes fix instructions for missing redirect', async () => {
      setupTlsSuccess();
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      const redirect = results.find((r) => r.id === 'ssl-redirect');
      expect(redirect?.fix).toContain('301 redirect');
      expect(redirect?.aiPrompt).toContain('Nginx');
    });
  });

  // -------------------------------------------------------------------------
  // Combined scenarios
  // -------------------------------------------------------------------------

  describe('combined results', () => {
    it('returns cert pass + redirect pass for a fully secure HTTPS site', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      expect(results).toHaveLength(2);
      expect(results.every((r) => r.status === 'pass')).toBe(true);
    });

    it('returns no-https + redirect for HTTP URL with redirect', async () => {
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'http://example.com' }),
      );

      expect(results).toHaveLength(2);
      expect(results.some((r) => r.id === 'ssl-no-https')).toBe(true);
      expect(results.some((r) => r.id === 'ssl-redirect' && r.status === 'pass')).toBe(true);
    });

    it('returns no-https + no-redirect for HTTP URL without redirect', async () => {
      setupHttpNoRedirect();
      const results = await sslCheck(
        makeContext({ url: 'http://example.com' }),
      );

      expect(results).toHaveLength(2);
      const fails = results.filter((r) => r.status === 'fail');
      expect(fails).toHaveLength(2);
      expect(fails.some((r) => r.severity === 'critical')).toBe(true);
      expect(fails.some((r) => r.severity === 'medium')).toBe(true);
    });

    it('returns cert fail + redirect pass for HTTPS with bad cert but good redirect', async () => {
      setupTlsError('CERT_HAS_EXPIRED', 'certificate has expired');
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      expect(results).toHaveLength(2);
      expect(results.find((r) => r.id === 'ssl-cert')?.status).toBe('fail');
      expect(results.find((r) => r.id === 'ssl-redirect')?.status).toBe('pass');
    });

    it('sets category to transport on all results', async () => {
      setupTlsSuccess();
      setupHttpRedirect(301, 'https://example.com/');
      const results = await sslCheck(
        makeContext({ url: 'https://example.com' }),
      );

      expect(results.every((r) => r.category === 'transport')).toBe(true);
    });
  });
});
