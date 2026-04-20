import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanContext } from '@bastion/shared';
import securityTxtUrlCheck from '../../src/checks/security-txt-url.js';

const fetchMock = vi.fn();

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/test',
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    ...overrides,
  };
}

function futureDate(): string {
  return new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
}

function plainResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  fetchMock.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// No URL — skip
// ---------------------------------------------------------------------------

describe('security-txt-url check', () => {
  describe('when no URL is provided', () => {
    it('returns skip result', async () => {
      const results = await securityTxtUrlCheck(makeContext());

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt-url',
        status: 'skip',
        severity: 'info',
        category: 'disclosure',
      });
    });

    it('does not call fetch', async () => {
      await securityTxtUrlCheck(makeContext());

      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  // ---------------------------------------------------------------------------
  // Valid security.txt found
  // ---------------------------------------------------------------------------

  describe('when valid security.txt is found', () => {
    it('passes for valid file at .well-known path', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt-url',
        status: 'pass',
        category: 'disclosure',
      });
    });

    it('sets location to the full URL', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results[0]?.location).toBe('https://example.com/.well-known/security.txt');
    });

    it('falls back to /security.txt when .well-known returns 404', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock
        .mockResolvedValueOnce(new Response('Not Found', { status: 404 }))
        .mockResolvedValueOnce(plainResponse(body));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({ status: 'pass' });
      expect(results[0]?.location).toBe('https://example.com/security.txt');
    });

    it('does not fetch /security.txt if .well-known succeeds', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(String(fetchMock.mock.calls[0]?.[0])).toContain('.well-known/security.txt');
    });
  });

  // ---------------------------------------------------------------------------
  // Not found
  // ---------------------------------------------------------------------------

  describe('when security.txt is not found', () => {
    beforeEach(() => {
      fetchMock.mockImplementation(() =>
        Promise.resolve(new Response('Not Found', { status: 404 })),
      );
    });

    it('returns fail with medium severity', async () => {
      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt-url',
        status: 'fail',
        severity: 'medium',
      });
    });

    it('includes both tried URLs in description', async () => {
      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results[0]?.description).toContain('.well-known/security.txt');
      expect(results[0]?.description).toContain('/security.txt');
    });

    it('includes fix instructions linking to securitytxt.org', async () => {
      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results[0]?.fix).toContain('securitytxt.org');
    });

    it('includes AI prompt mentioning RFC 9116', async () => {
      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results[0]?.aiPrompt).toContain('security.txt');
      expect(results[0]?.aiPrompt).toContain('RFC 9116');
    });
  });

  // ---------------------------------------------------------------------------
  // Field validation
  // ---------------------------------------------------------------------------

  describe('field validation', () => {
    it('fails when Contact field is missing', async () => {
      fetchMock.mockResolvedValue(plainResponse(`Expires: ${futureDate()}\n`));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      const contact = results.find((r) => r.id === 'security-txt-url-contact');
      expect(contact).toBeDefined();
      expect(contact?.status).toBe('fail');
      expect(contact?.severity).toBe('medium');
    });

    it('fails when Expires field is missing', async () => {
      fetchMock.mockResolvedValue(
        plainResponse('Contact: mailto:security@example.com\n'),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      const expires = results.find((r) => r.id === 'security-txt-url-expires');
      expect(expires).toBeDefined();
      expect(expires?.status).toBe('fail');
      expect(expires?.severity).toBe('medium');
    });

    it('warns when Expires date is in the past', async () => {
      fetchMock.mockResolvedValue(
        plainResponse(
          'Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00.000Z\n',
        ),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      const expired = results.find((r) => r.id === 'security-txt-url-expired');
      expect(expired).toBeDefined();
      expect(expired?.status).toBe('warn');
      expect(expired?.severity).toBe('medium');
      expect(expired?.description).toContain('2020-01-01');
    });

    it('returns two fail results when both fields are missing', async () => {
      fetchMock.mockResolvedValue(plainResponse('# Empty security.txt\n'));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results.filter((r) => r.status === 'fail')).toHaveLength(2);
      expect(results.some((r) => r.id === 'security-txt-url-contact')).toBe(true);
      expect(results.some((r) => r.id === 'security-txt-url-expires')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('returns fail when fetch throws a network error (retries exhausted)', async () => {
      const connError = new DOMException('The operation was aborted', 'AbortError');
      fetchMock.mockRejectedValue(connError);

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt-url',
        status: 'fail',
        severity: 'medium',
      });
    });

    it('retries on connection error then succeeds', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      const connError = new DOMException('The operation was aborted', 'AbortError');
      fetchMock
        .mockRejectedValueOnce(connError)
        .mockResolvedValueOnce(plainResponse(body));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]?.status).toBe('pass');
    });

    it('returns fail for non-200 responses (500) without retry', async () => {
      fetchMock.mockImplementation(() =>
        Promise.resolve(new Response('Server Error', { status: 500 })),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]?.status).toBe('fail');
    });

    it('returns fail for non-text/plain responses (text/html)', async () => {
      fetchMock.mockImplementation(() =>
        Promise.resolve(
          new Response('<html>Error</html>', {
            status: 200,
            headers: { 'content-type': 'text/html' },
          }),
        ),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]?.status).toBe('fail');
    });

    it('returns fail for application/json responses', async () => {
      fetchMock.mockImplementation(() =>
        Promise.resolve(
          new Response('{}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        ),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results).toHaveLength(1);
      expect(results[0]?.status).toBe('fail');
    });

    it('passes AbortSignal to fetch for timeout support', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      const callArgs = fetchMock.mock.calls[0];
      expect(callArgs?.[1]).toBeDefined();
      expect((callArgs?.[1] as RequestInit)?.signal).toBeInstanceOf(AbortSignal);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  describe('edge cases', () => {
    it('strips trailing slashes from URL', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      await securityTxtUrlCheck(makeContext({ url: 'https://example.com/' }));

      expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
        'https://example.com/.well-known/security.txt',
      );
    });

    it('handles multiple trailing slashes', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(plainResponse(body));

      await securityTxtUrlCheck(makeContext({ url: 'https://example.com///' }));

      expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
        'https://example.com/.well-known/security.txt',
      );
    });

    it('handles comments and empty lines in security.txt', async () => {
      const content = [
        '# Comment',
        '',
        'Contact: mailto:security@example.com',
        '# Another comment',
        `Expires: ${futureDate()}`,
        '',
      ].join('\n');
      fetchMock.mockResolvedValue(plainResponse(content));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results.find((r) => r.id === 'security-txt-url')?.status).toBe('pass');
    });

    it('handles case-insensitive field names', async () => {
      fetchMock.mockResolvedValue(
        plainResponse(`contact: mailto:security@example.com\nexpires: ${futureDate()}\n`),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results.find((r) => r.id === 'security-txt-url')?.status).toBe('pass');
    });

    it('treats unparseable Expires date as not expired', async () => {
      fetchMock.mockResolvedValue(
        plainResponse('Contact: mailto:security@example.com\nExpires: not-a-date\n'),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results.find((r) => r.id === 'security-txt-url')?.status).toBe('pass');
    });

    it('accepts text/plain with charset parameter', async () => {
      const body = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`;
      fetchMock.mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
      );

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      expect(results.find((r) => r.id === 'security-txt-url')?.status).toBe('pass');
    });

    it('includes fix text with securitytxt.org on field failures', async () => {
      fetchMock.mockResolvedValue(plainResponse(`Expires: ${futureDate()}\n`));

      const results = await securityTxtUrlCheck(makeContext({ url: 'https://example.com' }));

      const contact = results.find((r) => r.id === 'security-txt-url-contact');
      expect(contact?.fix).toContain('securitytxt.org');
    });
  });
});
