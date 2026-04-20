import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const mockFetch = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  vi.useFakeTimers();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function loadModule() {
  return await import('../../src/utils/fetch-with-retry.js');
}

// ---------------------------------------------------------------------------
// Success on first attempt
// ---------------------------------------------------------------------------

describe('fetchWithRetry', () => {
  it('returns response on first success', async () => {
    mockFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    const result = await fetchWithRetry('https://example.com');

    expect(result.response).toBeDefined();
    expect(result.response?.status).toBe(200);
    expect(result.attempts).toBe(1);
    expect(result.error).toBeUndefined();
  });

  it('does not retry on successful response', async () => {
    mockFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    await fetchWithRetry('https://example.com');

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('does not retry on HTTP error responses (404, 500)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('Not Found', { status: 404 }));

    const { fetchWithRetry } = await loadModule();
    const result = await fetchWithRetry('https://example.com');

    expect(result.response?.status).toBe(404);
    expect(result.attempts).toBe(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // ---------------------------------------------------------------------------
  // Retry on connection errors
  // ---------------------------------------------------------------------------

  it('retries once on AbortError (timeout) then succeeds', async () => {
    const abortError = new DOMException('The operation was aborted', 'AbortError');
    mockFetch
      .mockRejectedValueOnce(abortError)
      .mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    const promise = fetchWithRetry('https://example.com');

    // Advance past the 2s retry delay
    await vi.advanceTimersByTimeAsync(2_000);
    const result = await promise;

    expect(result.response?.status).toBe(200);
    expect(result.attempts).toBe(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('retries once on ECONNREFUSED then succeeds', async () => {
    const connError = new TypeError('fetch failed');
    (connError as Error & { cause?: Error }).cause = new Error('connect ECONNREFUSED 127.0.0.1:443');
    mockFetch
      .mockRejectedValueOnce(connError)
      .mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    const promise = fetchWithRetry('https://example.com');

    await vi.advanceTimersByTimeAsync(2_000);
    const result = await promise;

    expect(result.response?.status).toBe(200);
    expect(result.attempts).toBe(2);
  });

  it('retries once on ETIMEDOUT then succeeds', async () => {
    const timeoutError = new TypeError('fetch failed');
    (timeoutError as Error & { cause?: Error }).cause = new Error('connect ETIMEDOUT');
    mockFetch
      .mockRejectedValueOnce(timeoutError)
      .mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    const promise = fetchWithRetry('https://example.com');

    await vi.advanceTimersByTimeAsync(2_000);
    const result = await promise;

    expect(result.response?.status).toBe(200);
    expect(result.attempts).toBe(2);
  });

  it('retries once on ENOTFOUND then succeeds', async () => {
    const dnsError = new TypeError('fetch failed');
    (dnsError as Error & { cause?: Error }).cause = new Error('getaddrinfo ENOTFOUND example.com');
    mockFetch
      .mockRejectedValueOnce(dnsError)
      .mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    const promise = fetchWithRetry('https://example.com');

    await vi.advanceTimersByTimeAsync(2_000);
    const result = await promise;

    expect(result.response?.status).toBe(200);
    expect(result.attempts).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // Both attempts fail
  // ---------------------------------------------------------------------------

  it('returns error after 2 failed connection attempts', async () => {
    const abortError = new DOMException('The operation was aborted', 'AbortError');
    mockFetch
      .mockRejectedValueOnce(abortError)
      .mockRejectedValueOnce(abortError);

    const { fetchWithRetry } = await loadModule();
    const promise = fetchWithRetry('https://example.com');

    await vi.advanceTimersByTimeAsync(2_000);
    const result = await promise;

    expect(result.response).toBeUndefined();
    expect(result.error).toBeDefined();
    expect(result.attempts).toBe(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  // ---------------------------------------------------------------------------
  // Non-connection errors are NOT retried
  // ---------------------------------------------------------------------------

  it('does not retry on non-connection errors', async () => {
    mockFetch.mockRejectedValueOnce(new Error('some unexpected error'));

    const { fetchWithRetry } = await loadModule();
    const result = await fetchWithRetry('https://example.com');

    expect(result.error).toBeDefined();
    expect(result.attempts).toBe(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // ---------------------------------------------------------------------------
  // Timeout configuration
  // ---------------------------------------------------------------------------

  it('passes AbortSignal.timeout(10000) to each fetch call', async () => {
    mockFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const { fetchWithRetry } = await loadModule();
    await fetchWithRetry('https://example.com');

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  // ---------------------------------------------------------------------------
  // isConnectionError
  // ---------------------------------------------------------------------------

  describe('isConnectionError', () => {
    it('returns true for AbortError (DOMException)', async () => {
      const { isConnectionError } = await loadModule();
      expect(isConnectionError(new DOMException('aborted', 'AbortError'))).toBe(true);
    });

    it('returns true for ECONNREFUSED in message', async () => {
      const { isConnectionError } = await loadModule();
      expect(isConnectionError(new Error('connect ECONNREFUSED'))).toBe(true);
    });

    it('returns true for ECONNREFUSED in cause', async () => {
      const { isConnectionError } = await loadModule();
      const error = new TypeError('fetch failed');
      (error as Error & { cause?: Error }).cause = new Error('connect ECONNREFUSED');
      expect(isConnectionError(error)).toBe(true);
    });

    it('returns false for generic errors', async () => {
      const { isConnectionError } = await loadModule();
      expect(isConnectionError(new Error('something else'))).toBe(false);
    });

    it('returns false for non-Error values', async () => {
      const { isConnectionError } = await loadModule();
      expect(isConnectionError('string error')).toBe(false);
    });
  });
});
