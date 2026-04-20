/**
 * Fetch wrapper with single retry on connection failures.
 * Retries once after a 2-second delay on ECONNREFUSED, ETIMEDOUT, ENOTFOUND,
 * or fetch timeout (AbortError). Does NOT retry on HTTP error responses.
 */

const RETRY_DELAY_MS = 2_000;
const TIMEOUT_PER_ATTEMPT_MS = 10_000;

/** Error codes that indicate a connection failure (not an HTTP-level error) */
const CONNECTION_ERROR_PATTERNS = [
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENOTFOUND',
] as const;

/** Determine if an error is a connection failure worth retrying */
function isConnectionError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === 'AbortError') {
    return true;
  }

  const message = error instanceof Error ? error.message : '';
  const causeMessage =
    error instanceof Error && error.cause instanceof Error
      ? error.cause.message
      : '';

  const combined = `${message} ${causeMessage}`;
  return CONNECTION_ERROR_PATTERNS.some((code) => combined.includes(code));
}

/** Wait for a given number of milliseconds */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface FetchWithRetryResult {
  readonly response?: Response;
  readonly error?: unknown;
  readonly attempts: number;
}

/**
 * Fetch a URL with a single retry on connection failure.
 * Returns the response on success, or the final error after 2 attempts.
 */
export async function fetchWithRetry(
  url: string,
  init?: RequestInit,
): Promise<FetchWithRetryResult> {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const response = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(TIMEOUT_PER_ATTEMPT_MS),
      });
      return { response, attempts: attempt };
    } catch (error: unknown) {
      if (attempt === 1 && isConnectionError(error)) {
        await delay(RETRY_DELAY_MS);
        continue;
      }
      return { error, attempts: attempt };
    }
  }

  // Unreachable, but satisfies TypeScript
  return { error: new Error('Unexpected retry exhaustion'), attempts: 2 };
}

export { isConnectionError, TIMEOUT_PER_ATTEMPT_MS };
