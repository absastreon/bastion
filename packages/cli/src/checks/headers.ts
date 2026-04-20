/**
 * Check: Security headers via HTTP
 * Fetches the provided URL and verifies critical security headers are present.
 * Skips gracefully when no URL is provided or the request fails.
 */
import type { CheckFunction, CheckResult, ScanContext } from '@bastion/shared';
import { fetchWithRetry } from '../utils/fetch-with-retry.js';

const CHECK_ID = 'headers';
const CATEGORY = 'headers';

/** Header definitions: name, description of what it prevents, and fix text */
interface HeaderSpec {
  readonly header: string;
  readonly label: string;
  readonly description: string;
  readonly fix: string;
}

const REQUIRED_HEADERS: readonly HeaderSpec[] = [
  {
    header: 'content-security-policy',
    label: 'Content-Security-Policy',
    description:
      'Content-Security-Policy header is missing. CSP prevents cross-site scripting (XSS) and data injection attacks by controlling which resources the browser is allowed to load.',
    fix: "Add a Content-Security-Policy header. Start with a restrictive policy like `default-src 'self'` and loosen as needed.",
  },
  {
    header: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    description:
      'Strict-Transport-Security header is missing. HSTS forces browsers to use HTTPS, preventing protocol downgrade attacks and cookie hijacking.',
    fix: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS for one year.',
  },
  {
    header: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    description:
      'X-Content-Type-Options header is missing. This header prevents MIME-type sniffing, which can turn non-executable MIME types into executable ones.',
    fix: 'Add `X-Content-Type-Options: nosniff` to prevent browsers from MIME-sniffing the response.',
  },
  {
    header: 'x-frame-options',
    label: 'X-Frame-Options',
    description:
      'X-Frame-Options header is missing. This header prevents your site from being embedded in iframes, protecting against clickjacking attacks.',
    fix: 'Add `X-Frame-Options: DENY` (or SAMEORIGIN if you need to embed your own pages).',
  },
  {
    header: 'referrer-policy',
    label: 'Referrer-Policy',
    description:
      'Referrer-Policy header is missing. Without it, the browser may leak the full URL (including query parameters with sensitive data) to third-party sites.',
    fix: 'Add `Referrer-Policy: strict-origin-when-cross-origin` to limit referrer information sent to other origins.',
  },
  {
    header: 'permissions-policy',
    label: 'Permissions-Policy',
    description:
      'Permissions-Policy header is missing. This header controls which browser features (camera, microphone, geolocation) your site can use, reducing attack surface.',
    fix: 'Add a Permissions-Policy header disabling unused features. Example: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
  },
] as const;

/** Build a stack-aware AI prompt for missing headers */
function buildAiPrompt(missing: readonly string[], context: ScanContext): string {
  const headerList = missing.join(', ');
  const framework = context.stack.framework?.toLowerCase();

  if (framework === 'express' || framework === 'fastify' || framework === 'koa') {
    return `My ${framework} app is missing these security headers: ${headerList}. Install and configure helmet.js to add all recommended security headers. Show the middleware setup.`;
  }

  if (framework === 'next' || framework === 'nextjs') {
    return `My Next.js app is missing these security headers: ${headerList}. Add them using the headers() function in next.config.js. Show the full configuration.`;
  }

  return `My web app is missing these security headers: ${headerList}. Show how to configure my web server or framework to add each header with recommended values.`;
}

const headersCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [
      {
        id: CHECK_ID,
        name: 'Security headers skipped',
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: 'No URL provided — skipping HTTP security header check. Pass --url to enable.',
      },
    ];
  }

  const { response } = await fetchWithRetry(context.url);

  if (!response) {
    const hostname = safeHostname(context.url);
    return [
      {
        id: CHECK_ID,
        name: 'Security headers skipped',
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: `Could not connect to ${hostname} after 2 attempts. Skipping header check.`,
      },
    ];
  }

  if (response.status !== 200) {
    return [
      {
        id: CHECK_ID,
        name: 'Security headers skipped',
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: `Received HTTP ${response.status} from ${safeHostname(context.url)}. Skipping header check (expected 200).`,
      },
    ];
  }

  const missing: HeaderSpec[] = [];

  for (const spec of REQUIRED_HEADERS) {
    if (!response.headers.has(spec.header)) {
      missing.push(spec);
    }
  }

  if (missing.length === 0) {
    return [
      {
        id: CHECK_ID,
        name: 'All security headers present',
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        description: `All ${REQUIRED_HEADERS.length} recommended security headers are present.`,
      },
    ];
  }

  const aiPrompt = buildAiPrompt(
    missing.map((s) => s.label),
    context,
  );

  const results: CheckResult[] = missing.map((spec) => ({
    id: `${CHECK_ID}-${spec.header}`,
    name: `Missing ${spec.label}`,
    status: 'fail' as const,
    severity: 'high' as const,
    category: CATEGORY,
    location: context.url,
    description: spec.description,
    fix: spec.fix,
    aiPrompt,
  }));

  return results;
};

/** Safely extract hostname from a URL string */
function safeHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export default headersCheck;
