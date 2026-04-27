/**
 * Check: Server header information disclosure
 * Flags when the Server header reveals specific software and version info.
 */
import type { CheckFunction } from 'bastion-shared';
import { fetchWithRetry } from '../utils/fetch-with-retry.js';

const CHECK_ID = 'server-disclosure';
const CATEGORY = 'headers';

/** Patterns that indicate version-specific disclosure (name + version number) */
const VERSION_PATTERN = /\b(?:apache|nginx|iis|litespeed|openresty|tomcat|jetty|caddy|gunicorn|uwsgi|express|kestrel)\b.*?\d+/i;

/** Generic / CDN server values that are fine to expose */
const GENERIC_SERVERS = new Set([
  'cloudflare',
  'cloudfront',
  'vercel',
  'netlify',
  'akamaighost',
  'fastly',
  'gws',
  'gse',
  'fly.io',
]);

const serverDisclosureCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [{
      id: CHECK_ID,
      name: 'Server header disclosure',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'No URL provided — skipping server header check.',
    }];
  }

  const target = context.url.startsWith('http') ? context.url : `https://${context.url}`;
  const { response, error } = await fetchWithRetry(target, { redirect: 'follow' });

  if (!response) {
    return [{
      id: CHECK_ID,
      name: 'Server header disclosure',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: `Could not reach ${target}: ${error instanceof Error ? error.message : 'unknown error'}`,
    }];
  }

  const server = response.headers.get('server');

  if (!server) {
    return [{
      id: CHECK_ID,
      name: 'Server header disclosure',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: target,
      description: 'No Server header present — no information disclosed.',
    }];
  }

  const lower = server.toLowerCase().trim();

  // Generic CDN / platform names are fine
  if (GENERIC_SERVERS.has(lower)) {
    return [{
      id: CHECK_ID,
      name: 'Server header disclosure',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: target,
      description: `Server header is generic: "${server}". No version disclosed.`,
    }];
  }

  // Check for version-specific disclosure
  if (VERSION_PATTERN.test(server)) {
    return [{
      id: CHECK_ID,
      name: 'Server header disclosure',
      status: 'warn',
      severity: 'low',
      category: CATEGORY,
      location: target,
      description: `Server header reveals software and version: "${server}". Attackers can use this to target known vulnerabilities for that version.`,
      fix: 'Remove or genericize the Server header. In nginx: `server_tokens off;`. In Apache: `ServerTokens Prod`. In Express: `app.disable("x-powered-by")`.',
    }];
  }

  return [{
    id: CHECK_ID,
    name: 'Server header disclosure',
    status: 'pass',
    severity: 'info',
    category: CATEGORY,
    location: target,
    description: `Server header present ("${server}") but no specific version disclosed.`,
  }];
};

export default serverDisclosureCheck;
