/**
 * Check: Cookie security flags
 * Inspects Set-Cookie headers for HttpOnly, Secure, and SameSite attributes.
 */
import type { CheckFunction, CheckResult } from 'bastion-shared';
import { fetchWithRetry } from '../utils/fetch-with-retry.js';

const CHECK_ID = 'cookies';
const CATEGORY = 'cookies';

/** Parse a Set-Cookie header and return the cookie name + which flags are present */
function parseCookie(raw: string): { name: string; httpOnly: boolean; secure: boolean; sameSite: boolean } {
  const name = raw.split('=')[0].trim();
  const lower = raw.toLowerCase();
  return {
    name,
    httpOnly: lower.includes('httponly'),
    secure: lower.includes('secure'),
    sameSite: lower.includes('samesite'),
  };
}

const cookieCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [{
      id: CHECK_ID,
      name: 'Cookie security flags',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'No URL provided — skipping cookie flag check.',
    }];
  }

  const target = context.url.startsWith('http') ? context.url : `https://${context.url}`;
  const { response, error } = await fetchWithRetry(target, { redirect: 'follow' });

  if (!response) {
    return [{
      id: CHECK_ID,
      name: 'Cookie security flags',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: `Could not reach ${target}: ${error instanceof Error ? error.message : 'unknown error'}`,
    }];
  }

  // Collect all Set-Cookie headers
  const setCookies: string[] = [];
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      setCookies.push(value);
    }
  });

  // fetch() merges multiple Set-Cookie headers — split on comma followed by a cookie-name pattern
  const expanded: string[] = [];
  for (const raw of setCookies) {
    // Split on ", <word>=" but not inside expires date values
    const parts = raw.split(/,\s*(?=[a-zA-Z_][a-zA-Z0-9_]*=)/);
    expanded.push(...parts);
  }

  if (expanded.length === 0) {
    return [{
      id: CHECK_ID,
      name: 'Cookie security flags',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: target,
      description: 'No cookies set — nothing to check.',
    }];
  }

  const results: CheckResult[] = [];

  for (const raw of expanded) {
    const cookie = parseCookie(raw);
    if (!cookie.name) continue;

    const missing: string[] = [];
    if (!cookie.httpOnly) missing.push('HttpOnly');
    if (!cookie.secure) missing.push('Secure');
    if (!cookie.sameSite) missing.push('SameSite');

    if (missing.length === 0) {
      results.push({
        id: CHECK_ID,
        name: `Cookie: ${cookie.name}`,
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        location: target,
        description: `Cookie "${cookie.name}" has all recommended security flags.`,
      });
    } else {
      const hasHttpOnlyOrSecure = missing.includes('HttpOnly') || missing.includes('Secure');
      results.push({
        id: CHECK_ID,
        name: `Cookie: ${cookie.name}`,
        status: 'warn',
        severity: hasHttpOnlyOrSecure ? 'medium' : 'low',
        category: CATEGORY,
        location: target,
        description: `Cookie "${cookie.name}" is missing: ${missing.join(', ')}. ${!cookie.httpOnly ? 'Without HttpOnly, JavaScript can access this cookie (XSS risk). ' : ''}${!cookie.secure ? 'Without Secure, the cookie may be sent over plain HTTP. ' : ''}${!cookie.sameSite ? 'Without SameSite, the cookie is vulnerable to CSRF attacks.' : ''}`,
        fix: `Add the missing flags: Set-Cookie: ${cookie.name}=...; ${missing.join('; ')}`,
      });
    }
  }

  if (results.length === 0) {
    return [{
      id: CHECK_ID,
      name: 'Cookie security flags',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: target,
      description: 'No cookies set — nothing to check.',
    }];
  }

  return results;
};

export default cookieCheck;
