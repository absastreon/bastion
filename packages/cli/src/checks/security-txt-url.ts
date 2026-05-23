/**
 * Check: security.txt via URL
 * Fetches /.well-known/security.txt and /security.txt from a remote URL,
 * validates required fields (Contact, Expires) per RFC 9116.
 * URL-based counterpart to F009's file-based check.
 */
import type { CheckFunction, CheckResult } from '@bastion/shared';
import { fetchWithRetry } from '../utils/fetch-with-retry.js';

const CHECK_ID = 'security-txt-url';
const PATHS = ['/.well-known/security.txt', '/security.txt'] as const;

/** Parse key-value fields from security.txt content (case-insensitive keys) */
function parseFields(content: string): ReadonlyMap<string, readonly string[]> {
  const fields = new Map<string, string[]>();

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('-----')) continue;

    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) continue;

    const key = trimmed.slice(0, colonIndex).trim().toLowerCase();
    const value = trimmed.slice(colonIndex + 1).trim();
    if (value === '') continue;

    const existing = fields.get(key);
    fields.set(key, existing ? [...existing, value] : [value]);
  }

  return fields;
}

/** Check if an Expires date string is in the past */
function isExpired(value: string): boolean {
  const date = new Date(value);
  return !isNaN(date.getTime()) && date.getTime() < Date.now();
}

/** Fetch security.txt from a URL with retry on connection failure; returns body or null */
async function fetchSecurityTxt(url: string): Promise<string | null> {
  const { response } = await fetchWithRetry(url);

  if (!response || !response.ok) return null;

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('text/plain')) return null;

  return await response.text();
}

/** Validate parsed fields and return check results */
function validateFields(
  fields: ReadonlyMap<string, readonly string[]>,
  location: string,
): readonly CheckResult[] {
  const results: CheckResult[] = [];

  const hasContact = (fields.get('contact') ?? []).length > 0;
  const firstExpires = (fields.get('expires') ?? [])[0];
  const hasExpires = firstExpires !== undefined;

  if (!hasContact) {
    results.push({
      id: `${CHECK_ID}-contact`,
      name: 'security.txt missing Contact field',
      status: 'fail',
      severity: 'medium',
      category: 'disclosure',
      location,
      description:
        'security.txt is missing the required Contact field. Security researchers need a way to reach you.',
      fix: 'Add a Contact field to your security.txt. Example: Contact: mailto:security@example.com. See https://securitytxt.org/',
      aiPrompt:
        'My security.txt file is missing the required Contact field. Add a Contact field with my security email address using mailto: URI format per RFC 9116.',
    });
  }

  if (!hasExpires) {
    results.push({
      id: `${CHECK_ID}-expires`,
      name: 'security.txt missing Expires field',
      status: 'fail',
      severity: 'medium',
      category: 'disclosure',
      location,
      description:
        'security.txt is missing the required Expires field. This field ensures the information stays current.',
      fix: 'Add an Expires field with a date no more than 1 year in the future. Example: Expires: 2027-12-31T23:59:59.000Z. See https://securitytxt.org/',
      aiPrompt:
        'My security.txt file is missing the required Expires field. Add an Expires field set to one year from today in ISO 8601 date-time format per RFC 9116.',
    });
  } else if (isExpired(firstExpires)) {
    results.push({
      id: `${CHECK_ID}-expired`,
      name: 'security.txt has expired',
      status: 'warn',
      severity: 'medium',
      category: 'disclosure',
      location,
      description: `security.txt Expires date (${firstExpires}) is in the past. An expired security.txt signals the contact information may be stale.`,
      fix: 'Update the Expires field to a future date, no more than 1 year ahead. Use the generator at https://securitytxt.org/',
      aiPrompt:
        'My security.txt Expires field is in the past. Update it to one year from today in ISO 8601 date-time format. Also review the Contact field to ensure it is still accurate.',
    });
  }

  if (hasContact && hasExpires && !isExpired(firstExpires)) {
    results.push({
      id: CHECK_ID,
      name: 'security.txt is valid (via URL)',
      status: 'pass',
      severity: 'info',
      category: 'disclosure',
      location,
      description: 'security.txt found via URL with required Contact and Expires fields.',
    });
  }

  return results;
}

const securityTxtUrlCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [
      {
        id: CHECK_ID,
        name: 'security.txt URL check skipped',
        status: 'skip',
        severity: 'info',
        category: 'disclosure',
        description: 'No URL provided — skipping remote security.txt check.',
      },
    ];
  }

  const base = context.url.replace(/\/+$/, '');

  for (const path of PATHS) {
    const url = `${base}${path}`;
    const body = await fetchSecurityTxt(url);
    if (body !== null) {
      return validateFields(parseFields(body), url);
    }
  }

  return [
    {
      id: CHECK_ID,
      name: 'security.txt not found via URL',
      status: 'fail',
      severity: 'medium',
      category: 'disclosure',
      description: `No security.txt found at ${base}${PATHS[0]} or ${base}${PATHS[1]}. A security.txt file tells researchers how to report vulnerabilities.`,
      fix: 'Create a security.txt file and serve it at /.well-known/security.txt. Use the generator at https://securitytxt.org/',
      aiPrompt:
        'Generate a security.txt file for my project following RFC 9116. Include Contact (use my email: [YOUR_EMAIL]), Expires (1 year from now), and Preferred-Languages fields. Serve it at /.well-known/security.txt.',
    },
  ];
};

export default securityTxtUrlCheck;
