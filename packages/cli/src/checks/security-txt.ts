/**
 * Check: security.txt and SECURITY.md existence
 * Verifies the project has a security disclosure policy.
 * If security.txt exists, validates required fields (Contact, Expires) per RFC 9116.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, CheckResult } from 'bastion-shared';

/** Paths where security.txt can be located (preferred order) */
const SECURITY_TXT_PATHS = ['.well-known/security.txt', 'security.txt'] as const;

const SECURITY_MD = 'SECURITY.md';
const CHECK_ID = 'security-txt';

/** Parse key-value fields from a security.txt file (case-insensitive keys) */
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

/** Build the results when security.txt content is validated */
function validateSecurityTxt(
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
      fix: 'Add a Contact field to your security.txt. Example: Contact: mailto:security@example.com',
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
      fix: 'Add an Expires field with a date no more than 1 year in the future. Example: Expires: 2027-12-31T23:59:59.000Z',
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
      name: 'security.txt is valid',
      status: 'pass',
      severity: 'info',
      category: 'disclosure',
      location,
      description: 'security.txt exists with required Contact and Expires fields.',
    });
  }

  return results;
}

const securityTxtCheck: CheckFunction = async (context) => {
  const securityTxtFile = SECURITY_TXT_PATHS.find((p) => context.files.includes(p));
  const hasSecurityMd = context.files.includes(SECURITY_MD);

  // Neither exists
  if (!securityTxtFile && !hasSecurityMd) {
    return [
      {
        id: CHECK_ID,
        name: 'Security policy missing',
        status: 'fail',
        severity: 'medium',
        category: 'disclosure',
        description:
          'No security.txt or SECURITY.md found. A security disclosure policy tells researchers how to report vulnerabilities.',
        fix: 'Create .well-known/security.txt with Contact and Expires fields. Use the generator at https://securitytxt.org/',
        aiPrompt:
          'Generate a security.txt file for my project following RFC 9116. Include Contact (use my email: [YOUR_EMAIL]), Expires (1 year from now), and Preferred-Languages fields. Place it at .well-known/security.txt. Also create a SECURITY.md with a vulnerability disclosure policy.',
      },
    ];
  }

  const results: CheckResult[] = [];

  // Validate security.txt content
  if (securityTxtFile) {
    try {
      const content = await readFile(join(context.projectPath, securityTxtFile), 'utf-8');
      results.push(...validateSecurityTxt(parseFields(content), securityTxtFile));
    } catch {
      results.push({
        id: CHECK_ID,
        name: 'security.txt unreadable',
        status: 'skip',
        severity: 'info',
        category: 'disclosure',
        location: securityTxtFile,
        description: `Could not read ${securityTxtFile}. Skipping validation.`,
      });
    }
  }

  if (hasSecurityMd) {
    results.push({
      id: `${CHECK_ID}-md`,
      name: 'SECURITY.md exists',
      status: 'pass',
      severity: 'info',
      category: 'disclosure',
      location: SECURITY_MD,
      description: 'SECURITY.md found — vulnerability disclosure policy is documented.',
    });
  }

  return results;
};

export default securityTxtCheck;
