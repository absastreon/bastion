/**
 * Check: DMARC DNS record
 * Looks up _dmarc.{domain} TXT record to verify email authentication policy.
 */
import { resolveTxt } from 'node:dns/promises';
import type { CheckFunction } from 'bastion-shared';

const CHECK_ID = 'dmarc';
const CATEGORY = 'email';

/** Extract the domain from a URL string */
function extractDomain(url: string): string {
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    return parsed.hostname;
  } catch {
    return url;
  }
}

const dmarcCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [{
      id: CHECK_ID,
      name: 'DMARC record',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: 'No URL provided — skipping DMARC check.',
    }];
  }

  const domain = extractDomain(context.url);
  const dmarcHost = `_dmarc.${domain}`;

  let records: string[][];
  try {
    records = await resolveTxt(dmarcHost);
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'SERVFAIL') {
      return [{
        id: CHECK_ID,
        name: 'DMARC record',
        status: 'warn',
        severity: 'medium',
        category: CATEGORY,
        location: dmarcHost,
        description: `No DMARC record found for ${domain}. Without DMARC, attackers can spoof emails from your domain to phish your users.`,
        fix: `Add a TXT record at _dmarc.${domain} with value: "v=DMARC1; p=reject; rua=mailto:dmarc@${domain}"`,
      }];
    }
    return [{
      id: CHECK_ID,
      name: 'DMARC record',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      description: `DNS lookup failed for ${dmarcHost}: ${err instanceof Error ? err.message : 'unknown error'}`,
    }];
  }

  // Join TXT record chunks and find the DMARC record
  const flat = records.map(chunks => chunks.join(''));
  const dmarc = flat.find(r => r.toLowerCase().startsWith('v=dmarc1'));

  if (!dmarc) {
    return [{
      id: CHECK_ID,
      name: 'DMARC record',
      status: 'warn',
      severity: 'medium',
      category: CATEGORY,
      location: dmarcHost,
      description: `TXT records exist at ${dmarcHost} but no valid DMARC record (must start with "v=DMARC1").`,
      fix: `Add a TXT record at _dmarc.${domain} with value: "v=DMARC1; p=reject; rua=mailto:dmarc@${domain}"`,
    }];
  }

  // Parse policy
  const policyMatch = dmarc.match(/;\s*p\s*=\s*(reject|quarantine|none)/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase() : 'unknown';

  if (policy === 'reject') {
    return [{
      id: CHECK_ID,
      name: 'DMARC record',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: dmarcHost,
      description: `DMARC record found with p=reject — the strongest policy. Spoofed emails from ${domain} will be rejected.`,
    }];
  }

  if (policy === 'quarantine') {
    return [{
      id: CHECK_ID,
      name: 'DMARC record',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: dmarcHost,
      description: `DMARC record found with p=quarantine. Spoofed emails may be delivered to spam. Consider upgrading to p=reject.`,
    }];
  }

  return [{
    id: CHECK_ID,
    name: 'DMARC record',
    status: 'warn',
    severity: 'low',
    category: CATEGORY,
    location: dmarcHost,
    description: `DMARC record found but policy is p=${policy}. This only monitors — it does not prevent email spoofing.`,
    fix: `Upgrade your DMARC policy to p=quarantine or p=reject once you have verified legitimate email sources are aligned.`,
  }];
};

export default dmarcCheck;
