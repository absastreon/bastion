/**
 * Check registry — all check modules are imported and listed here.
 * When adding a new check, import it and append to the array.
 */
import type { CheckFunction } from '@bastion/shared';
import gitignoreCheck from './gitignore.js';
import secretsCheck from './secrets.js';
import dependencyCheck from './dependencies.js';
import envExampleCheck from './env-example.js';
import securityTxtCheck from './security-txt.js';
import headersCheck from './headers.js';
import securityTxtUrlCheck from './security-txt-url.js';
import sslCheck from './ssl.js';
import codePatternCheck from './code-patterns.js';
import corsCheck from './cors.js';
import rateLimitCheck from './rate-limit.js';
import authCheck from './auth.js';
import cookieCheck from './cookies.js';
import serverDisclosureCheck from './server-disclosure.js';
import dmarcCheck from './dmarc.js';

/** Return all registered check functions */
export function getAllChecks(): readonly CheckFunction[] {
  return [
    gitignoreCheck,
    secretsCheck,
    dependencyCheck,
    envExampleCheck,
    securityTxtCheck,
    headersCheck,
    securityTxtUrlCheck,
    sslCheck,
    codePatternCheck,
    corsCheck,
    rateLimitCheck,
    authCheck,
    cookieCheck,
    serverDisclosureCheck,
    dmarcCheck,
  ];
}

/** Return only HTTP-relevant checks for URL-only scans */
export function getUrlOnlyChecks(): readonly CheckFunction[] {
  return [headersCheck, sslCheck, securityTxtUrlCheck, cookieCheck, serverDisclosureCheck, dmarcCheck];
}
