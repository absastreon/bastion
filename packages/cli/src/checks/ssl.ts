/**
 * Check: SSL/TLS — verify HTTPS usage, certificate validity, and HTTP→HTTPS redirect
 */
import { connect as tlsConnect } from 'node:tls';
import { request as httpRequest } from 'node:http';
import type { CheckFunction, CheckResult } from '@bastion/shared';

const CHECK_ID = 'ssl';
const CATEGORY = 'transport';
const TIMEOUT_MS = 10_000;

/** Error with optional Node.js error code */
interface NodeError extends Error {
  readonly code?: string;
}

/** Known TLS error codes and user-friendly descriptions */
const CERT_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  CERT_HAS_EXPIRED: 'SSL certificate has expired',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'Self-signed certificate (not trusted by browsers)',
  SELF_SIGNED_CERT_IN_CHAIN: 'Self-signed certificate in the certificate chain',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'Unable to verify the certificate',
  ERR_TLS_CERT_ALTNAME_INVALID: 'Certificate hostname does not match the domain',
};

/** Error codes that indicate a connectivity problem, not a certificate issue */
const CONNECTION_ERRORS = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EHOSTUNREACH',
]);

/** Connect via TLS and verify the certificate is valid and trusted */
function verifyCertificate(hostname: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tlsConnect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: true },
      () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve();
      },
    );
    socket.setTimeout(TIMEOUT_MS);
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(Object.assign(new Error('Connection timed out'), { code: 'ETIMEDOUT' }));
    });
    socket.on('error', (err: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    });
  });
}

/** Make an HTTP HEAD request and check if the response redirects to HTTPS */
function checkHttpsRedirect(hostname: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const req = httpRequest(
      { hostname, port: 80, method: 'HEAD', path: '/' },
      (res) => {
        if (settled) return;
        settled = true;
        const status = res.statusCode ?? 0;
        const location = res.headers.location ?? '';
        const isRedirect = status >= 300 && status < 400;
        resolve(isRedirect && location.startsWith('https://'));
      },
    );
    req.setTimeout(TIMEOUT_MS);
    req.on('timeout', () => {
      if (settled) return;
      settled = true;
      resolve(false);
      req.destroy();
    });
    req.on('error', () => {
      if (settled) return;
      settled = true;
      resolve(false);
    });
    req.end();
  });
}

const RETRY_DELAY_MS = 2_000;

/** Wait for a given number of milliseconds */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Verify certificate with a single retry on connection failure */
async function verifyCertificateWithRetry(
  hostname: string,
  port: number,
): Promise<void> {
  try {
    await verifyCertificate(hostname, port);
  } catch (error: unknown) {
    const code = error instanceof Error ? (error as NodeError).code ?? '' : '';
    if (CONNECTION_ERRORS.has(code)) {
      await delay(RETRY_DELAY_MS);
      await verifyCertificate(hostname, port);
    } else {
      throw error;
    }
  }
}

/** Build a CheckResult for a certificate verification failure */
function buildCertErrorResult(error: NodeError, hostname: string): CheckResult {
  const code = error.code ?? '';

  if (CONNECTION_ERRORS.has(code)) {
    return {
      id: `${CHECK_ID}-cert`,
      name: 'SSL certificate could not be verified',
      status: 'skip',
      severity: 'info',
      category: CATEGORY,
      location: hostname,
      description: `Could not connect to ${hostname} after 2 attempts. Skipping SSL certificate check.`,
    };
  }

  const message =
    CERT_ERROR_MESSAGES[code] ?? `Certificate verification failed: ${error.message}`;

  return {
    id: `${CHECK_ID}-cert`,
    name: 'Invalid SSL certificate',
    status: 'fail',
    severity: 'critical',
    category: CATEGORY,
    location: hostname,
    description: `${message} for ${hostname}. Visitors will see a browser warning and their data may be intercepted.`,
    fix: "Obtain a valid TLS certificate. Let's Encrypt provides free certificates via Certbot.",
    aiPrompt: `My website ${hostname} has an SSL/TLS certificate error: "${message}". Help me fix this by setting up a valid certificate using Let's Encrypt and Certbot. Show me how to install Certbot, obtain a certificate for my domain, and configure automatic renewal.`,
  };
}

const sslCheck: CheckFunction = async (context) => {
  if (!context.url) {
    return [
      {
        id: CHECK_ID,
        name: 'SSL/TLS check',
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: 'No URL provided — skipping SSL/TLS verification.',
      },
    ];
  }

  let parsed: URL;
  try {
    parsed = new URL(context.url);
  } catch {
    return [
      {
        id: CHECK_ID,
        name: 'SSL/TLS check',
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: `Invalid URL "${context.url}" — skipping SSL/TLS verification.`,
      },
    ];
  }

  const { hostname } = parsed;
  const isHttps = parsed.protocol === 'https:';
  const results: CheckResult[] = [];

  // 1. Fail if URL uses HTTP instead of HTTPS
  if (!isHttps) {
    results.push({
      id: `${CHECK_ID}-no-https`,
      name: 'URL does not use HTTPS',
      status: 'fail',
      severity: 'critical',
      category: CATEGORY,
      location: context.url,
      description: `${context.url} uses plain HTTP. All traffic is unencrypted, exposing user data to interception.`,
      fix: "Configure your server to use HTTPS. Let's Encrypt provides free TLS certificates via Certbot.",
      aiPrompt:
        "My website is served over HTTP without SSL/TLS encryption. Help me set up HTTPS using Let's Encrypt and Certbot. Show me the steps to obtain a free TLS certificate, configure my web server (Nginx/Apache/Node.js), and enable automatic renewal.",
    });
  }

  // 2. Verify SSL certificate (only for HTTPS URLs)
  if (isHttps) {
    const port = parsed.port ? parseInt(parsed.port, 10) : 443;
    try {
      await verifyCertificateWithRetry(hostname, port);
      results.push({
        id: `${CHECK_ID}-cert`,
        name: 'SSL certificate is valid',
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        location: hostname,
        description: `SSL/TLS certificate for ${hostname} is valid and trusted.`,
      });
    } catch (error: unknown) {
      results.push(
        error instanceof Error
          ? buildCertErrorResult(error as NodeError, hostname)
          : {
              id: `${CHECK_ID}-cert`,
              name: 'SSL certificate verification failed',
              status: 'skip',
              severity: 'info',
              category: CATEGORY,
              location: hostname,
              description: `Could not verify SSL certificate for ${hostname}.`,
            },
      );
    }
  }

  // 3. Check HTTP → HTTPS redirect
  const redirects = await checkHttpsRedirect(hostname);
  if (redirects) {
    results.push({
      id: `${CHECK_ID}-redirect`,
      name: 'HTTP redirects to HTTPS',
      status: 'pass',
      severity: 'info',
      category: CATEGORY,
      location: hostname,
      description: `HTTP requests to ${hostname} are redirected to HTTPS.`,
    });
  } else {
    results.push({
      id: `${CHECK_ID}-redirect`,
      name: 'No HTTP to HTTPS redirect',
      status: 'fail',
      severity: 'medium',
      category: CATEGORY,
      location: hostname,
      description: `HTTP requests to ${hostname} are not redirected to HTTPS. Users who type the URL without https:// will use an insecure connection.`,
      fix: 'Configure your web server to return a 301 redirect from HTTP to HTTPS for all requests.',
      aiPrompt: `My website ${hostname} does not redirect HTTP to HTTPS. Help me configure a permanent 301 redirect from HTTP to HTTPS on my web server. Show me configurations for Nginx, Apache, and common hosting platforms.`,
    });
  }

  return results;
};

export default sslCheck;
