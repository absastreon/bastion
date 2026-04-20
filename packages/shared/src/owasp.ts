/**
 * OWASP Top 10 2025 — educational data for the Bastion web dashboard.
 * Each category includes plain-language explanations, real-world examples,
 * prevention strategies, and AI prompts users can paste into their AI tool.
 */

/** A single OWASP Top 10 category with educational context */
export interface OwaspCategory {
  readonly id: string;
  readonly rank: number;
  readonly name: string;
  readonly description: string;
  readonly impact: string;
  readonly examples: readonly string[];
  readonly prevention: readonly string[];
  readonly personalQuestion: string;
  readonly aiPrompt: string;
}

/** OWASP Top 10 2025 — all 10 categories with full educational content */
export const OWASP_2025_TOP_10: readonly OwaspCategory[] = [
  {
    id: 'A01:2025',
    rank: 1,
    name: 'Broken Access Control',
    description: 'Users can act outside their intended permissions. This includes accessing other users\' data, modifying access rights, or bypassing access controls by tampering with URLs, API requests, or internal state.',
    impact: 'Attackers can view, modify, or delete data they shouldn\'t have access to. This is the #1 web application security risk.',
    examples: [
      'Changing /api/users/123 to /api/users/456 to access another user\'s profile',
      'A regular user accessing admin-only API endpoints by guessing the URL',
      'Manipulating JWT tokens to escalate privileges from user to admin',
      'Accessing API endpoints that don\'t verify the authenticated user owns the requested resource',
    ],
    prevention: [
      'Deny access by default — explicitly grant permissions rather than implicitly allowing',
      'Check resource ownership on every request (does this user own this record?)',
      'Use middleware to enforce role-based access on route groups',
      'Disable directory listing and ensure metadata files (.git, .env) aren\'t accessible',
      'Log and alert on repeated access control failures',
    ],
    personalQuestion: 'Can a logged-in user of your app access or modify another user\'s data by changing an ID in the URL?',
    aiPrompt: 'Audit my API routes for broken access control. For each endpoint that accesses user-specific data, verify that the authenticated user owns the requested resource. Show me any endpoints where a user could access another user\'s data by changing an ID parameter.',
  },
  {
    id: 'A02:2025',
    rank: 2,
    name: 'Cryptographic Failures',
    description: 'Sensitive data is exposed due to weak or missing encryption. This includes transmitting data in cleartext, using deprecated algorithms, or improperly managing cryptographic keys.',
    impact: 'Personal data, credentials, financial information, or health records can be stolen. May trigger regulatory penalties (GDPR, HIPAA).',
    examples: [
      'Storing passwords with MD5 or SHA-1 instead of bcrypt/argon2',
      'Transmitting sensitive data over HTTP instead of HTTPS',
      'Hardcoding encryption keys in source code',
      'Using Math.random() for security-sensitive operations instead of crypto.randomUUID()',
    ],
    prevention: [
      'Classify data by sensitivity and apply appropriate encryption',
      'Enforce HTTPS everywhere with HSTS headers',
      'Use bcrypt, scrypt, or argon2 for password hashing — never MD5 or SHA-1',
      'Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive randomness',
      'Rotate encryption keys regularly and store them in a secret manager',
    ],
    personalQuestion: 'Are you storing passwords with bcrypt/argon2 and transmitting all data over HTTPS?',
    aiPrompt: 'Review my application\'s cryptographic practices. Check password hashing algorithms, data transmission security, key management, and random number generation. Flag any use of weak algorithms or cleartext transmission.',
  },
  {
    id: 'A03:2025',
    rank: 3,
    name: 'Injection',
    description: 'User-supplied data is sent to an interpreter as part of a command or query without validation or sanitization. This includes SQL injection, NoSQL injection, OS command injection, and XSS.',
    impact: 'Attackers can read, modify, or delete database contents, execute system commands, or hijack user sessions through injected scripts.',
    examples: [
      'Building SQL queries with string concatenation: `SELECT * FROM users WHERE id = ${userId}`',
      'Using eval() or Function() with user input',
      'Rendering user input with innerHTML or dangerouslySetInnerHTML without sanitization',
      'Passing user input to child_process.exec() without escaping',
    ],
    prevention: [
      'Use parameterized queries or an ORM (Prisma, Drizzle) for all database operations',
      'Never use eval(), Function(), or child_process.exec() with user input',
      'Sanitize HTML with DOMPurify before rendering user-generated content',
      'Use a strict Content-Security-Policy to mitigate XSS impact',
      'Validate and sanitize all input at the API boundary with Zod or similar',
    ],
    personalQuestion: 'Are any of your database queries built by concatenating user input into the query string?',
    aiPrompt: 'Scan my codebase for injection vulnerabilities. Look for SQL string concatenation, eval() usage, innerHTML with user input, and unsanitized child_process calls. Show me safe alternatives for each finding.',
  },
  {
    id: 'A04:2025',
    rank: 4,
    name: 'Insecure Design',
    description: 'Security flaws baked into the design itself — not implementation bugs, but missing or ineffective security controls that should have been designed in from the start.',
    impact: 'No amount of perfect implementation can fix a fundamentally insecure design. These issues require architectural changes to resolve.',
    examples: [
      'A password reset flow that answers security questions (which are publicly discoverable)',
      'A checkout flow that trusts client-side price calculations without server validation',
      'An API that returns full user objects when only the name is needed (over-exposure)',
      'No rate limiting on authentication endpoints, allowing brute force attacks',
    ],
    prevention: [
      'Use threat modeling during design (STRIDE, attack trees)',
      'Design with the principle of least privilege — expose only what\'s needed',
      'Validate all business logic server-side, never trust client calculations',
      'Add rate limiting to all authentication and sensitive endpoints',
      'Write security user stories: "As an attacker, I want to..."',
    ],
    personalQuestion: 'Did you consider how an attacker might abuse your application\'s core workflows when designing them?',
    aiPrompt: 'Review my application\'s design for security flaws. Look at authentication flows, data exposure in API responses, trust boundaries between client and server, and missing security controls. Suggest architectural improvements.',
  },
  {
    id: 'A05:2025',
    rank: 5,
    name: 'Security Misconfiguration',
    description: 'Insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, or verbose error messages exposing sensitive information.',
    impact: 'Attackers can exploit default credentials, access unprotected admin panels, or gather intelligence from verbose error messages.',
    examples: [
      'Default admin credentials left unchanged (admin/admin)',
      'Stack traces and debug information shown in production error responses',
      'Unnecessary features enabled (directory listing, unused HTTP methods)',
      'S3 buckets or cloud storage with public read access',
    ],
    prevention: [
      'Remove or disable all unnecessary features, frameworks, and services',
      'Set environment-specific configs — never use development defaults in production',
      'Review cloud permissions with principle of least privilege',
      'Return generic error messages in production; log details server-side',
      'Automate configuration verification in CI/CD pipeline',
    ],
    personalQuestion: 'Are you running any default configurations or debug modes in production?',
    aiPrompt: 'Audit my application and infrastructure configuration for security misconfigurations. Check for default credentials, debug mode settings, verbose error handling, unnecessary exposed services, and cloud storage permissions.',
  },
  {
    id: 'A06:2025',
    rank: 6,
    name: 'Vulnerable and Outdated Components',
    description: 'Using libraries, frameworks, or dependencies with known vulnerabilities. This includes not patching, not tracking dependency versions, or using unmaintained packages.',
    impact: 'Attackers can exploit known CVEs in your dependencies. Supply chain attacks through compromised packages can affect millions of users.',
    examples: [
      'Using a version of lodash with known prototype pollution vulnerability',
      'Running an outdated version of Next.js with a known SSRF vulnerability',
      'Depending on an unmaintained package that hasn\'t been updated in 3 years',
      'Not running npm audit as part of the CI/CD pipeline',
    ],
    prevention: [
      'Run `npm audit` regularly and in CI/CD pipelines',
      'Enable Dependabot or Snyk for automated dependency updates',
      'Remove unused dependencies to reduce attack surface',
      'Pin dependency versions with a lockfile and use `npm ci` in CI',
      'Monitor security advisories for critical dependencies',
    ],
    personalQuestion: 'When was the last time you ran npm audit, and do you have automated dependency updates enabled?',
    aiPrompt: 'Analyze my package.json dependencies for security risks. Check for known vulnerabilities, outdated packages, unmaintained dependencies, and unnecessary packages. Recommend which to update, replace, or remove.',
  },
  {
    id: 'A07:2025',
    rank: 7,
    name: 'Identification and Authentication Failures',
    description: 'Weaknesses in authentication mechanisms that allow attackers to compromise passwords, keys, or session tokens, or to exploit flaws to assume other users\' identities.',
    impact: 'Account takeover, unauthorized access to user data, and identity theft.',
    examples: [
      'Allowing weak passwords (no minimum length or complexity requirements)',
      'Not implementing multi-factor authentication on sensitive operations',
      'Session tokens that don\'t expire or aren\'t invalidated on logout',
      'Building custom auth instead of using a proven provider (Clerk, Auth0, Supabase Auth)',
    ],
    prevention: [
      'Use an established authentication provider instead of rolling your own',
      'Enforce strong password policies (minimum 12 characters)',
      'Implement multi-factor authentication (MFA)',
      'Set session timeouts and invalidate tokens on logout',
      'Rate limit authentication endpoints to prevent brute force',
    ],
    personalQuestion: 'Are you using a proven auth provider, and do you have rate limiting on login endpoints?',
    aiPrompt: 'Review my authentication implementation for security issues. Check password policies, session management, MFA support, brute force protection, and whether I\'m using a proven auth provider or custom auth.',
  },
  {
    id: 'A08:2025',
    rank: 8,
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that doesn\'t protect against integrity violations. This includes using untrusted plugins, libraries, or CDNs without verification, and insecure CI/CD pipelines.',
    impact: 'Supply chain attacks, malicious code execution through compromised dependencies, and unauthorized modifications to application code or data.',
    examples: [
      'Loading JavaScript from CDNs without Subresource Integrity (SRI) hashes',
      'CI/CD pipeline that doesn\'t verify the integrity of build artifacts',
      'Auto-updating dependencies without review or testing',
      'Deserializing untrusted data without validation',
    ],
    prevention: [
      'Use Subresource Integrity (SRI) for all CDN-loaded scripts',
      'Verify digital signatures on packages and updates',
      'Review dependency changes before merging (use lockfile diffs)',
      'Secure CI/CD pipelines with least-privilege access and audit logs',
      'Use npm provenance and package signing where available',
    ],
    personalQuestion: 'Do you review dependency updates before merging, and are your CI/CD pipelines secured?',
    aiPrompt: 'Audit my project for software and data integrity risks. Check for CDN scripts without SRI, insecure CI/CD configuration, dependency auto-updates without review, and unsafe deserialization.',
  },
  {
    id: 'A09:2025',
    rank: 9,
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, monitoring, and alerting that prevents detection of active attacks, breaches, or suspicious activity.',
    impact: 'Attackers can maintain persistence, exfiltrate data, and tamper with systems undetected. Average breach detection time is 277 days without proper monitoring.',
    examples: [
      'No logging of authentication events (failed logins, password resets)',
      'Logs stored only locally where attackers can delete them',
      'No alerting on unusual patterns (spike in failed logins, new admin user)',
      'Sensitive data (passwords, tokens) included in log output',
    ],
    prevention: [
      'Log all authentication events, access control failures, and input validation errors',
      'Use structured logging with a centralized service (Axiom, Datadog, Sentry)',
      'Set up alerts for suspicious patterns (brute force, unusual access)',
      'Never log sensitive data (passwords, tokens, PII)',
      'Ensure logs are tamper-proof and retained for incident investigation',
    ],
    personalQuestion: 'Would you know if someone was trying to brute-force login to your application right now?',
    aiPrompt: 'Set up security logging and monitoring for my application. Show me how to log authentication events, set up alerts for suspicious activity, and integrate with a monitoring service. Ensure no sensitive data is logged.',
  },
  {
    id: 'A10:2025',
    rank: 10,
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'The application fetches a remote resource based on a user-supplied URL without validating the destination. Attackers can coerce the server to make requests to internal services.',
    impact: 'Access to internal services, cloud metadata endpoints (169.254.169.254), internal APIs, and potentially remote code execution.',
    examples: [
      'A URL preview feature that fetches any URL, including internal IPs (127.0.0.1, 10.x.x.x)',
      'An image proxy that fetches user-supplied URLs without allowlisting',
      'A webhook receiver that follows redirects to internal services',
      'PDF generators that render user-supplied HTML with external resource loading',
    ],
    prevention: [
      'Validate and sanitize all user-supplied URLs',
      'Use an allowlist of permitted domains and protocols',
      'Block requests to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16)',
      'Don\'t follow HTTP redirects from user-supplied URLs',
      'Use network-level segmentation to limit server-side request scope',
    ],
    personalQuestion: 'Does your application fetch any URLs based on user input, and if so, do you validate the destination?',
    aiPrompt: 'Scan my application for SSRF vulnerabilities. Find any endpoints that fetch URLs based on user input and show me how to add proper URL validation, allowlisting, and private IP blocking.',
  },
];
