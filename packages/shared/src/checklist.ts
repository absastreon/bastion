/**
 * Security checklist items — the core Bastion checklist for AI-era builders.
 * Used by the web dashboard's interactive checklist page.
 */

import type { Severity } from './types.js';

/** A single security checklist item with educational context */
export interface ChecklistItem {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: 'secrets' | 'dependencies' | 'headers' | 'auth' | 'code' | 'infra' | 'monitoring';
  readonly howToFix: string;
  readonly aiPrompt: string;
}

/** All 20 security checklist items */
export const SECURITY_CHECKLIST: readonly ChecklistItem[] = [
  {
    id: 'CL-001',
    title: '.gitignore covers sensitive files',
    description: 'Verify .env, node_modules, .next, dist, *.pem, and *.key are excluded from version control.',
    severity: 'critical',
    category: 'secrets',
    howToFix: 'Add missing patterns to your .gitignore file. If secrets were already committed, rotate them immediately — git history retains deleted files.',
    aiPrompt: 'Review my .gitignore file and list any sensitive file patterns I\'m missing. Include patterns for environment files, private keys, build outputs, and IDE configs.',
  },
  {
    id: 'CL-002',
    title: 'No hardcoded secrets in source code',
    description: 'Scan for API keys (OpenAI, Stripe, AWS), database URIs, Bearer tokens, and generic secrets in source files.',
    severity: 'critical',
    category: 'secrets',
    howToFix: 'Move all secrets to environment variables. Use a .env file locally and your platform\'s secret manager in production. Rotate any keys that were committed.',
    aiPrompt: 'Scan my codebase for hardcoded API keys, tokens, passwords, and database URIs. Show me how to replace each one with an environment variable.',
  },
  {
    id: 'CL-003',
    title: 'Dependencies audited for vulnerabilities',
    description: 'Run npm audit (or equivalent) to check for known vulnerabilities in third-party packages.',
    severity: 'high',
    category: 'dependencies',
    howToFix: 'Run `npm audit fix` for automatic patches. For breaking changes, evaluate the advisory and update manually. Consider using Snyk or Dependabot for continuous monitoring.',
    aiPrompt: 'I ran npm audit and found vulnerabilities. Help me understand which ones are exploitable in my context and prioritize which to fix first.',
  },
  {
    id: 'CL-004',
    title: '.env.example documents required variables',
    description: 'A .env.example file exists with placeholder values so new developers know which environment variables to set.',
    severity: 'medium',
    category: 'secrets',
    howToFix: 'Create a .env.example file listing every environment variable your app needs. Use placeholder values like YOUR_API_KEY_HERE — never real secrets.',
    aiPrompt: 'Generate a .env.example file for my project. List all environment variables used in the codebase with placeholder values and comments explaining each one.',
  },
  {
    id: 'CL-005',
    title: 'security.txt exists and is valid',
    description: 'A security.txt file (RFC 9116) with Contact and Expires fields exists at /.well-known/security.txt.',
    severity: 'medium',
    category: 'infra',
    howToFix: 'Create a /.well-known/security.txt file with at minimum a Contact field (email or URL) and an Expires field (ISO 8601 date within one year).',
    aiPrompt: 'Generate a valid security.txt file following RFC 9116 for my project. Include Contact, Expires, Preferred-Languages, and Policy fields.',
  },
  {
    id: 'CL-006',
    title: 'SECURITY.md defines vulnerability disclosure policy',
    description: 'A SECURITY.md file documents how to report security vulnerabilities in your project.',
    severity: 'medium',
    category: 'infra',
    howToFix: 'Create a SECURITY.md with: supported versions, how to report vulnerabilities, expected response timeline, and your security contact.',
    aiPrompt: 'Write a SECURITY.md for my project that includes supported versions, vulnerability reporting instructions, and expected response times.',
  },
  {
    id: 'CL-007',
    title: 'HTTP security headers configured',
    description: 'Verify Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy are set.',
    severity: 'high',
    category: 'headers',
    howToFix: 'Use helmet.js (Express/Fastify) or next.config.js headers (Next.js) to set security headers. Start with a strict CSP and relax as needed.',
    aiPrompt: 'Configure all recommended security headers for my application. Generate the exact configuration code for my framework with explanations for each header.',
  },
  {
    id: 'CL-008',
    title: 'SSL/TLS properly configured',
    description: 'HTTPS is enforced with a valid certificate. HTTP requests redirect to HTTPS. TLS 1.2+ is required.',
    severity: 'critical',
    category: 'infra',
    howToFix: 'Enable HTTPS on your hosting platform. Most platforms (Vercel, Netlify, Railway) handle this automatically. For custom servers, use Let\'s Encrypt.',
    aiPrompt: 'Help me configure SSL/TLS for my deployment. Ensure HTTPS redirect, valid certificate, and TLS 1.2 minimum. Show me how to verify the configuration.',
  },
  {
    id: 'CL-009',
    title: 'CORS restricts allowed origins',
    description: 'Cross-Origin Resource Sharing is configured with specific allowed origins — not wildcard (*).',
    severity: 'high',
    category: 'headers',
    howToFix: 'Replace `Access-Control-Allow-Origin: *` with a whitelist of trusted origins. Be specific about allowed methods and headers.',
    aiPrompt: 'Configure CORS for my API to allow only my frontend origin. Show me the correct setup for my framework with credentials support.',
  },
  {
    id: 'CL-010',
    title: 'Rate limiting enabled on API endpoints',
    description: 'API routes have rate limiting to prevent abuse, brute force attacks, and denial of service.',
    severity: 'high',
    category: 'auth',
    howToFix: 'Add express-rate-limit (Express), @fastify/rate-limit (Fastify), or @upstash/ratelimit (serverless). Start with 100 requests per 15 minutes per IP.',
    aiPrompt: 'Add rate limiting to my API endpoints. Configure appropriate limits for authentication routes (stricter) and general API routes. Show the implementation for my framework.',
  },
  {
    id: 'CL-011',
    title: 'Authentication uses established provider',
    description: 'Auth is handled by a proven provider (Clerk, Supabase Auth, NextAuth, Auth0) rather than custom implementation.',
    severity: 'high',
    category: 'auth',
    howToFix: 'Integrate an established auth provider instead of building custom auth. Supabase Auth, Clerk, and NextAuth are popular choices with built-in security best practices.',
    aiPrompt: 'Help me integrate authentication using a managed provider. Compare Clerk, Supabase Auth, and NextAuth for my use case and show me how to set up the best fit.',
  },
  {
    id: 'CL-012',
    title: 'Input validation on all user-facing endpoints',
    description: 'All API endpoints and form handlers validate input using schema-based validation (Zod, Joi, etc.).',
    severity: 'high',
    category: 'code',
    howToFix: 'Add Zod schemas for all API route handlers and form submissions. Validate request body, query params, and URL params before processing.',
    aiPrompt: 'Add input validation to my API routes using Zod. Generate schemas for each endpoint based on the expected data shape and add proper error responses.',
  },
  {
    id: 'CL-013',
    title: 'No SQL injection vectors',
    description: 'Database queries use parameterized queries or an ORM — never string concatenation with user input.',
    severity: 'critical',
    category: 'code',
    howToFix: 'Replace string-concatenated SQL queries with parameterized queries. Use an ORM like Prisma or Drizzle. Never interpolate user input into query strings.',
    aiPrompt: 'Find all database queries in my codebase and convert any that use string concatenation to parameterized queries. Show me the before and after for each.',
  },
  {
    id: 'CL-014',
    title: 'No XSS vulnerabilities',
    description: 'User input is sanitized before rendering. No use of dangerouslySetInnerHTML or innerHTML with untrusted data.',
    severity: 'critical',
    category: 'code',
    howToFix: 'Remove dangerouslySetInnerHTML where possible. If HTML rendering is needed, use DOMPurify to sanitize input. Set a strict Content-Security-Policy.',
    aiPrompt: 'Audit my frontend code for XSS vulnerabilities. Find any use of innerHTML, dangerouslySetInnerHTML, or unsanitized user input in templates and show me safe alternatives.',
  },
  {
    id: 'CL-015',
    title: 'CSRF protection enabled',
    description: 'State-changing requests are protected against Cross-Site Request Forgery with tokens or SameSite cookies.',
    severity: 'high',
    category: 'auth',
    howToFix: 'Use SameSite=Strict or SameSite=Lax cookies. For traditional forms, add CSRF tokens. Next.js Server Actions have built-in CSRF protection.',
    aiPrompt: 'Add CSRF protection to my application. Show me how to implement it for my framework, covering both API routes and form submissions.',
  },
  {
    id: 'CL-016',
    title: 'Content Security Policy configured',
    description: 'A Content-Security-Policy header is set with appropriate directives to prevent XSS and data injection.',
    severity: 'high',
    category: 'headers',
    howToFix: 'Start with a strict CSP: `default-src \'self\'; script-src \'self\'`. Add exceptions as needed for CDNs, analytics, etc. Use report-uri for monitoring.',
    aiPrompt: 'Create a Content-Security-Policy for my application. Analyze my frontend dependencies and generate a CSP that\'s as strict as possible while allowing required resources.',
  },
  {
    id: 'CL-017',
    title: 'Error messages don\'t leak sensitive data',
    description: 'API error responses show user-friendly messages, not stack traces, database queries, or internal paths.',
    severity: 'medium',
    category: 'code',
    howToFix: 'Add a global error handler that returns generic messages in production. Log detailed errors server-side. Never expose stack traces, SQL queries, or file paths.',
    aiPrompt: 'Add a global error handler to my API that returns safe, user-friendly error messages in production while logging full details server-side.',
  },
  {
    id: 'CL-018',
    title: 'API keys stored in environment variables',
    description: 'All API keys, database credentials, and third-party tokens are loaded from environment variables, not source code.',
    severity: 'critical',
    category: 'secrets',
    howToFix: 'Move all credentials to environment variables. Use your platform\'s secret management (Vercel env vars, Railway variables, AWS Secrets Manager).',
    aiPrompt: 'Audit my codebase for hardcoded credentials and show me how to migrate each one to environment variables with proper validation at startup.',
  },
  {
    id: 'CL-019',
    title: 'Dependency lockfile committed',
    description: 'package-lock.json, yarn.lock, or pnpm-lock.yaml is committed to ensure reproducible builds and prevent supply chain attacks.',
    severity: 'medium',
    category: 'dependencies',
    howToFix: 'Commit your lockfile to version control. Never add it to .gitignore. Run `npm ci` in CI/CD instead of `npm install` for deterministic builds.',
    aiPrompt: 'Explain why committing the lockfile matters for security. Show me how to configure my CI/CD to use `npm ci` for reproducible, secure builds.',
  },
  {
    id: 'CL-020',
    title: 'Security logging and monitoring enabled',
    description: 'Authentication events, authorization failures, and suspicious activity are logged and monitored.',
    severity: 'medium',
    category: 'monitoring',
    howToFix: 'Log all auth events (login, logout, failed attempts, password resets). Use structured logging with a service like Axiom, Datadog, or Sentry.',
    aiPrompt: 'Set up security logging for my application. Show me how to log authentication events, failed authorization attempts, and rate limit violations with proper structured logging.',
  },
];
