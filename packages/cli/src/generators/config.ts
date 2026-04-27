/**
 * F022: Config generator — outputs ready-to-paste security configs based on detected stack
 *
 * Generates complete, copy-paste-ready security configuration snippets tailored
 * to the project's detected technology stack. Supports Express, Next.js, Fastify,
 * and generic configs (.gitignore, .env.example).
 */
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { ConfigSnippet, DetectedStack } from 'bastion-shared';

// ---------------------------------------------------------------------------
// Express configs
// ---------------------------------------------------------------------------

function expressHelmetConfig(): ConfigSnippet {
  return {
    name: 'Helmet.js Security Headers',
    filename: 'helmet-setup.js',
    language: 'javascript',
    description: 'Express middleware that sets security-related HTTP headers via helmet.js',
    code: `// helmet-setup.js — Security headers for Express
// Install: npm install helmet
import helmet from 'helmet';

/**
 * Configure helmet.js with recommended security headers.
 * Add this BEFORE your route definitions.
 *
 * Usage:
 *   import { securityHeaders } from './helmet-setup.js';
 *   app.use(securityHeaders);
 */
export const securityHeaders = helmet({
  // Content-Security-Policy: restricts resource loading sources
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Strict-Transport-Security: force HTTPS
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  // X-Content-Type-Options: prevent MIME sniffing
  noSniff: true,
  // X-Frame-Options: prevent clickjacking
  frameguard: { action: 'deny' },
  // Referrer-Policy: control referrer information
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Permissions-Policy: restrict browser features
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
});`,
  };
}

function expressCorsConfig(): ConfigSnippet {
  return {
    name: 'CORS Configuration',
    filename: 'cors-setup.js',
    language: 'javascript',
    description: 'Express CORS middleware with secure defaults — never use wildcard origins in production',
    code: `// cors-setup.js — Secure CORS configuration for Express
// Install: npm install cors
import cors from 'cors';

/**
 * Configure CORS with explicit allowed origins.
 * NEVER use origin: '*' or origin: true in production.
 *
 * Usage:
 *   import { corsMiddleware } from './cors-setup.js';
 *   app.use(corsMiddleware);
 */
const ALLOWED_ORIGINS = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  // Add your production domain(s) here:
  // 'https://yourdomain.com',
];

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, curl, etc.)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400, // 24 hours — browsers cache preflight responses
});`,
  };
}

function expressRateLimitConfig(): ConfigSnippet {
  return {
    name: 'Rate Limiter Setup',
    filename: 'rate-limit-setup.js',
    language: 'javascript',
    description: 'Express rate limiting middleware to prevent brute-force and DDoS attacks',
    code: `// rate-limit-setup.js — Rate limiting for Express
// Install: npm install express-rate-limit
import rateLimit from 'express-rate-limit';

/**
 * General API rate limiter — 100 requests per 15 minutes per IP.
 *
 * Usage:
 *   import { apiLimiter, authLimiter } from './rate-limit-setup.js';
 *   app.use('/api/', apiLimiter);
 *   app.use('/api/auth/', authLimiter);
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in \`RateLimit-*\` headers
  legacyHeaders: false, // Disable \`X-RateLimit-*\` headers
  message: { error: 'Too many requests, please try again later.' },
});

/**
 * Stricter limiter for auth endpoints — 5 requests per 15 minutes per IP.
 * Prevents brute-force login/signup attacks.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts, please try again later.' },
});`,
  };
}

// ---------------------------------------------------------------------------
// Next.js configs
// ---------------------------------------------------------------------------

function nextSecurityHeadersConfig(): ConfigSnippet {
  return {
    name: 'Next.js Security Headers',
    filename: 'next-security-headers.js',
    language: 'javascript',
    description: 'Security headers configuration for next.config.js — add to your existing config',
    code: `// next-security-headers.js — Security headers for Next.js
// Copy the headers() function into your next.config.js

/**
 * Recommended security headers for Next.js.
 *
 * Usage in next.config.js:
 *   import { securityHeaders } from './next-security-headers.js';
 *   export default {
 *     async headers() {
 *       return [{ source: '/(.*)', headers: securityHeaders }];
 *     },
 *   };
 */
export const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join('; '),
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  },
];`,
  };
}

function nextRateLimitMiddlewareConfig(): ConfigSnippet {
  return {
    name: 'Next.js Rate Limiting Middleware',
    filename: 'middleware-rate-limit.ts',
    language: 'typescript',
    description: 'Edge-compatible rate limiting middleware for Next.js App Router using in-memory store',
    code: `// middleware-rate-limit.ts — Rate limiting for Next.js middleware
// For production, consider @upstash/ratelimit with Redis for distributed rate limiting.
// This in-memory implementation works for single-instance deployments.

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/** Rate limit window configuration */
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100; // requests per window
const AUTH_MAX_REQUESTS = 5; // stricter limit for auth routes

interface RateLimitEntry {
  readonly count: number;
  readonly resetTime: number;
}

/** In-memory store — use Redis (@upstash/ratelimit) in production */
const store = new Map<string, RateLimitEntry>();

function getClientIp(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    request.headers.get('x-real-ip') ??
    'unknown'
  );
}

function isRateLimited(key: string, max: number): boolean {
  const now = Date.now();
  const entry = store.get(key);

  if (!entry || now > entry.resetTime) {
    store.set(key, { count: 1, resetTime: now + WINDOW_MS });
    return false;
  }

  if (entry.count >= max) {
    return true;
  }

  store.set(key, { ...entry, count: entry.count + 1 });
  return false;
}

/**
 * Next.js middleware with rate limiting.
 *
 * Usage: Save as middleware.ts in your project root.
 */
export function middleware(request: NextRequest): NextResponse {
  const ip = getClientIp(request);
  const isAuthRoute = request.nextUrl.pathname.startsWith('/api/auth');
  const max = isAuthRoute ? AUTH_MAX_REQUESTS : MAX_REQUESTS;
  const key = \`\${ip}:\${isAuthRoute ? 'auth' : 'api'}\`;

  if (isRateLimited(key, max)) {
    return NextResponse.json(
      { error: 'Too many requests, please try again later.' },
      { status: 429, headers: { 'Retry-After': String(Math.ceil(WINDOW_MS / 1000)) } },
    );
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*',
};`,
  };
}

// ---------------------------------------------------------------------------
// Fastify configs
// ---------------------------------------------------------------------------

function fastifyHelmetConfig(): ConfigSnippet {
  return {
    name: 'Fastify Helmet Plugin',
    filename: 'fastify-helmet-setup.js',
    language: 'javascript',
    description: 'Fastify security headers plugin using @fastify/helmet',
    code: `// fastify-helmet-setup.js — Security headers for Fastify
// Install: npm install @fastify/helmet
import helmet from '@fastify/helmet';

/**
 * Register @fastify/helmet with recommended security headers.
 *
 * Usage:
 *   import { registerHelmet } from './fastify-helmet-setup.js';
 *   await registerHelmet(fastify);
 */
export async function registerHelmet(fastify) {
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  });
}`,
  };
}

function fastifyCorsConfig(): ConfigSnippet {
  return {
    name: 'Fastify CORS Plugin',
    filename: 'fastify-cors-setup.js',
    language: 'javascript',
    description: 'Fastify CORS plugin with secure defaults — never use wildcard origins in production',
    code: `// fastify-cors-setup.js — Secure CORS configuration for Fastify
// Install: npm install @fastify/cors
import cors from '@fastify/cors';

/**
 * Register @fastify/cors with explicit allowed origins.
 *
 * Usage:
 *   import { registerCors } from './fastify-cors-setup.js';
 *   await registerCors(fastify);
 */
const ALLOWED_ORIGINS = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  // Add your production domain(s) here:
  // 'https://yourdomain.com',
];

export async function registerCors(fastify) {
  await fastify.register(cors, {
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'), false);
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
  });
}`,
  };
}

function fastifyRateLimitConfig(): ConfigSnippet {
  return {
    name: 'Fastify Rate Limit Plugin',
    filename: 'fastify-rate-limit-setup.js',
    language: 'javascript',
    description: 'Fastify rate limiting plugin to prevent brute-force and DDoS attacks',
    code: `// fastify-rate-limit-setup.js — Rate limiting for Fastify
// Install: npm install @fastify/rate-limit
import rateLimit from '@fastify/rate-limit';

/**
 * Register @fastify/rate-limit with default and route-specific limits.
 *
 * Usage:
 *   import { registerRateLimit } from './fastify-rate-limit-setup.js';
 *   await registerRateLimit(fastify);
 *
 *   // Stricter limit on a specific route:
 *   fastify.post('/login', { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } }, handler);
 */
export async function registerRateLimit(fastify) {
  await fastify.register(rateLimit, {
    global: true,
    max: 100, // 100 requests per window per IP
    timeWindow: '15 minutes',
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true,
      'retry-after': true,
    },
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Too many requests, please try again later.',
    }),
  });
}`,
  };
}

// ---------------------------------------------------------------------------
// Generic configs (always generated)
// ---------------------------------------------------------------------------

function gitignoreConfig(): ConfigSnippet {
  return {
    name: '.gitignore Security Additions',
    filename: '.gitignore-additions',
    language: 'gitignore',
    description: 'Essential .gitignore patterns to prevent committing secrets, keys, and build artifacts',
    code: `# === Security-critical patterns (add to your .gitignore) ===

# Environment files — may contain secrets
.env
.env.local
.env.*.local
.env.production

# Cryptographic keys
*.pem
*.key
*.crt
*.p12
*.pfx

# Dependency directories
node_modules/

# Build outputs
dist/
build/
.next/
out/

# IDE and OS files
.vscode/
.idea/
.DS_Store
Thumbs.db

# Log files
*.log
npm-debug.log*

# Coverage and test reports
coverage/
.nyc_output/`,
  };
}

function envExampleConfig(): ConfigSnippet {
  return {
    name: '.env.example Template',
    filename: '.env.example',
    language: 'shell',
    description: 'Environment variable template with safe placeholders — commit this file, never .env',
    code: `# .env.example — Template for required environment variables
# Copy this file to .env and fill in real values. NEVER commit .env.

# ─── Application ──────────────────────────────────────────────
NODE_ENV=development
PORT=3000

# ─── Database ─────────────────────────────────────────────────
# DATABASE_URL=postgresql://user:password@localhost:5432/mydb

# ─── Authentication ───────────────────────────────────────────
# AUTH_SECRET=generate-a-random-32-char-string-here
# NEXTAUTH_URL=http://localhost:3000

# ─── Third-Party APIs ────────────────────────────────────────
# OPENAI_API_KEY=sk-your-key-here
# STRIPE_SECRET_KEY=sk_test_your-key-here
# STRIPE_WEBHOOK_SECRET=whsec_your-secret-here

# ─── CORS ─────────────────────────────────────────────────────
FRONTEND_URL=http://localhost:3000`,
  };
}

// ---------------------------------------------------------------------------
// Generator registry
// ---------------------------------------------------------------------------

interface FrameworkGenerators {
  readonly framework: string;
  readonly generators: ReadonlyArray<() => ConfigSnippet>;
}

const FRAMEWORK_GENERATORS: readonly FrameworkGenerators[] = [
  {
    framework: 'express',
    generators: [expressHelmetConfig, expressCorsConfig, expressRateLimitConfig],
  },
  {
    framework: 'next.js',
    generators: [nextSecurityHeadersConfig, nextRateLimitMiddlewareConfig],
  },
  {
    framework: 'fastify',
    generators: [fastifyHelmetConfig, fastifyCorsConfig, fastifyRateLimitConfig],
  },
];

const GENERIC_GENERATORS: ReadonlyArray<() => ConfigSnippet> = [
  gitignoreConfig,
  envExampleConfig,
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate security configuration snippets based on detected stack.
 * Always includes generic configs; adds framework-specific configs when a
 * supported framework is detected.
 */
export function generateConfigs(stack: DetectedStack): readonly ConfigSnippet[] {
  const snippets: ConfigSnippet[] = [];

  // Framework-specific configs
  if (stack.framework) {
    const match = FRAMEWORK_GENERATORS.find(
      (fg) => fg.framework === stack.framework,
    );
    if (match) {
      for (const gen of match.generators) {
        snippets.push(gen());
      }
    }
  }

  // Generic configs (always included)
  for (const gen of GENERIC_GENERATORS) {
    snippets.push(gen());
  }

  return snippets;
}

/**
 * Format a single config snippet for terminal display.
 * Returns a readable block with name, description, and fenced code.
 */
export function formatConfigSnippet(snippet: ConfigSnippet): string {
  const lines: string[] = [];
  lines.push(`── ${snippet.name} ──`);
  lines.push(snippet.description);
  lines.push(`File: ${snippet.filename}`);
  lines.push('');
  lines.push(`\`\`\`${snippet.language}`);
  lines.push(snippet.code);
  lines.push('```');
  return lines.join('\n');
}

/**
 * Format all config snippets for terminal display.
 */
export function formatConfigOutput(snippets: readonly ConfigSnippet[]): string {
  if (snippets.length === 0) {
    return 'No configuration snippets to generate.';
  }

  const sections = snippets.map(formatConfigSnippet);
  return (
    '\n  Generated Security Configs\n' +
    `  ${snippets.length} snippet${snippets.length === 1 ? '' : 's'} for your stack\n\n` +
    sections.join('\n\n') +
    '\n'
  );
}

/**
 * Write config snippets to individual files in the specified output directory.
 * Creates the directory if it doesn't exist.
 * Returns the list of file paths written.
 */
export async function writeConfigFiles(
  snippets: readonly ConfigSnippet[],
  outputDir: string,
): Promise<readonly string[]> {
  await mkdir(outputDir, { recursive: true });

  const paths: string[] = [];
  for (const snippet of snippets) {
    const filePath = join(outputDir, snippet.filename);
    await writeFile(filePath, snippet.code + '\n', 'utf-8');
    paths.push(filePath);
  }

  return paths;
}
