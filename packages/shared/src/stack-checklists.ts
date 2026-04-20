/**
 * Stack-specific security checklists — tailored items for each technology choice.
 *
 * Items are organized by technology type (framework, database, auth provider).
 * `generateStackChecklist()` combines items from each selection into a single
 * tailored checklist for the user's exact stack.
 */

import type { Severity } from './types.js';

/** A single stack-specific checklist item */
export interface StackChecklistItem {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: string;
  readonly howToFix: string;
  readonly aiPrompt: string;
}

/** Dropdown option for stack selection */
export interface StackOption {
  readonly value: string;
  readonly label: string;
}

/** A generated checklist for a specific stack combination */
export interface StackChecklist {
  readonly framework: string;
  readonly database: string;
  readonly auth: string;
  readonly items: readonly StackChecklistItem[];
}

// ---------------------------------------------------------------------------
// Dropdown options
// ---------------------------------------------------------------------------

export const FRAMEWORK_OPTIONS: readonly StackOption[] = [
  { value: 'nextjs', label: 'Next.js' },
  { value: 'express', label: 'Express' },
  { value: 'fastify', label: 'Fastify' },
  { value: 'remix', label: 'Remix' },
  { value: 'astro', label: 'Astro' },
  { value: 'nuxt', label: 'Nuxt' },
  { value: 'sveltekit', label: 'SvelteKit' },
  { value: 'hono', label: 'Hono' },
];

export const DATABASE_OPTIONS: readonly StackOption[] = [
  { value: 'supabase', label: 'Supabase' },
  { value: 'prisma', label: 'Prisma' },
  { value: 'drizzle', label: 'Drizzle' },
  { value: 'mongoose', label: 'Mongoose' },
  { value: 'typeorm', label: 'TypeORM' },
];

export const AUTH_OPTIONS: readonly StackOption[] = [
  { value: 'clerk', label: 'Clerk' },
  { value: 'auth0', label: 'Auth0' },
  { value: 'nextauth', label: 'NextAuth' },
  { value: 'supabase-auth', label: 'Supabase Auth' },
  { value: 'passport', label: 'Passport' },
  { value: 'lucia', label: 'Lucia' },
];

// ---------------------------------------------------------------------------
// Framework-specific items
// ---------------------------------------------------------------------------

const FRAMEWORK_ITEMS: Readonly<Record<string, readonly StackChecklistItem[]>> = {
  nextjs: [
    {
      id: 'FW-NX-001',
      title: 'Protect API routes with middleware authentication',
      description: 'All /api routes should verify the user session via Next.js middleware before reaching the handler.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Create middleware.ts at the project root. Use your auth provider\'s middleware helper to verify sessions. Configure the matcher to cover /api and protected page routes.',
      aiPrompt: 'I\'m using Next.js with App Router. Generate a middleware.ts that protects all /api routes and /dashboard pages. Show me how to configure the matcher and handle unauthenticated requests with a redirect to /login.',
    },
    {
      id: 'FW-NX-002',
      title: 'Set security headers in next.config',
      description: 'Configure Content-Security-Policy, HSTS, X-Frame-Options, and other security headers in next.config.mjs.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Add a headers() function in next.config.mjs that returns security headers for all routes. Start with a strict CSP and relax as needed for your CDN and analytics.',
      aiPrompt: 'Generate a next.config.mjs headers configuration with Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Include comments explaining each header value.',
    },
    {
      id: 'FW-NX-003',
      title: 'Validate Server Action inputs with Zod',
      description: 'All Server Actions should validate their input using a schema library before processing.',
      severity: 'high',
      category: 'code',
      howToFix: 'Install Zod. Define a schema for each Server Action\'s expected input shape. Parse the input at the top of the action before any database calls or side effects.',
      aiPrompt: 'I have Next.js Server Actions. Show me how to add Zod validation to each action. Generate example schemas for form submissions and demonstrate proper error handling when validation fails.',
    },
    {
      id: 'FW-NX-004',
      title: 'Prevent server component data leaks to client',
      description: 'Ensure server components don\'t pass sensitive data (API keys, internal IDs, full user records) to client components via props.',
      severity: 'high',
      category: 'code',
      howToFix: 'Audit all server-to-client component boundaries. Only pass the minimum data needed for rendering. Use server-only utilities from the "server-only" package to prevent accidental client imports.',
      aiPrompt: 'Audit my Next.js app for data leaks from server components to client components. Show me how to use the "server-only" package and demonstrate safe patterns for passing data across the server/client boundary.',
    },
    {
      id: 'FW-NX-005',
      title: 'Enable CSRF protection for mutations',
      description: 'Server Actions have built-in CSRF protection, but custom API routes using POST/PUT/DELETE need explicit CSRF tokens or SameSite cookies.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Use Server Actions for mutations whenever possible (they include CSRF protection). For custom API routes, set SameSite=Lax on cookies and verify the Origin header matches your domain.',
      aiPrompt: 'My Next.js app has custom API routes for mutations alongside Server Actions. Show me how to add CSRF protection to the API routes using Origin header verification and SameSite cookies.',
    },
  ],
  express: [
    {
      id: 'FW-EX-001',
      title: 'Enable helmet for security headers',
      description: 'Use the helmet middleware to set secure HTTP headers including CSP, HSTS, and X-Frame-Options.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Install helmet: npm install helmet. Add app.use(helmet()) before your route handlers. Customize the CSP directives for your frontend assets and CDN origins.',
      aiPrompt: 'I\'m using Express. Set up helmet with a customized Content-Security-Policy that allows my frontend assets, Google Fonts, and analytics. Show the full middleware configuration.',
    },
    {
      id: 'FW-EX-002',
      title: 'Configure CORS with specific origins',
      description: 'Replace wildcard CORS with an explicit allowlist of trusted frontend origins.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Install cors: npm install cors. Configure it with an origin array or function that checks against your known frontend domains. Enable credentials only if needed.',
      aiPrompt: 'Configure CORS in my Express app to only allow requests from my frontend domains. Show origin whitelist, credential handling, and proper preflight responses.',
    },
    {
      id: 'FW-EX-003',
      title: 'Add rate limiting to all endpoints',
      description: 'Protect against brute force and DDoS by limiting requests per IP, especially on auth routes.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Install express-rate-limit. Apply a global limiter (100 req/15 min) and a stricter one for /auth routes (5 req/15 min). Use a Redis store in production for multi-instance deployments.',
      aiPrompt: 'Set up express-rate-limit in my Express app with a global limit and stricter limits for /auth and /api/login routes. Show Redis store configuration for production.',
    },
    {
      id: 'FW-EX-004',
      title: 'Sanitize user input against injection',
      description: 'All user inputs (body, query, params) should be sanitized to prevent XSS and injection attacks.',
      severity: 'critical',
      category: 'code',
      howToFix: 'Use express-validator or Zod for input validation. Sanitize HTML input with DOMPurify or sanitize-html. Never interpolate user input into SQL, shell commands, or HTML.',
      aiPrompt: 'Add input validation and sanitization to my Express routes using express-validator. Show me middleware that validates body, query, and params with proper error responses.',
    },
    {
      id: 'FW-EX-005',
      title: 'Configure secure session management',
      description: 'Sessions should use secure, httpOnly, sameSite cookies with a strong secret and proper expiration.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Use express-session with a strong secret from environment variables. Set cookie options: secure: true, httpOnly: true, sameSite: "lax", maxAge: 24h. Use a Redis store in production.',
      aiPrompt: 'Configure express-session in my Express app with secure cookie settings, Redis session store, and proper secret management. Show production-ready configuration.',
    },
  ],
  fastify: [
    {
      id: 'FW-FT-001',
      title: 'Register @fastify/helmet for security headers',
      description: 'Use the official Fastify helmet plugin to set secure HTTP response headers.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Install @fastify/helmet. Register it with fastify.register(helmet, { contentSecurityPolicy: { directives: { ... } } }). Customize CSP for your assets.',
      aiPrompt: 'Set up @fastify/helmet in my Fastify app with customized CSP directives. Show registration order and proper configuration for a REST API.',
    },
    {
      id: 'FW-FT-002',
      title: 'Enable @fastify/rate-limit on all routes',
      description: 'Protect your API from abuse with per-IP rate limiting, with stricter limits on auth endpoints.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Install @fastify/rate-limit. Register globally with a default limit (100 req/min). Add route-specific overrides for auth endpoints (5 req/min).',
      aiPrompt: 'Configure @fastify/rate-limit in my Fastify app with global and per-route limits. Show Redis store setup for production and stricter limits on /auth routes.',
    },
    {
      id: 'FW-FT-003',
      title: 'Use JSON Schema validation on all routes',
      description: 'Fastify\'s built-in schema validation should be configured on every route to validate request body, params, query, and headers.',
      severity: 'high',
      category: 'code',
      howToFix: 'Define JSON Schema objects for each route\'s body, querystring, params, and response. Fastify compiles these for fast validation. Use @sinclair/typebox for type-safe schemas.',
      aiPrompt: 'Add JSON Schema validation to all my Fastify routes using @sinclair/typebox. Show schemas for body, querystring, params, and response with proper error formatting.',
    },
    {
      id: 'FW-FT-004',
      title: 'Validate JWT tokens on protected routes',
      description: 'Protected endpoints should verify JWT tokens with proper audience, issuer, and expiration checks.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Install @fastify/jwt. Register it with a secret from env vars. Use fastify.authenticate as a preHandler on protected routes. Verify audience and issuer claims.',
      aiPrompt: 'Set up JWT authentication in my Fastify app using @fastify/jwt. Show route protection with preHandler hooks, token verification, and proper error responses for expired/invalid tokens.',
    },
    {
      id: 'FW-FT-005',
      title: 'Configure custom error handler to hide internals',
      description: 'Replace Fastify\'s default error response with a custom handler that hides stack traces and internal details in production.',
      severity: 'medium',
      category: 'code',
      howToFix: 'Set a custom error handler with fastify.setErrorHandler(). Return generic messages in production. Log full error details server-side. Map known error codes to user-friendly messages.',
      aiPrompt: 'Create a custom Fastify error handler that returns safe, user-friendly error responses in production while logging full details with structured logging. Include handling for validation errors and 404s.',
    },
  ],
  remix: [
    {
      id: 'FW-RX-001',
      title: 'Protect loaders and actions with auth checks',
      description: 'Every loader and action in protected routes should verify the user session before returning data or processing mutations.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Create a requireAuth() utility that checks the session cookie in the request. Call it at the top of every protected loader and action. Redirect to /login if unauthenticated.',
      aiPrompt: 'Create a Remix requireAuth() utility function that verifies the user session in loaders and actions. Show how to use it across protected routes with proper redirect handling.',
    },
    {
      id: 'FW-RX-002',
      title: 'Validate action form data with Zod',
      description: 'All form submissions handled by Remix actions should validate input before processing.',
      severity: 'high',
      category: 'code',
      howToFix: 'Parse formData in actions, convert to an object, and validate with Zod. Return actionData errors for the UI to display. Never trust client-side validation alone.',
      aiPrompt: 'Add Zod validation to my Remix action handlers. Show how to parse FormData, validate with schemas, and return typed errors that the UI can display inline.',
    },
    {
      id: 'FW-RX-003',
      title: 'Set security headers in entry.server',
      description: 'Configure security headers in the server entry point to apply them to all responses.',
      severity: 'high',
      category: 'headers',
      howToFix: 'In entry.server.tsx, add security headers to the Response object: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.',
      aiPrompt: 'Add security headers to my Remix app in entry.server.tsx. Generate a complete set of headers including CSP, HSTS, and X-Frame-Options that work with Remix\'s asset loading.',
    },
    {
      id: 'FW-RX-004',
      title: 'Prevent data leaks in loader responses',
      description: 'Loaders should return only the data needed for rendering, never full database records with sensitive fields.',
      severity: 'high',
      category: 'code',
      howToFix: 'Select only needed fields in database queries. Use pick/omit utilities to strip sensitive fields before returning from loaders. Never return password hashes, tokens, or internal IDs.',
      aiPrompt: 'Audit my Remix loaders for data leaks. Show me how to create safe data transformation functions that strip sensitive fields before returning loader data to the client.',
    },
  ],
  astro: [
    {
      id: 'FW-AS-001',
      title: 'Protect API endpoints with auth middleware',
      description: 'Astro API routes (src/pages/api/) should verify authentication before processing requests.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Create a middleware in src/middleware.ts that checks auth tokens on API routes. Use Astro.locals to pass user context to endpoints. Return 401 for unauthenticated requests.',
      aiPrompt: 'Create an Astro middleware that protects API routes with authentication. Show how to verify tokens, pass user context via Astro.locals, and handle unauthorized requests.',
    },
    {
      id: 'FW-AS-002',
      title: 'Configure security headers for static and SSR pages',
      description: 'Set security headers in astro.config.mjs or via middleware for all page responses.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Add a middleware that sets security headers on all responses. For static hosting, configure headers in your hosting platform (Vercel, Netlify, Cloudflare).',
      aiPrompt: 'Add security headers to my Astro site. Show middleware configuration for SSR mode and platform-specific config files (vercel.json, _headers) for static deployment.',
    },
    {
      id: 'FW-AS-003',
      title: 'Sanitize dynamic content in .astro templates',
      description: 'Astro auto-escapes expressions in templates, but set:html bypasses this. Ensure user-generated content is sanitized before using set:html.',
      severity: 'high',
      category: 'code',
      howToFix: 'Avoid set:html with user-generated content. If HTML rendering is needed, sanitize with DOMPurify or sanitize-html before passing to set:html.',
      aiPrompt: 'Audit my Astro templates for XSS risks from set:html usage. Show me how to safely render user-generated HTML content with DOMPurify in Astro components.',
    },
  ],
  nuxt: [
    {
      id: 'FW-NU-001',
      title: 'Protect server routes with auth middleware',
      description: 'Nuxt server routes (server/api/) should verify authentication via server middleware.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Create server middleware in server/middleware/ that verifies auth tokens. Use defineEventHandler to protect API routes. Set session data on the event context.',
      aiPrompt: 'Create Nuxt 3 server middleware for authentication. Show how to protect server/api routes, verify tokens with H3 utilities, and pass user context to handlers.',
    },
    {
      id: 'FW-NU-002',
      title: 'Configure security headers in nuxt.config',
      description: 'Set HTTP security headers using the routeRules or nitro config in nuxt.config.ts.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Use nuxt-security module or configure headers in routeRules within nuxt.config.ts. Set CSP, HSTS, X-Frame-Options for all routes.',
      aiPrompt: 'Set up security headers in my Nuxt 3 app using nuxt-security module. Show configuration for CSP, HSTS, and other security headers in nuxt.config.ts.',
    },
    {
      id: 'FW-NU-003',
      title: 'Validate API route inputs with Zod',
      description: 'All Nuxt server API routes should validate request body, query, and params before processing.',
      severity: 'high',
      category: 'code',
      howToFix: 'Use readValidatedBody() and getValidatedQuery() from H3 with Zod schemas to validate inputs in server routes.',
      aiPrompt: 'Add Zod input validation to my Nuxt 3 server API routes using H3 utilities. Show readValidatedBody and getValidatedQuery patterns with proper error responses.',
    },
  ],
  sveltekit: [
    {
      id: 'FW-SK-001',
      title: 'Protect server-side load functions and actions',
      description: 'SvelteKit load functions and form actions should verify auth via hooks.server.ts before returning data.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Create a handle hook in hooks.server.ts that verifies sessions and attaches user data to event.locals. Check event.locals.user in load functions and actions.',
      aiPrompt: 'Set up authentication in my SvelteKit app via hooks.server.ts. Show the handle hook for session verification and how load functions access user data from event.locals.',
    },
    {
      id: 'FW-SK-002',
      title: 'Configure CSP and security headers in hooks',
      description: 'Set security headers in the handle hook in hooks.server.ts for all responses.',
      severity: 'high',
      category: 'headers',
      howToFix: 'In the handle hook, modify response.headers to add CSP, HSTS, X-Frame-Options, and other security headers. Configure CSP nonces for inline scripts.',
      aiPrompt: 'Add security headers to my SvelteKit app in hooks.server.ts. Generate a CSP configuration with nonce support for SvelteKit\'s inline scripts and show all recommended headers.',
    },
    {
      id: 'FW-SK-003',
      title: 'Validate form action inputs',
      description: 'SvelteKit form actions should validate all form data before processing mutations.',
      severity: 'high',
      category: 'code',
      howToFix: 'Parse request.formData() in actions and validate with Zod. Return fail() with typed errors for the form to display. Use superforms for advanced form handling.',
      aiPrompt: 'Add Zod validation to my SvelteKit form actions. Show how to validate formData, return typed errors with fail(), and display validation messages in the form component.',
    },
  ],
  hono: [
    {
      id: 'FW-HO-001',
      title: 'Apply security headers middleware',
      description: 'Use Hono\'s built-in secureHeaders middleware to set security HTTP headers on all responses.',
      severity: 'high',
      category: 'headers',
      howToFix: 'Import secureHeaders from hono/secure-headers. Apply it globally with app.use("*", secureHeaders()). Customize CSP directives for your needs.',
      aiPrompt: 'Configure Hono\'s secureHeaders middleware with customized CSP, HSTS, and other security headers. Show the full middleware setup for a REST API.',
    },
    {
      id: 'FW-HO-002',
      title: 'Add JWT authentication middleware',
      description: 'Protect API routes with JWT verification using Hono\'s built-in JWT middleware.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Import jwt from hono/jwt. Apply it to protected route groups. Verify audience and issuer claims. Store the JWT secret in environment variables.',
      aiPrompt: 'Set up JWT authentication in my Hono app using the built-in jwt middleware. Show route protection, custom claim validation, and error handling for invalid tokens.',
    },
    {
      id: 'FW-HO-003',
      title: 'Validate request bodies with Zod',
      description: 'Use the zod-validator middleware to validate all incoming request data before processing.',
      severity: 'high',
      category: 'code',
      howToFix: 'Install @hono/zod-validator. Define Zod schemas for each endpoint\'s request body. Apply the zValidator middleware to routes.',
      aiPrompt: 'Add Zod validation to my Hono API routes using @hono/zod-validator. Show middleware setup, schema definitions, and typed error responses for validation failures.',
    },
  ],
};

// ---------------------------------------------------------------------------
// Database-specific items
// ---------------------------------------------------------------------------

const DATABASE_ITEMS: Readonly<Record<string, readonly StackChecklistItem[]>> = {
  supabase: [
    {
      id: 'DB-SB-001',
      title: 'Enable Row Level Security on all tables',
      description: 'Every Supabase table should have RLS enabled with policies that restrict access based on the authenticated user.',
      severity: 'critical',
      category: 'database',
      howToFix: 'Enable RLS: ALTER TABLE table_name ENABLE ROW LEVEL SECURITY. Create policies for SELECT, INSERT, UPDATE, DELETE that check auth.uid() against an owner column.',
      aiPrompt: 'Enable Row Level Security on all my Supabase tables. Generate RLS policies for each table that restrict reads/writes to the authenticated user. Include policies for public data and admin access patterns.',
    },
    {
      id: 'DB-SB-002',
      title: 'Never expose the service_role key to the client',
      description: 'The service_role key bypasses RLS. It must only be used in server-side code, never in client bundles.',
      severity: 'critical',
      category: 'secrets',
      howToFix: 'Use the anon key on the client and the service_role key only in server-side code (API routes, Server Actions, Edge Functions). Prefix client env vars with NEXT_PUBLIC_ only for the anon key.',
      aiPrompt: 'Audit my Supabase configuration to ensure the service_role key is never exposed to the client. Show me the correct way to use anon vs service_role keys across server and client code.',
    },
    {
      id: 'DB-SB-003',
      title: 'Restrict Supabase API access to your domain',
      description: 'Configure allowed origins in Supabase dashboard to prevent unauthorized API access from other domains.',
      severity: 'high',
      category: 'database',
      howToFix: 'In Supabase Dashboard > Settings > API, configure the allowed origins to include only your application domains. Remove wildcard (*) access.',
      aiPrompt: 'Configure my Supabase project to restrict API access. Show me how to set allowed origins, configure API rate limits, and set up proper CORS in the Supabase dashboard.',
    },
  ],
  prisma: [
    {
      id: 'DB-PR-001',
      title: 'Use parameterized queries — avoid $queryRawUnsafe',
      description: 'Prisma prevents SQL injection by default, but $queryRawUnsafe and $executeRawUnsafe bypass these protections.',
      severity: 'critical',
      category: 'database',
      howToFix: 'Replace $queryRawUnsafe with $queryRaw which uses tagged template literals for safe parameterization. Use Prisma Client methods (findMany, create, etc.) whenever possible.',
      aiPrompt: 'Audit my Prisma codebase for uses of $queryRawUnsafe and $executeRawUnsafe. Replace each with the safe $queryRaw/$executeRaw alternatives using tagged template parameterization.',
    },
    {
      id: 'DB-PR-002',
      title: 'Select only needed fields in queries',
      description: 'Use Prisma\'s select to return only the fields needed, preventing accidental exposure of sensitive columns like password hashes.',
      severity: 'high',
      category: 'database',
      howToFix: 'Add select clauses to all queries that return data to the client. Create reusable select objects for common query patterns. Never return the full user record with password hash.',
      aiPrompt: 'Audit my Prisma queries and add select clauses to prevent returning sensitive fields. Create reusable select objects for user profiles, lists, and detail views.',
    },
    {
      id: 'DB-PR-003',
      title: 'Secure database connection string',
      description: 'The DATABASE_URL should use SSL, be stored in environment variables, and use connection pooling in production.',
      severity: 'high',
      category: 'secrets',
      howToFix: 'Add ?sslmode=require to your DATABASE_URL. Use a connection pooler (PgBouncer, Supabase pooler) in production. Store the URL in env vars, never in source code.',
      aiPrompt: 'Secure my Prisma database connection. Show the correct DATABASE_URL format with SSL, connection pooling configuration, and proper environment variable management for development and production.',
    },
  ],
  drizzle: [
    {
      id: 'DB-DZ-001',
      title: 'Use Drizzle query builder — avoid raw SQL with user input',
      description: 'Drizzle\'s query builder auto-parameterizes, but sql.raw() bypasses this. Ensure user input never reaches sql.raw().',
      severity: 'critical',
      category: 'database',
      howToFix: 'Use Drizzle\'s type-safe query builder (db.select(), db.insert(), etc.) instead of raw SQL. When raw SQL is needed, use sql`` tagged templates for parameterization.',
      aiPrompt: 'Audit my Drizzle ORM code for unsafe raw SQL usage. Replace any sql.raw() calls that include user input with the safe sql`` tagged template or type-safe query builder methods.',
    },
    {
      id: 'DB-DZ-002',
      title: 'Define column-level constraints in schema',
      description: 'Use Drizzle schema definitions to enforce NOT NULL, unique constraints, and check constraints at the database level.',
      severity: 'medium',
      category: 'database',
      howToFix: 'Add .notNull(), .unique(), and .default() modifiers to your Drizzle schema columns. Use check constraints for data validation that should be enforced at the database level.',
      aiPrompt: 'Review my Drizzle schema and add appropriate database constraints. Show column-level NOT NULL, unique, check constraints, and proper foreign key relationships.',
    },
    {
      id: 'DB-DZ-003',
      title: 'Secure database connection with SSL',
      description: 'Ensure the database connection uses SSL/TLS and the connection string is stored in environment variables.',
      severity: 'high',
      category: 'secrets',
      howToFix: 'Add ssl: { rejectUnauthorized: true } to your database connection config. Store the connection string in env vars. Use connection pooling in production.',
      aiPrompt: 'Secure my Drizzle database connection with SSL and connection pooling. Show the correct configuration for postgres.js or better-sqlite3 driver with proper env var management.',
    },
  ],
  mongoose: [
    {
      id: 'DB-MG-001',
      title: 'Enable strict query mode to prevent injection',
      description: 'Mongoose query filters can be exploited with object injection. Enable strict mode and validate all query inputs.',
      severity: 'critical',
      category: 'database',
      howToFix: 'Set mongoose.set("strictQuery", true) globally. Validate and sanitize all query filter inputs. Use express-mongo-sanitize middleware to strip $ operators from user input.',
      aiPrompt: 'Secure my Mongoose queries against NoSQL injection. Show me how to enable strictQuery, use express-mongo-sanitize, and properly validate query filter inputs.',
    },
    {
      id: 'DB-MG-002',
      title: 'Add schema validation with required fields',
      description: 'Mongoose schemas should enforce required fields, type checking, and custom validators to prevent malformed data.',
      severity: 'high',
      category: 'database',
      howToFix: 'Add required: true to essential fields. Use enum for restricted values. Add custom validate functions for business rules. Enable timestamps for audit trails.',
      aiPrompt: 'Review my Mongoose schemas and add proper validation. Show required fields, enum constraints, custom validators, and index definitions for each model.',
    },
    {
      id: 'DB-MG-003',
      title: 'Restrict returned fields to prevent data leaks',
      description: 'Use select() or projection to exclude sensitive fields like password hashes from query results.',
      severity: 'high',
      category: 'database',
      howToFix: 'Add select: false to sensitive schema fields (password, tokens). Use .select("-password -__v") in queries. Create reusable projection constants for common query patterns.',
      aiPrompt: 'Configure my Mongoose schemas to hide sensitive fields by default. Show schema-level select: false, query-level projections, and toJSON transforms to strip internal fields.',
    },
  ],
  typeorm: [
    {
      id: 'DB-TO-001',
      title: 'Use QueryBuilder parameters — never interpolate user input',
      description: 'TypeORM\'s QueryBuilder supports parameterized queries. Never concatenate user input into where clauses or raw SQL.',
      severity: 'critical',
      category: 'database',
      howToFix: 'Use .where("user.id = :id", { id }) parameter binding syntax. Avoid template literals in query strings. Use the Repository API (findOne, find) when possible.',
      aiPrompt: 'Audit my TypeORM queries for SQL injection risks. Replace any string concatenation with parameterized queries using QueryBuilder\'s :param syntax or Repository methods.',
    },
    {
      id: 'DB-TO-002',
      title: 'Configure entity column-level validation',
      description: 'Use TypeORM column decorators with class-validator to enforce data integrity at the entity level.',
      severity: 'high',
      category: 'database',
      howToFix: 'Install class-validator. Add validation decorators (@IsEmail, @Length, @IsNotEmpty) to entity properties. Enable validation in the data source config.',
      aiPrompt: 'Add class-validator decorators to my TypeORM entities. Show column-level validation for common fields (email, password, name) and proper error handling.',
    },
    {
      id: 'DB-TO-003',
      title: 'Secure database connection with SSL and pooling',
      description: 'TypeORM connections should use SSL and connection pooling in production environments.',
      severity: 'high',
      category: 'secrets',
      howToFix: 'Add ssl: { rejectUnauthorized: true } to the data source config. Configure connection pool size. Store credentials in env vars. Use a separate read replica config for scaling.',
      aiPrompt: 'Secure my TypeORM data source configuration with SSL, connection pooling, and proper environment variable management. Show production-ready DataSource configuration.',
    },
  ],
};

// ---------------------------------------------------------------------------
// Auth provider-specific items
// ---------------------------------------------------------------------------

const AUTH_ITEMS: Readonly<Record<string, readonly StackChecklistItem[]>> = {
  clerk: [
    {
      id: 'AU-CK-001',
      title: 'Configure Clerk middleware with proper route protection',
      description: 'Clerk middleware should protect all routes by default and explicitly declare public routes.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Use clerkMiddleware() with createRouteMatcher to define public routes. Default to protecting everything. List only truly public pages (landing, sign-in, sign-up, webhooks) as public.',
      aiPrompt: 'Configure Clerk middleware in my app to protect all routes by default. Show how to use createRouteMatcher to define public routes and protect API endpoints. Include webhook routes as public.',
    },
    {
      id: 'AU-CK-002',
      title: 'Verify Clerk webhook signatures',
      description: 'Clerk webhooks (user.created, session.ended, etc.) should verify the svix signature to prevent spoofing.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Install svix. In your webhook handler, verify the signature using the webhook secret from Clerk dashboard. Reject requests with invalid signatures.',
      aiPrompt: 'Set up Clerk webhook verification in my API route. Show how to verify svix signatures, handle different event types (user.created, user.updated), and sync data to my database.',
    },
    {
      id: 'AU-CK-003',
      title: 'Use server-side auth() for data access control',
      description: 'Always verify the user\'s identity server-side before database queries, not just in middleware.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Call auth() in Server Actions and API routes to get the userId. Pass it to database queries for ownership verification. Never trust client-provided user IDs.',
      aiPrompt: 'Show me how to use Clerk\'s auth() function server-side for data access control. Demonstrate in Server Actions and API routes, verifying ownership before database operations.',
    },
  ],
  auth0: [
    {
      id: 'AU-A0-001',
      title: 'Validate JWT audience and issuer claims',
      description: 'Auth0 JWTs should be validated with the correct audience (API identifier) and issuer (Auth0 domain) to prevent token misuse.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Configure your JWT validation middleware to check: audience matches your API identifier, issuer matches your Auth0 domain, token is not expired, and signature is valid.',
      aiPrompt: 'Set up Auth0 JWT validation in my API with proper audience and issuer verification. Show the complete middleware configuration and error handling for invalid tokens.',
    },
    {
      id: 'AU-A0-002',
      title: 'Restrict callback and logout URLs',
      description: 'Auth0 callback and logout URLs should whitelist only your application domains to prevent open redirect attacks.',
      severity: 'high',
      category: 'auth',
      howToFix: 'In Auth0 Dashboard > Applications, set Allowed Callback URLs and Allowed Logout URLs to your exact application domains. Never use wildcards in production.',
      aiPrompt: 'Audit my Auth0 application settings for security. Show the correct configuration for callback URLs, logout URLs, CORS origins, and web origins. Explain the risks of misconfiguration.',
    },
    {
      id: 'AU-A0-003',
      title: 'Implement proper token refresh flow',
      description: 'Implement silent token refresh to avoid storing long-lived tokens and handle expired sessions gracefully.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Use Auth0\'s refresh token rotation. Configure short access token lifetimes (1 hour). Implement silent refresh with the Auth0 SDK. Handle token expiry in your API client.',
      aiPrompt: 'Set up token refresh in my Auth0 integration. Show refresh token rotation configuration, silent refresh implementation in the frontend, and API-side handling for expired tokens.',
    },
  ],
  nextauth: [
    {
      id: 'AU-NA-001',
      title: 'Set a strong NEXTAUTH_SECRET',
      description: 'NextAuth requires a cryptographic secret for JWT signing and CSRF. It must be a strong random value stored in env vars.',
      severity: 'critical',
      category: 'secrets',
      howToFix: 'Generate a strong secret: openssl rand -base64 32. Store it as NEXTAUTH_SECRET in environment variables. Never commit it to source code.',
      aiPrompt: 'Verify my NextAuth configuration is secure. Check NEXTAUTH_SECRET strength, session strategy, CSRF protection, and callback URL validation. Show the recommended production configuration.',
    },
    {
      id: 'AU-NA-002',
      title: 'Validate OAuth callback URLs in NextAuth config',
      description: 'The callbacks.redirect function should validate that redirect URLs belong to your domain to prevent open redirects.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Implement the callbacks.redirect function. Check that the URL starts with your base URL. Reject external redirects. Use NEXTAUTH_URL for origin validation.',
      aiPrompt: 'Secure my NextAuth callbacks configuration. Show proper redirect validation, session callback for adding user roles, and JWT callback for custom claims. Include CSRF protection settings.',
    },
    {
      id: 'AU-NA-003',
      title: 'Use server-side getServerSession for auth checks',
      description: 'API routes and Server Components should use getServerSession() instead of client-side session checks for security decisions.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Import getServerSession with your authOptions. Call it in API route handlers and server components. Never rely on client-side session data for authorization decisions.',
      aiPrompt: 'Migrate my NextAuth auth checks to use getServerSession in API routes and Server Components. Show the pattern for each context and how to handle unauthenticated requests.',
    },
  ],
  'supabase-auth': [
    {
      id: 'AU-SA-001',
      title: 'Combine Supabase Auth with Row Level Security',
      description: 'RLS policies should reference auth.uid() to tie data access to the authenticated user. Auth alone is not enough without RLS.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Enable RLS on all tables. Create policies that check auth.uid() = user_id. Use the Supabase client with the user\'s session token so RLS policies are enforced.',
      aiPrompt: 'Set up Supabase Auth + RLS for my tables. Generate policies that use auth.uid() for ownership checks. Show the correct client initialization for both server and client components.',
    },
    {
      id: 'AU-SA-002',
      title: 'Handle auth state changes on the client',
      description: 'Listen for SIGNED_OUT and TOKEN_REFRESHED events to keep the client state in sync and prevent stale sessions.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Use supabase.auth.onAuthStateChange() to listen for auth events. Redirect on SIGNED_OUT. Refresh page data on TOKEN_REFRESHED. Clear local state on sign-out.',
      aiPrompt: 'Set up Supabase Auth state management in my React app. Show onAuthStateChange handler for session sync, token refresh, sign-out cleanup, and proper error handling.',
    },
    {
      id: 'AU-SA-003',
      title: 'Verify Supabase auth on the server for mutations',
      description: 'Server-side code should verify the user session from the cookie or Authorization header, not trust client-provided user IDs.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Use createServerClient (for SSR) or createClient (for API routes) with cookie-based auth. Call supabase.auth.getUser() — getUser() verifies the JWT, getSession() does not.',
      aiPrompt: 'Set up server-side Supabase Auth verification. Show the difference between getSession() and getUser(), and demonstrate safe patterns for API routes and Server Actions.',
    },
  ],
  passport: [
    {
      id: 'AU-PP-001',
      title: 'Configure secure session with strong secret',
      description: 'Passport relies on express-session. The session secret must be strong and stored in environment variables.',
      severity: 'critical',
      category: 'secrets',
      howToFix: 'Use a 256-bit random secret stored in env vars. Configure express-session with secure, httpOnly, sameSite cookies. Use a production-grade session store (Redis, PostgreSQL).',
      aiPrompt: 'Configure express-session for Passport.js with secure settings. Show Redis session store, strong secret management, and cookie configuration for production.',
    },
    {
      id: 'AU-PP-002',
      title: 'Implement proper serialize/deserialize handlers',
      description: 'serializeUser and deserializeUser should handle edge cases: deleted users, expired sessions, and database errors.',
      severity: 'high',
      category: 'auth',
      howToFix: 'In serializeUser, store only the user ID. In deserializeUser, fetch the user from the database and handle the case where the user no longer exists (return done(null, false)).',
      aiPrompt: 'Implement secure Passport.js serialize/deserialize handlers. Show error handling for deleted users, database failures, and session invalidation when user permissions change.',
    },
    {
      id: 'AU-PP-003',
      title: 'Add rate limiting to login routes',
      description: 'Login endpoints using Passport should have strict rate limiting to prevent brute force attacks.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Apply express-rate-limit to /login and /auth routes with a strict limit (5 attempts per 15 minutes). Consider account lockout after repeated failures.',
      aiPrompt: 'Add brute force protection to my Passport.js login routes. Show rate limiting, account lockout after failed attempts, and progressive delays between retries.',
    },
  ],
  lucia: [
    {
      id: 'AU-LU-001',
      title: 'Configure secure session cookies',
      description: 'Lucia sessions should use secure, httpOnly, sameSite cookies with proper expiration settings.',
      severity: 'critical',
      category: 'auth',
      howToFix: 'Configure Lucia with sessionCookie options: secure: true (in production), httpOnly: true, sameSite: "lax". Set session expiration and implement idle timeout.',
      aiPrompt: 'Configure Lucia auth with secure session cookies. Show cookie settings, session expiration, idle timeout, and the correct setup for both development and production environments.',
    },
    {
      id: 'AU-LU-002',
      title: 'Validate sessions on every protected request',
      description: 'Validate the session token from the cookie on every request to protected routes, not just during login.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Call lucia.validateSession() in middleware or at the top of protected handlers. Handle invalid sessions by clearing the cookie and redirecting to login.',
      aiPrompt: 'Set up Lucia session validation middleware for my app. Show how to validate sessions on every request, handle expired sessions, and implement session refresh/extension.',
    },
    {
      id: 'AU-LU-003',
      title: 'Implement CSRF protection for forms',
      description: 'Lucia doesn\'t include CSRF protection. Add it manually for form submissions and state-changing requests.',
      severity: 'high',
      category: 'auth',
      howToFix: 'Use the Origin header check or CSRF tokens for form submissions. Verify that the Origin header matches your domain on all POST/PUT/DELETE requests.',
      aiPrompt: 'Add CSRF protection to my Lucia auth setup. Show Origin header validation middleware and CSRF token generation/verification for form submissions.',
    },
  ],
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generates a tailored security checklist for the given stack combination.
 * Combines framework, database, and auth provider items into a single list.
 */
export function generateStackChecklist(
  framework: string,
  database: string,
  auth: string,
): StackChecklist {
  const frameworkItems = FRAMEWORK_ITEMS[framework] ?? [];
  const databaseItems = DATABASE_ITEMS[database] ?? [];
  const authItems = AUTH_ITEMS[auth] ?? [];

  return {
    framework,
    database,
    auth,
    items: [...frameworkItems, ...databaseItems, ...authItems],
  };
}
