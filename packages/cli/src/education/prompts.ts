/**
 * F019: AI prompt generator — stack-aware, copy-paste-ready prompts
 *
 * Enriches check results with detailed AI prompts that include the detected
 * tech stack, file locations, and actionable fix requests. Prompts are
 * designed to be pasted directly into Claude, ChatGPT, or any AI tool.
 */
import type { CheckResult, ScanContext, DetectedStack } from 'bastion-shared';

// ---------------------------------------------------------------------------
// Stack description
// ---------------------------------------------------------------------------

/** Build a human-readable stack description for prompt context */
export function buildStackDescription(stack: DetectedStack): string {
  const parts: string[] = [];

  if (stack.framework) {
    parts.push(stack.framework);
  } else if (stack.language !== 'unknown') {
    parts.push(`a ${stack.language} project`);
  }

  if (stack.database) parts.push(stack.database);
  if (stack.auth) parts.push(`${stack.auth} for authentication`);
  if (stack.hosting) parts.push(`deployed on ${stack.hosting}`);

  if (parts.length === 0) return '';
  return `I'm using ${parts.join(' with ')}.`;
}

/** Build a location hint for the prompt */
function locationHint(location?: string): string {
  if (!location) return '';
  return ` The issue is in \`${location}\`.`;
}

// ---------------------------------------------------------------------------
// Prompt generator type & helpers
// ---------------------------------------------------------------------------

type PromptGenerator = (result: CheckResult, context: ScanContext) => string;

function getRateLimitPackage(stack: DetectedStack): string {
  switch (stack.framework) {
    case 'express':
      return 'express-rate-limit';
    case 'fastify':
      return '@fastify/rate-limit';
    case 'next.js':
      return '@upstash/ratelimit';
    case 'hono':
      return 'the built-in hono rate limiter';
    default:
      return 'rate-limiter-flexible';
  }
}

function getRecommendedAuth(stack: DetectedStack): string {
  switch (stack.framework) {
    case 'next.js':
      return stack.database === 'supabase' ? 'Supabase Auth' : 'Clerk';
    case 'express':
    case 'fastify':
      return 'Passport.js with Auth0';
    case 'remix':
      return 'Lucia';
    default:
      return 'Clerk or Auth0';
  }
}

// ---------------------------------------------------------------------------
// Check-specific generators
// ---------------------------------------------------------------------------

const gitignorePrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const fw = context.stack.framework ?? context.stack.language;

  if (result.id === 'gitignore-missing') {
    return (
      `${stack} My project has no .gitignore file. ` +
      `Generate a comprehensive .gitignore for ${fw} that covers: ` +
      `environment files (.env*), dependencies (node_modules), ` +
      `build outputs (dist, build${context.stack.framework === 'next.js' ? ', .next' : ''}), ` +
      `IDE files, OS files (.DS_Store), and cryptographic keys (*.pem, *.key). ` +
      `Show me the complete file.`
    );
  }

  const pattern =
    result.description.match(/\(([^)]+)\)/)?.[1] ??
    result.id.replace('gitignore-', '.');
  return (
    `${stack} My .gitignore is missing \`${pattern}\`. ` +
    `Show me: (1) the exact line to add to .gitignore, ` +
    `(2) how to remove it from git history if already committed (\`git rm --cached\`), ` +
    `and (3) any related patterns I should also add for a ${fw} project.`
  );
};

const secretsPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const loc = locationHint(result.location);
  const secretType = result.name.replace('Hardcoded secret: ', '');

  return (
    `${stack}${loc} ` +
    `I found a hardcoded ${secretType} in my source code. ` +
    `Help me fix this by: ` +
    `(1) moving the value to a .env file (gitignored), ` +
    `(2) loading it via process.env in my ${context.stack.framework ?? 'Node.js'} code, ` +
    `(3) adding a placeholder to .env.example, ` +
    `and (4) adding a startup check that validates the variable is set. ` +
    `Show me the complete code changes.`
  );
};

const depVulnPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  return (
    `${stack} ${result.description} ` +
    `Help me fix this by: ` +
    `(1) updating the package safely (\`npm audit fix\` or \`npm install pkg@latest\`), ` +
    `(2) identifying any breaking changes in the new version, ` +
    `and (3) verifying the fix doesn't break my application. ` +
    `If the vulnerability can't be fixed by updating, suggest alternative packages.`
  );
};

const envExamplePrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const loc = locationHint(result.location);

  if (result.description.includes('real secret values') || result.description.includes('contain real')) {
    return (
      `${stack}${loc} ` +
      `My .env.example file contains what appear to be real secret values. ` +
      `Help me replace every real-looking value with a safe descriptive placeholder ` +
      `(e.g. YOUR_API_KEY_HERE). Add a comment above each variable explaining ` +
      `what it's for and where to get the value.`
    );
  }

  const db = context.stack.database ? ` with ${context.stack.database}` : '';
  const auth = context.stack.auth ? ` and ${context.stack.auth}` : '';
  return (
    `${stack} ` +
    `My project has a .env file (gitignored) but no .env.example template. ` +
    `Generate a .env.example that lists every required environment variable ` +
    `for a ${context.stack.framework ?? context.stack.language} project${db}${auth}. ` +
    `Use descriptive placeholders and add comments explaining each variable.`
  );
};

const securityTxtPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const hosting = context.stack.hosting;

  if (result.description.includes('expired') || result.description.includes('Expires')) {
    return (
      `${stack} ` +
      `My security.txt has an expired or missing Expires field. ` +
      `Help me update it with a valid Expires date (one year from today in RFC 3339 format) ` +
      `and verify all required fields (Contact, Expires) are present per RFC 9116.`
    );
  }

  if (result.description.includes('Contact')) {
    return (
      `${stack} ` +
      `My security.txt is missing the required Contact field (RFC 9116). ` +
      `Generate a complete security.txt with Contact (email or URL), ` +
      `Expires (one year from today), and optional fields (Preferred-Languages, Policy). ` +
      `Show me where to place it (/.well-known/security.txt).`
    );
  }

  return (
    `${stack} ` +
    `My project needs a security.txt file. ` +
    `Generate a valid security.txt per RFC 9116 with Contact, Expires, ` +
    `Preferred-Languages, and Policy fields. ` +
    `Show me where to place it in my ${context.stack.framework ?? 'web'} project` +
    `${hosting ? ` deployed on ${hosting}` : ''}.`
  );
};

const headersPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const headerName = result.name.replace('Missing ', '');
  const framework = context.stack.framework;

  if (framework === 'express' || framework === 'fastify' || framework === 'hono') {
    return (
      `${stack} My app is missing the ${headerName} security header. ` +
      `Show me how to add it using ` +
      `${framework === 'express' ? 'helmet.js middleware' : `the ${framework} equivalent`}. ` +
      `Include the recommended value and explain what attacks it prevents. ` +
      `Show me the complete middleware configuration.`
    );
  }

  if (framework === 'next.js') {
    return (
      `${stack} My app is missing the ${headerName} security header. ` +
      `Show me how to add it in next.config.js using the headers() function. ` +
      `Include the recommended value and explain what attacks it prevents.`
    );
  }

  return (
    `${stack} My web app is missing the ${headerName} security header. ` +
    `${result.description} ` +
    `Show me how to configure it with the recommended value for my framework.`
  );
};

const sslPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const hosting = context.stack.hosting;
  const managed = hosting === 'vercel' || hosting === 'netlify';

  if (result.id.includes('redirect')) {
    if (managed) {
      return (
        `${stack} My site does not redirect HTTP to HTTPS. ` +
        `Since I'm on ${hosting}, this should be automatic. ` +
        `Help me verify the redirect is configured correctly ` +
        `and show how to force HTTPS in my ${context.stack.framework ?? 'web'} app.`
      );
    }
    return (
      `${stack} My site does not redirect HTTP to HTTPS. ` +
      `Show me how to configure a permanent 301 redirect from HTTP to HTTPS ` +
      `for my web server (Nginx, Apache, or Node.js). Include HSTS header configuration.`
    );
  }

  if (managed) {
    return (
      `${stack} ${result.description} ` +
      `Since I'm on ${hosting}, SSL should be handled automatically. ` +
      `Help me verify the certificate is configured correctly and troubleshoot the issue.`
    );
  }

  return (
    `${stack} ${result.description} ` +
    `Help me set up a valid SSL certificate using Let's Encrypt and Certbot. ` +
    `Show me: (1) how to install Certbot, (2) how to obtain a certificate, ` +
    `(3) how to configure automatic renewal, and (4) how to set up HTTPS in my web server.`
  );
};

const codePatternsPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const loc = locationHint(result.location);
  const patternName = result.name.replace('Insecure pattern: ', '');
  const fw = context.stack.framework ?? 'my framework';

  return (
    `${stack}${loc} ` +
    `I have an insecure code pattern: ${patternName}. ` +
    `${result.fix ?? result.description} ` +
    `Show me: (1) why this is dangerous with an exploit example, ` +
    `(2) the safe replacement code for ${fw}, ` +
    `and (3) an ESLint rule or equivalent to prevent this in the future.`
  );
};

const corsPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const loc = locationHint(result.location);
  const framework = context.stack.framework ?? 'my web application';

  return (
    `${stack}${loc} ` +
    `${result.description.split('.')[0]}. ` +
    `Help me fix this by: ` +
    `(1) replacing the wildcard origin with my specific domain(s), ` +
    `(2) showing the correct CORS configuration for ${framework}, ` +
    `(3) handling preflight OPTIONS requests properly, ` +
    `and (4) configuring credentials mode safely. ` +
    `Show me the complete working code.`
  );
};

const rateLimitPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const framework = context.stack.framework;
  const pkg = getRateLimitPackage(context.stack);

  return (
    `${stack} My API routes have no rate limiting. ` +
    `Generate middleware using ${pkg} that: ` +
    `(1) limits requests to 10 per 15 seconds per IP, ` +
    `(2) returns 429 with Retry-After header, ` +
    `(3) applies to all API routes` +
    `${framework === 'next.js' ? ' and works with the App Router' : ''}, ` +
    `and (4) has separate stricter limits for auth endpoints (5 per 15 minutes). ` +
    `Show me the complete working code.`
  );
};

const authPrompt: PromptGenerator = (result, context) => {
  const stack = buildStackDescription(context.stack);
  const rec = getRecommendedAuth(context.stack);

  if (result.status === 'warn') {
    return (
      `${stack} ` +
      `I'm using custom authentication instead of an established provider. ` +
      `Help me migrate to ${rec}. Show me: ` +
      `(1) installation and configuration, ` +
      `(2) protecting all API routes and pages, ` +
      `(3) complete sign-up, login, and logout flows, ` +
      `and (4) session management best practices. ` +
      `Show me the complete working code.`
    );
  }

  return (
    `${stack} ` +
    `My project has no authentication but has user-facing features. ` +
    `Help me add ${rec}. Show me: ` +
    `(1) installation and initial setup, ` +
    `(2) protecting API routes and pages, ` +
    `(3) complete sign-up, login, and logout flows, ` +
    `and (4) secure session management. ` +
    `Show me the complete working code.`
  );
};

// ---------------------------------------------------------------------------
// Generator registry — ordered longest-prefix-first
// ---------------------------------------------------------------------------

interface GeneratorMatcher {
  readonly prefix: string;
  readonly generator: PromptGenerator;
}

const GENERATOR_MATCHERS: readonly GeneratorMatcher[] = [
  { prefix: 'security-txt-url', generator: securityTxtPrompt },
  { prefix: 'security-txt', generator: securityTxtPrompt },
  { prefix: 'gitignore', generator: gitignorePrompt },
  { prefix: 'headers', generator: headersPrompt },
  { prefix: 'dep-vuln', generator: depVulnPrompt },
  { prefix: 'env-example', generator: envExamplePrompt },
  { prefix: 'code-patterns', generator: codePatternsPrompt },
  { prefix: 'ssl', generator: sslPrompt },
  { prefix: 'cors', generator: corsPrompt },
  { prefix: 'rate-limit', generator: rateLimitPrompt },
  { prefix: 'secrets', generator: secretsPrompt },
  { prefix: 'auth', generator: authPrompt },
];

/** Find the matching prompt generator for a check ID */
export function findGenerator(checkId: string): PromptGenerator | undefined {
  for (const matcher of GENERATOR_MATCHERS) {
    if (checkId === matcher.prefix || checkId.startsWith(`${matcher.prefix}-`)) {
      return matcher.generator;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Generic fallback
// ---------------------------------------------------------------------------

function buildGenericPrompt(result: CheckResult, context: ScanContext): string {
  const stack = buildStackDescription(context.stack);
  const loc = locationHint(result.location);

  return (
    `${stack}${loc} ` +
    `${result.description} ` +
    `${result.fix ? `Recommended fix: ${result.fix} ` : ''}` +
    `Help me fix this security issue. Show me the complete working code with an explanation.`
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Generate a rich, copy-paste-ready AI prompt for a single check result */
export function generatePrompt(
  result: CheckResult,
  context: ScanContext,
): string {
  const generator = findGenerator(result.id);
  if (generator) return generator(result, context);
  return buildGenericPrompt(result, context);
}

/**
 * Enrich check results with stack-aware, copy-paste-ready AI prompts.
 * Only fail/warn results are enriched; pass/skip results are returned as-is.
 * Returns new result objects (immutable).
 */
export function enrichWithAiPrompts(
  results: readonly CheckResult[],
  context: ScanContext,
): readonly CheckResult[] {
  return results.map((result) => {
    if (result.status === 'pass' || result.status === 'skip') {
      return result;
    }
    return { ...result, aiPrompt: generatePrompt(result, context) };
  });
}
