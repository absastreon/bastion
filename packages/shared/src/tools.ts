/**
 * Recommended security tools — curated list for the Bastion web dashboard.
 * Includes free and paid tools across categories, with direct links.
 */

/** Pricing model for a security tool */
export type ToolPricing = 'free' | 'freemium' | 'paid';

/** Tool category */
export type ToolCategory =
  | 'dependency-scanning'
  | 'static-analysis'
  | 'dynamic-testing'
  | 'secret-detection'
  | 'runtime-protection'
  | 'monitoring'
  | 'code-quality'
  | 'supply-chain';

/** A recommended security tool with metadata */
export interface SecurityTool {
  readonly name: string;
  readonly description: string;
  readonly category: ToolCategory;
  readonly url: string;
  readonly pricing: ToolPricing;
  readonly tags: readonly string[];
}

/** All recommended security tools */
export const RECOMMENDED_TOOLS: readonly SecurityTool[] = [
  {
    name: 'Bastion',
    description: 'Security scanner for Cursor-generated code. Scans locally, never uploads code. 15 checks, fix explanations, and AI prompts.',
    category: 'static-analysis',
    url: 'https://github.com/ABS-Projects-2026/Bastion',
    pricing: 'free',
    tags: ['cli', 'education', 'privacy-first', 'ai-prompts'],
  },
  {
    name: 'Skylos',
    description: 'Dead code detection for TypeScript and JavaScript projects. Finds unused exports, functions, types, and modules to reduce attack surface.',
    category: 'code-quality',
    url: 'https://github.com/ABS-Projects-2026/Skylos',
    pricing: 'free',
    tags: ['dead-code', 'typescript', 'cli', 'treeshaking'],
  },
  {
    name: 'npm audit',
    description: 'Built-in Node.js dependency vulnerability scanner. Checks installed packages against the GitHub Advisory Database.',
    category: 'dependency-scanning',
    url: 'https://docs.npmjs.com/cli/commands/npm-audit',
    pricing: 'free',
    tags: ['built-in', 'npm', 'node.js', 'ci-cd'],
  },
  {
    name: 'Snyk',
    description: 'Developer-first security platform. Finds and fixes vulnerabilities in dependencies, container images, and infrastructure as code.',
    category: 'dependency-scanning',
    url: 'https://snyk.io',
    pricing: 'freemium',
    tags: ['dependencies', 'containers', 'iac', 'ci-cd', 'github'],
  },
  {
    name: 'SonarCloud',
    description: 'Cloud-based code quality and security analysis. Detects bugs, vulnerabilities, and code smells across 30+ languages.',
    category: 'static-analysis',
    url: 'https://sonarcloud.io',
    pricing: 'freemium',
    tags: ['code-quality', 'security', 'ci-cd', 'multi-language'],
  },
  {
    name: 'OWASP ZAP',
    description: 'Free, open-source dynamic application security testing (DAST) tool. Actively scans running web applications for vulnerabilities.',
    category: 'dynamic-testing',
    url: 'https://www.zaproxy.org',
    pricing: 'free',
    tags: ['dast', 'web-scanning', 'active-testing', 'open-source'],
  },
  {
    name: 'eslint-plugin-security',
    description: 'ESLint rules that identify potential security hotspots in Node.js code. Detects eval, non-literal requires, and timing attacks.',
    category: 'static-analysis',
    url: 'https://github.com/eslint-community/eslint-plugin-security',
    pricing: 'free',
    tags: ['eslint', 'node.js', 'static-analysis', 'ci-cd'],
  },
  {
    name: 'Secretlint',
    description: 'Pluggable linting tool to prevent committing credentials. Supports AWS, GCP, npm tokens, private keys, and custom patterns.',
    category: 'secret-detection',
    url: 'https://github.com/secretlint/secretlint',
    pricing: 'free',
    tags: ['secrets', 'pre-commit', 'ci-cd', 'git-hooks'],
  },
  {
    name: 'Helmet.js',
    description: 'Express.js middleware that sets security-related HTTP headers. Configures CSP, HSTS, X-Frame-Options, and more with sensible defaults.',
    category: 'runtime-protection',
    url: 'https://helmetjs.github.io',
    pricing: 'free',
    tags: ['express', 'headers', 'middleware', 'node.js'],
  },
  {
    name: 'Dependabot',
    description: 'GitHub-native automated dependency updates. Creates pull requests for outdated and vulnerable dependencies with changelogs.',
    category: 'supply-chain',
    url: 'https://github.com/dependabot',
    pricing: 'free',
    tags: ['github', 'automated', 'pull-requests', 'updates'],
  },
  {
    name: 'GitHub Advanced Security',
    description: 'Code scanning (CodeQL), secret scanning, and dependency review built into GitHub. Catches vulnerabilities in pull requests.',
    category: 'static-analysis',
    url: 'https://github.com/features/security',
    pricing: 'freemium',
    tags: ['github', 'codeql', 'secrets', 'ci-cd'],
  },
  {
    name: 'Trivy',
    description: 'Comprehensive open-source vulnerability scanner. Scans container images, file systems, git repositories, and Kubernetes clusters.',
    category: 'dependency-scanning',
    url: 'https://trivy.dev',
    pricing: 'free',
    tags: ['containers', 'kubernetes', 'sbom', 'open-source'],
  },
  {
    name: 'Mozilla Observatory',
    description: 'Free online tool that analyzes your website\'s HTTP headers, TLS configuration, and other security best practices. Provides a letter grade.',
    category: 'dynamic-testing',
    url: 'https://observatory.mozilla.org',
    pricing: 'free',
    tags: ['headers', 'tls', 'grading', 'online'],
  },
  {
    name: 'Sentry',
    description: 'Application monitoring and error tracking platform. Security-relevant for detecting anomalous errors, tracking release health, and monitoring performance.',
    category: 'monitoring',
    url: 'https://sentry.io',
    pricing: 'freemium',
    tags: ['error-tracking', 'monitoring', 'performance', 'releases'],
  },
];
