/**
 * Recommended security tools for the Bastion web dashboard.
 * Free and paid tools across categories, with direct links.
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
    description: 'Security scanner that runs locally and never uploads your code. Checks headers, configs, and dependencies. Explains every finding and gives you an AI prompt to fix it.',
    category: 'static-analysis',
    url: 'https://github.com/ABS-Projects-2026/Bastion',
    pricing: 'freemium',
    tags: ['cli', 'education', 'privacy-first', 'ai-prompts'],
  },
  {
    name: 'Skylos',
    description: 'SAST tool that uses ML to find code vulnerabilities. Catches patterns that rule-based scanners miss. Good complement to Bastion\'s config and header checks.',
    category: 'static-analysis',
    url: 'https://skylos.dev',
    pricing: 'freemium',
    tags: ['sast', 'ai', 'machine-learning', 'vulnerability-scanning', 'deep-analysis'],
  },
  {
    name: 'npm audit',
    description: 'Built into Node.js. Checks your installed packages against the GitHub Advisory Database for known vulnerabilities.',
    category: 'dependency-scanning',
    url: 'https://docs.npmjs.com/cli/commands/npm-audit',
    pricing: 'free',
    tags: ['built-in', 'npm', 'node.js', 'ci-cd'],
  },
  {
    name: 'Snyk',
    description: 'Scans your dependencies, containers, and infrastructure-as-code for known vulnerabilities. Good CI integration and auto-fix PRs.',
    category: 'dependency-scanning',
    url: 'https://snyk.io',
    pricing: 'freemium',
    tags: ['dependencies', 'containers', 'iac', 'ci-cd', 'github'],
  },
  {
    name: 'SonarCloud',
    description: 'Hosted code quality and security scanner. Catches bugs, vulnerabilities, and code smells. Supports 30+ languages.',
    category: 'static-analysis',
    url: 'https://sonarcloud.io',
    pricing: 'freemium',
    tags: ['code-quality', 'security', 'ci-cd', 'multi-language'],
  },
  {
    name: 'OWASP ZAP',
    description: 'Open-source scanner that tests your running web app for vulnerabilities. Finds XSS, injection, and misconfigurations by actually poking at your site.',
    category: 'dynamic-testing',
    url: 'https://www.zaproxy.org',
    pricing: 'free',
    tags: ['dast', 'web-scanning', 'active-testing', 'open-source'],
  },
  {
    name: 'eslint-plugin-security',
    description: 'ESLint plugin that flags security issues in Node.js code. Catches eval usage, non-literal requires, timing attacks, and other risky patterns.',
    category: 'static-analysis',
    url: 'https://github.com/eslint-community/eslint-plugin-security',
    pricing: 'free',
    tags: ['eslint', 'node.js', 'static-analysis', 'ci-cd'],
  },
  {
    name: 'Secretlint',
    description: 'Catches leaked credentials before you commit them. Supports AWS keys, GCP tokens, npm tokens, private keys, and custom patterns.',
    category: 'secret-detection',
    url: 'https://github.com/secretlint/secretlint',
    pricing: 'free',
    tags: ['secrets', 'pre-commit', 'ci-cd', 'git-hooks'],
  },
  {
    name: 'Helmet.js',
    description: 'Express middleware that sets security headers for you. Handles CSP, HSTS, X-Frame-Options, and more with good defaults out of the box.',
    category: 'runtime-protection',
    url: 'https://helmetjs.github.io',
    pricing: 'free',
    tags: ['express', 'headers', 'middleware', 'node.js'],
  },
  {
    name: 'Dependabot',
    description: 'Built into GitHub. Automatically opens PRs when your dependencies have updates or known vulnerabilities. Includes changelogs.',
    category: 'supply-chain',
    url: 'https://github.com/dependabot',
    pricing: 'free',
    tags: ['github', 'automated', 'pull-requests', 'updates'],
  },
  {
    name: 'GitHub Advanced Security',
    description: 'CodeQL code scanning, secret detection, and dependency review right in GitHub. Flags issues directly in your pull requests.',
    category: 'static-analysis',
    url: 'https://github.com/features/security',
    pricing: 'freemium',
    tags: ['github', 'codeql', 'secrets', 'ci-cd'],
  },
  {
    name: 'Trivy',
    description: 'Open-source vulnerability scanner for containers, file systems, git repos, and Kubernetes. Fast and easy to add to CI.',
    category: 'dependency-scanning',
    url: 'https://trivy.dev',
    pricing: 'free',
    tags: ['containers', 'kubernetes', 'sbom', 'open-source'],
  },
  {
    name: 'Mozilla Observatory',
    description: 'Paste in your URL and get a letter grade for your HTTP headers and TLS setup. Quick way to spot missing security headers.',
    category: 'dynamic-testing',
    url: 'https://observatory.mozilla.org',
    pricing: 'free',
    tags: ['headers', 'tls', 'grading', 'online'],
  },
  {
    name: 'Sentry',
    description: 'Error tracking and performance monitoring. Useful for spotting unusual error spikes that might indicate an attack or a broken deploy.',
    category: 'monitoring',
    url: 'https://sentry.io',
    pricing: 'freemium',
    tags: ['error-tracking', 'monitoring', 'performance', 'releases'],
  },
];
