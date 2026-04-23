<p align="center">
  <strong>🛡️ BASTION</strong><br/>
  <em>Privacy-first security checker for AI-era builders</em>
</p>

<p align="center">
  <img alt="Build" src="https://img.shields.io/github/actions/workflow/status/absastreon/bastion/ci.yml?branch=main&style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-744%20passing-brightgreen?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img alt="npm" src="https://img.shields.io/npm/v/@bastion/cli?style=flat-square" />
</p>

---

## Why Bastion?

AI tools help you build fast — but they routinely ship code with hardcoded secrets, missing security headers, and SQL injection vectors. Enterprise security scanners cost $350+/mo and bury developers in jargon. Nobody teaches the security basics that actually matter.

**Bastion scans your project locally, explains every finding in plain language, and gives you an AI prompt to paste for an instant fix.** No code leaves your machine. Ever.

---

## Quick Start

```bash
# Install globally
npm install -g @bastion/cli

# Scan your project
npx bastion scan

# Scan with a live URL (checks headers, SSL, security.txt)
npx bastion scan --url https://yourapp.com

# Output as JSON for CI/CD
npx bastion scan --format json

# Generate security configs for your stack
npx bastion scan --generate-configs
```

---

## Features

### 12 Security Checks

| Check | What it does |
|-------|-------------|
| `.gitignore` coverage | Verifies `.env`, `node_modules`, keys are excluded |
| Hardcoded secrets | Scans for API keys (OpenAI, Stripe, AWS, generic) |
| Dependency audit | Wraps `npm audit`, maps to severity levels |
| `.env.example` | Verifies template exists with safe placeholders |
| `security.txt` | Validates RFC 9116 Contact + Expires fields |
| Security headers | CSP, HSTS, X-Frame-Options, Referrer-Policy, more |
| SSL/TLS | HTTPS redirect, certificate validity, TLS version |
| Insecure code | `eval()`, `innerHTML`, SQL concat, `exec()` injection |
| CORS config | Detects `Allow-Origin: *`, bare `cors()`, credential escalation |
| Rate limiting | Checks for `express-rate-limit`, `@upstash/ratelimit`, etc. |
| Auth method | Flags custom auth, recommends Clerk/Supabase/NextAuth |
| `security.txt` URL | Fetches and validates remote security.txt |

### Stack Detection

Auto-detects **Next.js, Express, Fastify, Remix, Astro, Nuxt, SvelteKit, Hono** plus databases, auth providers, hosting, and package managers. Tailors AI prompts and config suggestions to your stack.

### 3 Output Formats

- **Terminal** — colour-coded with severity icons, score ring, verbose mode
- **JSON** — machine-readable for CI/CD pipelines
- **Markdown** — generates `security-report.md` with full findings

### AI Fix Prompts

Every finding includes a stack-aware prompt you can paste into Claude, ChatGPT, or Copilot for an instant, contextual fix.

### Config Generators

Outputs ready-to-paste security configs:
- `helmet.js` setup (Express/Fastify)
- CORS configuration
- Rate limiter middleware
- Next.js security headers
- `.gitignore` additions

### security.txt Generator

Interactive CLI to create a valid RFC 9116 `security.txt`:

```bash
npx bastion generate security-txt
```

---

## CLI Usage

```
bastion scan [options]

Options:
  -p, --path <dir>          Project path (default: current directory)
  -f, --format <type>       Output format: terminal, json, markdown
  -u, --url <url>           Live URL to scan (headers, SSL, security.txt)
  -v, --verbose             Show fix instructions and AI prompts
  --generate-configs        Print security config snippets for your stack
  --output-dir <dir>        Write config files to directory
```

---

## Web App

The Bastion web dashboard at [bastion.dev](https://bastion.dev) provides:

- **Security Checklist** — 20 interactive items with expand/collapse fix panels
- **OWASP 2025** — All 10 categories with plain-language explanations and AI prompts
- **URL Scanner** — Enter a URL, get instant results for headers, SSL, security.txt
- **Vulnerability Feed** — Current threats, AI coding risks, and recent breaches
- **Recommended Tools** — 14 curated tools with search, filtering, and pricing info
- **Stack Checklists** — Auto-generated checklists for your framework + database + auth combo
- **Deploy Gate** — Pre-deploy security check runner with go/no-go verdict
- **Security Badge** — Embeddable SVG for your GitHub README

---

## Pricing

| | Free | Pro | Team |
|---|---|---|---|
| **Price** | $0 | $5/mo or $49/yr | $19/mo or $149/yr |
| CLI checks | 5 | All 12 | All 12 |
| URL scans | 1/day | Unlimited | Unlimited |
| AI prompts | 3/scan | Unlimited | Unlimited |
| Config generators | — | Yes | Yes |
| Security badge | — | Yes | Yes |
| GitHub Action | — | Public repos | All repos |
| Projects | 1 | 3 | Unlimited |
| Compliance reports | — | — | Yes |
| CVE alerts | — | — | Yes |
| Score history | — | — | Yes |

Annual plans save 2 months. All plans include a 14-day free trial.

---

## Security Badge

Add a security score badge to your README:

```markdown
![Bastion Score](https://bastion.dev/api/badge/85)
```

Renders as a colour-coded shield (green >= 80, yellow >= 50, red < 50). Score updates when you re-scan.

---

## GitHub Action

Add Bastion to your CI pipeline:

```yaml
name: Security Scan
on: [pull_request]

jobs:
  bastion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: absastreon/bastion-action@v1
        with:
          path: '.'
          fail-on: 'critical'    # Block PRs with critical findings
          format: 'markdown'     # Comment results on PR
```

---

## Scoring

Starts at **100**. Deductions by severity:

| Severity | Deduction |
|----------|-----------|
| Critical | -15 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

Minimum score is 0. Only `fail` results deduct — `warn`, `skip`, and `pass` do not.

---

## Project Structure

```
bastion/
├── packages/
│   ├── cli/          # npx bastion scan — 12 checks, 3 reporters
│   ├── shared/       # Types, checklist data, OWASP data, tools
│   └── web/          # Next.js 14 dashboard
└── docs/playbooks/   # Stack-specific security guides
```

---

## Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Write tests (we use Vitest, 80%+ coverage required)
4. Run `npm run build && npm run lint && npm run test`
5. Open a PR against `main`

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

MIT - see [LICENSE](LICENSE) for details.

---

## Links

- [Web Dashboard](https://bastion.dev)
- [CLI Documentation](https://bastion.dev/docs)
- [Stack Playbooks](docs/playbooks/)
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [Report a Bug](https://github.com/absastreon/bastion/issues)
