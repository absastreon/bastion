<p align="center">
  <strong>BASTION</strong><br/>
  <em>Security scanner for web projects. Runs locally. Explains what it finds.</em>
</p>

<p align="center">
  <img alt="Build" src="https://img.shields.io/github/actions/workflow/status/absastreon/bastion/ci.yml?branch=main&style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-783%20passing-brightgreen?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img alt="npm" src="https://img.shields.io/npm/v/bastion-scan?style=flat-square" />
</p>

---

## What is this

Bastion scans your code for security issues and tells you how to fix them. It runs on your machine, never uploads your code, and works with any Node.js project.

AI tools help you build fast, but they regularly ship hardcoded secrets, missing headers, and injection vectors. Enterprise scanners cost £300+/mo and drown you in jargon. Bastion is the middle ground: it catches the stuff that actually matters and explains it in plain English.

Every finding comes with a prompt you can paste into Claude, ChatGPT, or Copilot to get a fix tailored to your stack.

---

## Quick Start

```bash
# Install globally
npm install -g bastion-scan

# Scan your project
npx bastion-scan scan

# Scan a live URL (headers, SSL, security.txt)
npx bastion-scan scan --url https://yourapp.com

# JSON output for CI/CD
npx bastion-scan scan --format json

# Generate security configs for your stack
npx bastion-scan scan --generate-configs
```

---

## What it checks

| Check | What it does |
|-------|-------------|
| `.gitignore` coverage | Makes sure `.env`, `node_modules`, and keys are excluded |
| Hardcoded secrets | API keys from OpenAI, Anthropic, GitHub, Stripe, AWS, Google, Slack, and more |
| Dependency audit | Wraps `npm audit` and maps findings to severity levels |
| `.env.example` | Checks that a template exists with safe placeholder values |
| `security.txt` | Validates RFC 9116 Contact + Expires fields |
| Security headers | CSP, HSTS, X-Frame-Options, Referrer-Policy, and more |
| SSL/TLS | HTTPS redirect, cert validity, TLS version |
| Insecure code patterns | `eval()`, `innerHTML`, SQL concatenation, `exec()` |
| CORS config | Catches `Allow-Origin: *`, bare `cors()`, credential leaks |
| Rate limiting | Looks for `express-rate-limit`, `@upstash/ratelimit`, etc. |
| Auth method | Flags hand-rolled auth, suggests Clerk/Supabase/NextAuth |
| `security.txt` URL | Fetches and validates the remote file |

### Stack detection

Bastion figures out what you're running. It detects **Next.js, Express, Fastify, Remix, Astro, Nuxt, SvelteKit, Hono**, plus databases, auth providers, hosting, and package managers. AI prompts and config suggestions are tailored to your stack.

### Output formats

Three options: **terminal** (colour-coded, score ring, verbose mode), **JSON** (for CI/CD), and **markdown** (writes a `security-report.md`).

### Config generators

Bastion can output ready-to-paste configs for your stack:

- `helmet.js` setup for Express/Fastify
- CORS policy
- Rate limiter middleware
- Next.js security headers
- `.gitignore` additions

### security.txt generator

Interactive CLI that walks you through creating a valid RFC 9116 `security.txt`:

```bash
npx bastion-scan generate security-txt
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

The web dashboard lives at [bastion.wiki](https://bastion.wiki).

- **Security Checklist** with 20 interactive items and fix panels
- **OWASP 2025** guide, all 10 categories in plain language
- **URL Scanner** for quick header/SSL/security.txt checks
- **Vulnerability Feed** with current threats and AI coding risks
- **Tool Recommendations**, 14 curated tools with pricing info
- **Stack Checklists** generated for your framework + database + auth combo
- **Deploy Gate** that runs checks and gives a go/no-go verdict
- **Security Badge** you can embed in your README

---

## Pricing

| | Free | Pro | Team |
|---|---|---|---|
| **Price** | £0 | £4/mo or £39/yr | £15/mo or £119/yr |
| CLI checks | 5 | All 12 | All 12 |
| URL scans | 1/day | Unlimited | Unlimited |
| AI prompts | 3/scan | Unlimited | Unlimited |
| Config generators | | Yes | Yes |
| Security badge | | Yes | Yes |
| GitHub Action | | Public repos | All repos |
| Projects | 1 | 3 | Unlimited |
| Compliance reports | | | Yes |
| CVE alerts | | | Yes |
| Score history | | | Yes |

Annual plans save 2 months. All plans come with a 14-day free trial.

---

## Security Badge

Drop this in your README to show your score:

```markdown
![Bastion Score](https://bastion.wiki/api/badge/85)
```

The shield is green at 80+, yellow at 50+, red below 50. It updates when you re-scan.

---

## GitHub Action

Add this to your CI and Bastion will scan every PR:

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

You start at **100**. Points come off by severity:

| Severity | Deduction |
|----------|-----------|
| Critical | -15 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

Floor is 0. Only `fail` results deduct. `warn`, `skip`, and `pass` don't affect the score.

---

## Project Structure

```
bastion/
├── packages/
│   ├── cli/          # npx bastion-scan scan, 12 checks, 3 reporters
│   ├── shared/       # Types, checklist data, OWASP data, tools
│   └── web/          # Next.js 14 dashboard
└── docs/playbooks/   # Stack-specific security guides
```

---

## Contributing

PRs are welcome.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Write tests (Vitest, 80%+ coverage required)
4. Run `npm run build && npm run lint && npm run test`
5. Open a PR against `main`

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Links

- [Web Dashboard](https://bastion.wiki)
- [CLI Docs](https://bastion.wiki/docs)
- [Stack Playbooks](docs/playbooks/)
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [Report a Bug](https://github.com/absastreon/bastion/issues)
