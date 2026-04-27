# Security Checklist for AI-Built Apps

If you used ChatGPT, Claude, Copilot, or any AI tool to write your code, this guide is for you. AI code generators make specific, predictable security mistakes. Here's how to find and fix them.

---

## The Problem

AI tools write code that *looks* correct but often has subtle security gaps. The code compiles, the tests pass, and the app works — but it's vulnerable. These aren't random bugs. They're patterns that show up across every AI tool.

---

## 1. Phantom Function Calls

AI tools sometimes call security functions that don't exist. The code looks like it's doing the right thing, but the function was never imported, defined, or installed.

```typescript
// AI generated this — looks secure, right?
import { sanitizeInput } from './utils/security';

app.post('/api/comment', async (req, res) => {
  const clean = sanitizeInput(req.body.comment); // Looks real
  await db.comments.create({ text: clean });
});
```

**The problem:** `sanitizeInput` was never created. The import will throw at runtime, or worse, the AI defines it as a passthrough:

```typescript
// AI's "implementation" in utils/security.ts
export function sanitizeInput(input: string): string {
  return input; // Does literally nothing
}
```

**How to check:**
1. Search your codebase for security-sounding function names: `sanitize`, `validate`, `encrypt`, `authorize`
2. For each one, read the actual implementation — does it do what the name promises?
3. Run your app and trigger each code path to verify functions exist

---

## 2. Hardcoded Test Credentials

AI tools often include working API keys, passwords, or tokens as "examples" that never get replaced.

```typescript
// AI left these as "examples"
const ADMIN_PASSWORD = 'admin123';
const JWT_SECRET = 'super-secret-key-change-me';
const API_KEY = 'sk-test-xxxxxxxxxxxxxxxxxxxx';
```

**How to check:**
1. Search for strings like `password`, `secret`, `key`, `token` in your source files
2. Look for `TODO`, `CHANGE`, `REPLACE`, `FIXME` near credentials
3. Run `npx bastion-scan scan` — it detects hardcoded secret patterns

**Fix:** Move all secrets to environment variables:

```typescript
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}
```

---

## 3. Missing Input Validation

AI tools often skip validation entirely, or add it to some endpoints but not others.

```typescript
// AI generated — no validation at all
app.post('/api/users', async (req, res) => {
  const user = await db.users.create(req.body); // Trusts everything
  res.json(user);
});
```

**The fix:** Validate at every system boundary:

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100).trim(),
});

app.post('/api/users', async (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const user = await db.users.create(parsed.data);
  return res.json(user);
});
```

---

## 4. eval() and Dynamic Code Execution

AI tools sometimes use `eval()`, `new Function()`, or child process execution with user input. These let attackers run arbitrary code on your server.

```typescript
// AI generated — allows arbitrary code execution
app.get('/api/calculate', (req, res) => {
  const result = eval(req.query.expression as string);
  res.json({ result });
});
```

```typescript
// Also dangerous — AI sometimes generates this
import { exec } from 'child_process';

app.post('/api/convert', (req, res) => {
  exec(`convert ${req.body.filename} output.pdf`, (err, stdout) => {
    // Attacker sends filename: "; rm -rf /"
  });
});
```

**How to check:**
1. Search for `eval(`, `new Function(`, `exec(`, `execSync(`, `spawn(`
2. If any of these use user input, they're critical vulnerabilities
3. Run `npx bastion-scan scan` — it detects these patterns automatically

**Fix:** Use safe alternatives. For math: a parser library. For shell commands: `execFile` with explicit args (no string interpolation).

---

## 5. Placeholder Auth That Looks Real

This is the most dangerous pattern. AI tools create authentication systems that have all the right function names and structure but don't actually verify anything.

```typescript
// AI's "auth middleware" — looks correct, does nothing useful
function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token) {
    req.user = { id: 'user-1', role: 'admin' }; // Always "authenticated"
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
```

**The problem:** It checks if a token *exists* but never verifies it. Anyone can send any string as a token and get admin access.

**How to check:**
1. Find your auth middleware. Read every line.
2. Does it verify the token signature? (JWT: `jwt.verify()`, not just `jwt.decode()`)
3. Does it check the user exists in the database?
4. Does it check token expiration?
5. Is the middleware actually applied to protected routes?

---

## 6. Other Common AI Mistakes

| Mistake | What to look for |
|---------|-----------------|
| CORS `origin: '*'` | Search for `cors()` with no config or `Access-Control-Allow-Origin: *` |
| No rate limiting | Check if `express-rate-limit`, `@upstash/ratelimit`, or similar is installed |
| SQL/NoSQL injection | Look for string concatenation in queries: `` `SELECT * FROM users WHERE id = '${id}'` `` |
| Missing HTTPS | Check if cookies have `secure: true` and HSTS is enabled |
| Exposed error details | Search for `stack` in error handlers — stack traces should never reach clients |
| No CSRF protection | Forms that POST without a CSRF token |

---

## How to Review AI-Generated Code

Follow this 5-step process:

1. **Map the auth flow.** Trace every request from entry to database. Where is the user verified? Is it real verification or a stub?

2. **Check every input.** Find every `req.body`, `req.query`, `req.params`, form field, and URL parameter. Is it validated before use?

3. **Search for danger patterns.** Run these searches across your codebase:
   ```bash
   # Dangerous functions
   grep -rn "eval\|new Function\|exec(" src/

   # Hardcoded secrets
   grep -rn "password.*=.*['\"]" src/

   # Missing validation
   grep -rn "req\.body\." src/
   ```

4. **Verify dependencies are real.** Check `package.json` — are the security packages actually installed and imported?

5. **Run automated tools.** Use tools built to catch what humans miss:
   - **[Bastion](https://github.com/ABS-Projects-2026/Bastion)** — security checker for AI-built apps (15 checks, AI-generated fix prompts)
   - **[Skylos](https://github.com/ABS-Projects-2026/Skylos)** — dead code detection (finds unused security functions)
   - **Dependabot** — alerts for vulnerable dependencies (built into GitHub)
   - **`npm audit`** — checks for known vulnerabilities in dependencies

---

## Quick Checklist

Run through this before every deploy:

- [ ] All security functions have real implementations (not passthroughs)
- [ ] No hardcoded passwords, API keys, or tokens in source files
- [ ] Every API endpoint validates its input
- [ ] No `eval()`, `new Function()`, or `exec()` with user input
- [ ] Auth middleware actually verifies tokens (not just checks existence)
- [ ] CORS is configured with specific origins (not wildcard)
- [ ] Rate limiting is enabled on all public endpoints
- [ ] Error responses don't include stack traces
- [ ] `npm audit` shows no critical or high vulnerabilities
- [ ] Run `npx bastion-scan scan` — score 80+

---

*Generated by [Bastion](https://github.com/ABS-Projects-2026/Bastion) — security for AI-era builders.*
