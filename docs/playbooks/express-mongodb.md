# Securing an Express + MongoDB App

A practical security guide for developers building APIs with Express and MongoDB. No prior security experience needed.

---

## 1. Helmet.js — Security Headers in One Line

Helmet sets HTTP security headers that protect against common attacks like XSS, clickjacking, and MIME sniffing.

```bash
npm install helmet
```

```typescript
import express from 'express';
import helmet from 'helmet';

const app = express();

// Add security headers — do this BEFORE any route definitions
app.use(helmet());
```

That one line sets 11 security headers. You can customize specific headers:

```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));
```

---

## 2. MongoDB Injection Prevention

MongoDB is vulnerable to NoSQL injection. Unlike SQL injection, it uses JavaScript objects instead of strings.

**The attack:** A user sends `{ "$gt": "" }` instead of a real value, which matches every document.

```typescript
// DANGEROUS: Raw user input in queries
app.post('/api/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    email: req.body.email,       // Could be { "$gt": "" }
    password: req.body.password, // Could be { "$gt": "" }
  });
});
```

**Fix 1:** Install `express-mongo-sanitize` to strip `$` operators from input:

```bash
npm install express-mongo-sanitize
```

```typescript
import mongoSanitize from 'express-mongo-sanitize';

app.use(express.json());
app.use(mongoSanitize()); // Strips $ and . from req.body, req.query, req.params
```

**Fix 2:** Never use `$where` — it executes JavaScript on the server:

```typescript
// NEVER do this
db.collection('users').find({ $where: `this.role === '${role}'` });

// Instead, use standard query operators
db.collection('users').find({ role: role });
```

---

## 3. CORS Configuration

CORS controls which websites can call your API. Getting it wrong means any website can make requests to your server.

```bash
npm install cors
```

```typescript
import cors from 'cors';

// DANGEROUS: Allows any website to access your API
app.use(cors()); // DO NOT use this in production

// CORRECT: Only allow your frontend
app.use(cors({
  origin: ['https://yourapp.com', 'https://www.yourapp.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true, // Only if you need cookies/auth headers
}));
```

For multiple environments:

```typescript
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') ?? [];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));
```

---

## 4. Rate Limiting

Without rate limiting, attackers can brute-force passwords, scrape data, or crash your server.

```bash
npm install express-rate-limit
```

```typescript
import rateLimit from 'express-rate-limit';

// General rate limit — 100 requests per 15 minutes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests, try again later' },
});

app.use(generalLimiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: { error: 'Too many login attempts, try again in 15 minutes' },
});

app.use('/api/auth', authLimiter);
```

---

## 5. Session Management

Secure session storage with `express-session` and `connect-mongo`:

```bash
npm install express-session connect-mongo
```

```typescript
import session from 'express-session';
import MongoStore from 'connect-mongo';

app.use(session({
  secret: process.env.SESSION_SECRET!, // Long random string from env
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60, // 1 day in seconds
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    httpOnly: true,   // JavaScript can't access the cookie
    sameSite: 'lax',  // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
  },
}));
```

**Key settings:**
- `httpOnly: true` — prevents XSS from stealing session cookies
- `secure: true` — only sends cookies over HTTPS
- `sameSite: 'lax'` — prevents CSRF attacks
- Never use the default in-memory store in production (it leaks memory)

---

## 6. Input Validation with Zod

Validate every piece of user input before processing it. Zod gives you type-safe validation:

```bash
npm install zod
```

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).trim(),
});

app.post('/api/users', async (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid input',
      details: parsed.error.issues,
    });
  }

  // parsed.data is fully typed and validated
  const user = await createUser(parsed.data);
  return res.status(201).json({ data: user });
});
```

Validate route params too:

```typescript
const idSchema = z.object({
  id: z.string().regex(/^[a-f\d]{24}$/i, 'Invalid MongoDB ObjectId'),
});

app.get('/api/users/:id', async (req, res) => {
  const parsed = idSchema.safeParse(req.params);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  // ...
});
```

---

## 7. Common Mistakes AI Tools Make with Express

Watch for these when reviewing AI-generated code:

| Mistake | Why it's dangerous | Fix |
|---------|-------------------|-----|
| `app.use(cors())` with no options | Any website can call your API | Specify exact `origin` list |
| No rate limiting | Brute-force and DDoS attacks | Add `express-rate-limit` |
| `req.body` directly in MongoDB queries | NoSQL injection | Use `express-mongo-sanitize` + Zod |
| `$where` in MongoDB queries | Server-side JavaScript injection | Use standard query operators |
| Default in-memory session store | Memory leaks, lost sessions | Use `connect-mongo` or Redis |
| `cookie.secure: false` in production | Cookies sent over HTTP | Set `secure: true` in production |
| No `helmet()` middleware | Missing all security headers | Add `helmet()` before routes |
| Error stack traces in responses | Leaks internal details | Use generic messages in production |

---

## Quick Checklist

- [ ] `helmet()` added before all route definitions
- [ ] `express-mongo-sanitize` strips `$` from all input
- [ ] No `$where` queries anywhere in the codebase
- [ ] CORS `origin` specifies exact allowed domains (not `*`)
- [ ] Rate limiting on all routes, stricter on auth
- [ ] Sessions use `connect-mongo`, not in-memory store
- [ ] All cookies: `httpOnly`, `secure`, `sameSite`
- [ ] Every endpoint validates input with Zod
- [ ] Error responses don't include stack traces

---

*Generated by [Bastion](https://github.com/absastreon/bastion) — privacy-first security checker.*
