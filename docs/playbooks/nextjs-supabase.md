# Securing a Next.js + Supabase App

A practical security guide for developers using Next.js with Supabase. No prior security experience needed.

---

## 1. Understand Your Supabase Keys

Supabase gives you two keys. Using the wrong one is the most common security mistake.

| Key | Where to use | What it can do |
|-----|-------------|----------------|
| `anon` (public) | Browser, client components | Only what RLS policies allow |
| `service_role` (secret) | Server only (API routes, Server Actions) | Bypasses all RLS — full database access |

```env
# .env.local
NEXT_PUBLIC_SUPABASE_URL=https://xyz.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...      # Safe for browser
SUPABASE_SERVICE_ROLE_KEY=eyJ...           # NEVER expose to client
```

**Rule:** If a key starts with `NEXT_PUBLIC_`, it ships to the browser. Your `service_role` key must NEVER have that prefix.

---

## 2. Enable Row Level Security (RLS)

RLS is Supabase's most important security feature. Without it, anyone with your `anon` key can read and write your entire database.

```sql
-- Step 1: Enable RLS on every table
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Step 2: Create policies that restrict access
-- Users can only read their own profile
CREATE POLICY "Users read own profile"
  ON profiles FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only update their own profile
CREATE POLICY "Users update own profile"
  ON profiles FOR UPDATE
  USING (auth.uid() = user_id);
```

**Check yourself:** Go to Supabase Dashboard > Table Editor. Every table should show "RLS enabled". If any table says "RLS disabled", fix it now.

**Common AI mistake:** AI tools often create tables without RLS policies, or add `USING (true)` which allows anyone to access everything.

---

## 3. Auth Session Handling with @supabase/ssr

Never roll your own session handling. Use the official `@supabase/ssr` package.

```bash
npm install @supabase/ssr @supabase/supabase-js
```

Create a server client for use in Server Components and API routes:

```typescript
// lib/supabase/server.ts
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (cookiesToSet) => {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          );
        },
      },
    }
  );
}
```

---

## 4. Protect API Routes with Middleware

Use Next.js middleware to check auth before requests reach your API routes:

```typescript
// middleware.ts (project root)
import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const response = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (cookiesToSet) => {
          cookiesToSet.forEach(({ name, value, options }) => {
            response.cookies.set(name, value, options);
          });
        },
      },
    }
  );

  const { data: { user } } = await supabase.auth.getUser();

  // Redirect unauthenticated users away from protected routes
  if (!user && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return response;
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/:path*'],
};
```

---

## 5. Set CSP Headers in next.config.js

Content Security Policy headers prevent XSS attacks by controlling what scripts can run:

```javascript
// next.config.mjs
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      `connect-src 'self' ${process.env.NEXT_PUBLIC_SUPABASE_URL}`,
      "img-src 'self' data: blob:",
      "style-src 'self' 'unsafe-inline'",
    ].join('; '),
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
];

const nextConfig = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};

export default nextConfig;
```

---

## 6. Rate Limiting with @upstash/ratelimit

Without rate limiting, anyone can spam your API endpoints. Upstash provides a serverless-friendly solution:

```bash
npm install @upstash/ratelimit @upstash/redis
```

```typescript
// lib/rate-limit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '60 s'), // 10 requests per minute
});
```

```typescript
// app/api/scan/route.ts
import { ratelimit } from '@/lib/rate-limit';
import { NextResponse, type NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const { success } = await ratelimit.limit(ip);

  if (!success) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429 }
    );
  }

  // ... handle request
}
```

---

## 7. Common Mistakes AI Tools Make with Supabase

Watch for these when reviewing AI-generated code:

| Mistake | Why it's dangerous | Fix |
|---------|-------------------|-----|
| Using `service_role` key in client code | Full database access from browser | Use `anon` key + RLS |
| Tables without RLS policies | Anyone can read/write all data | Enable RLS on every table |
| `USING (true)` RLS policies | Allows all access, same as no RLS | Write specific conditions with `auth.uid()` |
| Storing sessions in `localStorage` | Vulnerable to XSS | Use `@supabase/ssr` cookie-based sessions |
| Skipping `getUser()` validation | Trusting client-provided auth state | Always call `getUser()` server-side |
| No rate limiting on API routes | Easy to DDoS or brute-force | Add `@upstash/ratelimit` |

---

## Quick Checklist

- [ ] `SUPABASE_SERVICE_ROLE_KEY` does NOT start with `NEXT_PUBLIC_`
- [ ] Every table has RLS enabled with specific policies
- [ ] Using `@supabase/ssr` for auth (not `localStorage`)
- [ ] Middleware protects `/dashboard` and `/api` routes
- [ ] CSP headers set in `next.config.mjs`
- [ ] Rate limiting on all public API routes
- [ ] No `USING (true)` RLS policies

---

*Generated by [Bastion](https://github.com/ABS-Projects-2026/Bastion) — privacy-first security checker.*
