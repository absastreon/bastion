import { describe, it, expect } from 'vitest';
import { detectStack } from '../../src/detectors/stack.js';

/** Helper: build a minimal package.json object */
function makePkg(
  deps?: Record<string, string>,
  devDeps?: Record<string, string>,
): Record<string, unknown> {
  return {
    name: 'test-project',
    version: '1.0.0',
    ...(deps ? { dependencies: deps } : {}),
    ...(devDeps ? { devDependencies: devDeps } : {}),
  };
}

// ---------------------------------------------------------------------------
// Framework detection
// ---------------------------------------------------------------------------

describe('detectStack — framework', () => {
  it('detects Next.js', () => {
    expect(detectStack(makePkg({ next: '^14.0.0' }), []).framework).toBe('next.js');
  });

  it('detects Express', () => {
    expect(detectStack(makePkg({ express: '^4.18.0' }), []).framework).toBe('express');
  });

  it('detects Fastify', () => {
    expect(detectStack(makePkg({ fastify: '^4.0.0' }), []).framework).toBe('fastify');
  });

  it('detects Remix via @remix-run/node', () => {
    expect(detectStack(makePkg({ '@remix-run/node': '^2.0.0' }), []).framework).toBe('remix');
  });

  it('detects Remix via @remix-run/react', () => {
    expect(detectStack(makePkg({ '@remix-run/react': '^2.0.0' }), []).framework).toBe('remix');
  });

  it('detects Astro', () => {
    expect(detectStack(makePkg({ astro: '^4.0.0' }), []).framework).toBe('astro');
  });

  it('detects Nuxt', () => {
    expect(detectStack(makePkg({ nuxt: '^3.0.0' }), []).framework).toBe('nuxt');
  });

  it('detects SvelteKit', () => {
    expect(detectStack(makePkg({ '@sveltejs/kit': '^2.0.0' }), []).framework).toBe('sveltekit');
  });

  it('detects Hono', () => {
    expect(detectStack(makePkg({ hono: '^4.0.0' }), []).framework).toBe('hono');
  });

  it('returns undefined when no framework found', () => {
    expect(detectStack(makePkg({ lodash: '^4.0.0' }), []).framework).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Database detection
// ---------------------------------------------------------------------------

describe('detectStack — database', () => {
  it('detects Supabase', () => {
    expect(detectStack(makePkg({ '@supabase/supabase-js': '^2.0.0' }), []).database).toBe('supabase');
  });

  it('detects Prisma via @prisma/client', () => {
    expect(detectStack(makePkg({ '@prisma/client': '^5.0.0' }), []).database).toBe('prisma');
  });

  it('detects Prisma via devDependencies', () => {
    expect(detectStack(makePkg({}, { prisma: '^5.0.0' }), []).database).toBe('prisma');
  });

  it('detects Drizzle', () => {
    expect(detectStack(makePkg({ 'drizzle-orm': '^0.30.0' }), []).database).toBe('drizzle');
  });

  it('detects Mongoose', () => {
    expect(detectStack(makePkg({ mongoose: '^7.0.0' }), []).database).toBe('mongoose');
  });

  it('detects TypeORM', () => {
    expect(detectStack(makePkg({ typeorm: '^0.3.0' }), []).database).toBe('typeorm');
  });

  it('detects Sequelize', () => {
    expect(detectStack(makePkg({ sequelize: '^6.0.0' }), []).database).toBe('sequelize');
  });
});

// ---------------------------------------------------------------------------
// Auth detection
// ---------------------------------------------------------------------------

describe('detectStack — auth', () => {
  it('detects Clerk', () => {
    expect(detectStack(makePkg({ '@clerk/nextjs': '^5.0.0' }), []).auth).toBe('clerk');
  });

  it('detects Auth0', () => {
    expect(detectStack(makePkg({ '@auth0/nextjs-auth0': '^3.0.0' }), []).auth).toBe('auth0');
  });

  it('detects NextAuth', () => {
    expect(detectStack(makePkg({ 'next-auth': '^4.0.0' }), []).auth).toBe('next-auth');
  });

  it('detects Auth.js via @auth/core', () => {
    expect(detectStack(makePkg({ '@auth/core': '^0.30.0' }), []).auth).toBe('next-auth');
  });

  it('detects Supabase Auth via @supabase/ssr', () => {
    expect(detectStack(makePkg({ '@supabase/ssr': '^0.3.0' }), []).auth).toBe('supabase-auth');
  });

  it('detects Passport', () => {
    expect(detectStack(makePkg({ passport: '^0.7.0' }), []).auth).toBe('passport');
  });

  it('detects Lucia', () => {
    expect(detectStack(makePkg({ lucia: '^3.0.0' }), []).auth).toBe('lucia');
  });
});

// ---------------------------------------------------------------------------
// Hosting detection
// ---------------------------------------------------------------------------

describe('detectStack — hosting', () => {
  it('detects Vercel from vercel.json', () => {
    expect(detectStack(makePkg(), ['vercel.json']).hosting).toBe('vercel');
  });

  it('detects Netlify from netlify.toml', () => {
    expect(detectStack(makePkg(), ['netlify.toml']).hosting).toBe('netlify');
  });

  it('detects Docker from Dockerfile', () => {
    expect(detectStack(makePkg(), ['Dockerfile']).hosting).toBe('docker');
  });

  it('returns undefined when no hosting clue', () => {
    expect(detectStack(makePkg(), ['package.json']).hosting).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

describe('detectStack — language', () => {
  it('detects TypeScript from root tsconfig.json', () => {
    expect(detectStack(makePkg(), ['tsconfig.json']).language).toBe('typescript');
  });

  it('detects TypeScript from nested tsconfig.json', () => {
    expect(detectStack(makePkg(), ['packages/app/tsconfig.json']).language).toBe('typescript');
  });

  it('defaults to javascript when package.json exists', () => {
    expect(detectStack(makePkg(), []).language).toBe('javascript');
  });

  it('defaults to unknown when no package.json', () => {
    expect(detectStack(undefined, []).language).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

describe('detectStack — packageManager', () => {
  it('detects npm from package-lock.json', () => {
    expect(detectStack(makePkg(), ['package-lock.json']).packageManager).toBe('npm');
  });

  it('detects yarn from yarn.lock', () => {
    expect(detectStack(makePkg(), ['yarn.lock']).packageManager).toBe('yarn');
  });

  it('detects pnpm from pnpm-lock.yaml', () => {
    expect(detectStack(makePkg(), ['pnpm-lock.yaml']).packageManager).toBe('pnpm');
  });

  it('detects bun from bun.lockb', () => {
    expect(detectStack(makePkg(), ['bun.lockb']).packageManager).toBe('bun');
  });

  it('defaults to npm when package.json exists but no lock file', () => {
    expect(detectStack(makePkg(), []).packageManager).toBe('npm');
  });

  it('returns undefined when no package.json', () => {
    expect(detectStack(undefined, []).packageManager).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Composite scenarios (user-required)
// ---------------------------------------------------------------------------

describe('detectStack — composite', () => {
  it('detects Next.js + Supabase + Vercel + TypeScript', () => {
    const pkg = makePkg(
      { next: '^14.0.0', '@supabase/supabase-js': '^2.0.0', react: '^18.0.0' },
      { typescript: '^5.0.0' },
    );
    const files = ['tsconfig.json', 'package.json', 'vercel.json', 'src/app/page.tsx'];
    const result = detectStack(pkg, files);

    expect(result.framework).toBe('next.js');
    expect(result.database).toBe('supabase');
    expect(result.language).toBe('typescript');
    expect(result.hosting).toBe('vercel');
    expect(result.dependencies).toContain('next');
    expect(result.dependencies).toContain('@supabase/supabase-js');
    expect(result.dependencies).toContain('typescript');
  });

  it('detects Express + Mongoose + JavaScript', () => {
    const pkg = makePkg({ express: '^4.18.0', mongoose: '^7.0.0' });
    const files = ['package.json', 'package-lock.json', 'src/server.js'];
    const result = detectStack(pkg, files);

    expect(result.framework).toBe('express');
    expect(result.database).toBe('mongoose');
    expect(result.language).toBe('javascript');
    expect(result.packageManager).toBe('npm');
  });

  it('handles plain Node.js with no framework', () => {
    const pkg = makePkg({ lodash: '^4.0.0' });
    const result = detectStack(pkg, ['package.json', 'index.js']);

    expect(result.framework).toBeUndefined();
    expect(result.database).toBeUndefined();
    expect(result.auth).toBeUndefined();
    expect(result.hosting).toBeUndefined();
    expect(result.language).toBe('javascript');
    expect(result.dependencies).toEqual(['lodash']);
  });

  it('handles missing package.json gracefully', () => {
    const result = detectStack(undefined, ['README.md']);

    expect(result.framework).toBeUndefined();
    expect(result.database).toBeUndefined();
    expect(result.auth).toBeUndefined();
    expect(result.hosting).toBeUndefined();
    expect(result.language).toBe('unknown');
    expect(result.packageManager).toBeUndefined();
    expect(result.dependencies).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Dependencies list
// ---------------------------------------------------------------------------

describe('detectStack — dependencies', () => {
  it('collects from both dependencies and devDependencies', () => {
    const pkg = makePkg(
      { express: '^4.0.0', lodash: '^4.0.0' },
      { typescript: '^5.0.0', vitest: '^1.0.0' },
    );
    const result = detectStack(pkg, []);

    expect(result.dependencies).toHaveLength(4);
    expect(result.dependencies).toContain('express');
    expect(result.dependencies).toContain('lodash');
    expect(result.dependencies).toContain('typescript');
    expect(result.dependencies).toContain('vitest');
  });

  it('returns empty array when package.json has no deps', () => {
    expect(detectStack(makePkg(), []).dependencies).toEqual([]);
  });

  it('returns empty array for undefined package.json', () => {
    expect(detectStack(undefined, []).dependencies).toEqual([]);
  });
});
