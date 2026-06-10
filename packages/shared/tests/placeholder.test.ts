import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { VERSION } from '../src/index.js';

// Read the sibling package.json at runtime so we don't depend on TS JSON
// module attributes (avoids rootDir/composite/NodeNext friction).
const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(here, '..', 'package.json'), 'utf-8'),
) as { version: string };

describe('@bastion/shared', () => {
  it('VERSION matches package.json version', () => {
    // Pinning to package.json rather than a literal so version bumps don't
    // silently re-break this test (regression: commit 97e5494 bumped the
    // constant to 0.2.1 but left the assertion at 0.1.0).
    expect(VERSION).toBe(pkg.version);
  });
});
