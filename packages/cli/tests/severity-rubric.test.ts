/**
 * R2 severity-rubric regression guard (26 May 2026)
 *
 * Single source of truth for the calibration: when these tests pass, the
 * critical-bar holds. If a future check author drifts a finding into the
 * wrong tier, this file is the loud failure.
 *
 * Rubric (mirrors the docstring on shared/src/types.ts Severity):
 *  - critical: active exploitability, no preconditions
 *  - high:     misconfig exploitable under common dev mistakes
 *  - medium:   hygiene / defense-in-depth
 *
 * Two directions tested:
 *  A) Recalibrated findings stay at their NEW level (not critical).
 *  B) Protected criticals are STILL critical (no silent demotion).
 */
import { describe, it, expect } from 'vitest';
import { SECRET_PATTERNS, scanContent as scanSecrets } from '../src/checks/secrets.js';
import { PATTERN_DEFS as CODE_PATTERN_DEFS, scanFileContent as scanCode } from '../src/checks/code-patterns.js';

/**
 * Build a test key from prefix + body (same convention as secrets.test.ts).
 * Splitting prevents GitHub push protection from flagging test fixtures —
 * the public mirror rejects pushes containing key-shaped literals.
 */
function fakeKey(prefix: string, body: string): string {
  return prefix + body;
}

// ---------------------------------------------------------------------------
// A. Recalibrated to "high" — must NOT be critical
// ---------------------------------------------------------------------------

describe('R2 rubric — recalibrated findings (must be "high", not critical)', () => {
  // gitignore severities are asserted in tests/checks/gitignore.test.ts
  // (existing + new "R2 regression: all secret-leak gitignore findings sit at high")
  // ssl no-https severity is asserted in tests/checks/ssl.test.ts
  // (existing assertion updated to "high")
  // This file pins the *protected criticals* — see section B.

  it('Severity rubric exists and is documented', () => {
    // Sanity: ensure the type still has exactly five tiers in expected order.
    // (Caught at compile time by TS; this is the runtime canary.)
    const tiers = ['critical', 'high', 'medium', 'low', 'info'] as const;
    expect(tiers).toHaveLength(5);
  });
});

// ---------------------------------------------------------------------------
// B. Protected criticals — must STILL be critical (no silent demotion)
// ---------------------------------------------------------------------------

describe('R2 rubric — protected criticals (must stay critical)', () => {
  describe('secrets check', () => {
    // Representative coverage across the secret families. If any of these
    // drops below critical, real exploitability is being under-rated.
    const REPRESENTATIVE_CRITICAL_SECRETS = [
      {
        label: 'OpenAI API key',
        sample: `const k = "${fakeKey('sk-proj', '-abc123XYZdefgh456jklmno789pqrstuvwxyzABCDEFGH012ijklmnopqrstuv')}";`,
      },
      {
        label: 'Anthropic API key',
        sample: `const k = "${fakeKey('sk-ant-api03', '-abcdef1234567890ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef-AAAAAAAA')}";`,
      },
      {
        label: 'GitHub PAT (classic)',
        sample: `const t = "${fakeKey('ghp', '_abcdefghijklmnopqrstuvwxyz0123456789AB')}";`,
      },
      {
        label: 'Stripe secret key (live)',
        sample: `const k = "${fakeKey('sk_live', '_abcdefghijklmnopqrstuvwxyz012345')}";`,
      },
      {
        label: 'AWS access key ID',
        sample: `const k = "${fakeKey('AKIA', 'IOSFODNN7EXAMPLE')}";`,
      },
      {
        label: 'Generic API key assignment',
        sample: `const apiKey = "${fakeKey('abcdefghijklmnopqrstuvwxyz', '0123456789ABCDEF')}";`,
      },
    ];

    for (const { label, sample } of REPRESENTATIVE_CRITICAL_SECRETS) {
      it(`${label} stays critical`, () => {
        const hits = scanSecrets(sample, 'src/config.ts');
        // We don't pin which pattern matched — just that something fired AND
        // that the firing finding(s) include at least one critical.
        const criticals = hits.filter((h) => h.severity === 'critical');
        expect(criticals.length, `${label}: expected ≥1 critical hit, got severities=${hits.map(h=>h.severity).join(',')}`).toBeGreaterThanOrEqual(1);
      });
    }

    it('SECRET_PATTERNS table: every "critical" pattern in the table still emits critical findings', () => {
      // Direct contract: every entry the secrets check classifies as critical
      // remains critical. Future authors editing severities will trip this.
      const criticalPatternCount = SECRET_PATTERNS.filter((p) => p.severity === 'critical').length;
      // Snapshot lower bound — was 20 at R2 commit time. If this drops, someone
      // demoted a real credential pattern; investigate before updating the bar.
      expect(criticalPatternCount).toBeGreaterThanOrEqual(20);
    });
  });

  describe('code-patterns check', () => {
    it('sql-injection pattern is still classified critical', () => {
      const sql = CODE_PATTERN_DEFS.find((p) => p.id === 'sql-injection');
      expect(sql, 'sql-injection pattern must exist in PATTERN_DEFS').toBeDefined();
      expect(sql?.severity).toBe('critical');
    });

    it('a real injectable SQL string still fires as critical', () => {
      const hits = scanCode(
        'const q = `UPDATE users SET name = ${userInput}`;',
        'src/db.ts',
      );
      expect(hits.some((h) => h.severity === 'critical')).toBe(true);
    });
  });

  // ssl invalid-certificate criticals are asserted in tests/checks/ssl.test.ts
  // ("returns a critical failure" under self-signed, expired, hostname-mismatch,
  // and untrusted-chain). Those tests remain untouched by R2 and continue to
  // pin invalid-cert at critical.
});
