/**
 * --fail-on threshold logic — pure functions backing the exit-code contract.
 *
 * Contract (approved 11 June 2026):
 *   exit 0  scan completed; no failed check at/above the threshold (or no flag)
 *   exit 1  scan completed; findings at/above threshold (only with --fail-on)
 *   exit 2  scan error — the scan could not complete
 *   exit 3  usage error — invalid flag values
 *
 * Severity ladder for thresholds: critical > high > medium > low. Fails with
 * info severity sit below `low` and only trip `warn`. `warn` is the strictest
 * level: any failed check of any severity OR any warn-status result.
 * `any` is an accepted alias for `warn`.
 */
import type { CheckResult, Severity } from '@bastion/shared';

/** Canonical threshold levels, strictest last */
export const FAIL_ON_LEVELS = ['critical', 'high', 'medium', 'low', 'warn'] as const;

export type FailOnLevel = (typeof FAIL_ON_LEVELS)[number];

/** Flag values accepted on the command line (canonical levels + aliases) */
export const FAIL_ON_CHOICES = [...FAIL_ON_LEVELS, 'any'] as const;

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const THRESHOLD_RANK: Readonly<Record<Exclude<FailOnLevel, 'warn'>, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Normalise a flag value to a canonical level (`any` → `warn`). Returns null if unrecognised. */
export function normalizeFailOn(value: string): FailOnLevel | null {
  const v = value.toLowerCase();
  if (v === 'any') return 'warn';
  return (FAIL_ON_LEVELS as readonly string[]).includes(v) ? (v as FailOnLevel) : null;
}

/**
 * Count the results that trip the given threshold.
 * `warn`: every failed check plus every warn-status result.
 * Severity levels: failed checks whose severity is at or above the level.
 */
export function countAtOrAbove(results: readonly CheckResult[], level: FailOnLevel): number {
  if (level === 'warn') {
    return results.filter((r) => r.status === 'fail' || r.status === 'warn').length;
  }
  const min = THRESHOLD_RANK[level];
  return results.filter((r) => r.status === 'fail' && SEVERITY_RANK[r.severity] >= min).length;
}
