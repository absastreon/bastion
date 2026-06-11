import { describe, it, expect } from 'vitest';
import { normalizeFailOn, countAtOrAbove, FAIL_ON_LEVELS, FAIL_ON_CHOICES } from '../../src/utils/fail-on.js';
import type { CheckResult, Severity } from '@bastion/shared';

function result(status: CheckResult['status'], severity: Severity): CheckResult {
  return {
    id: `t-${status}-${severity}`,
    name: 'test',
    status,
    severity,
    description: 'test result',
    category: 'test',
  } as CheckResult;
}

describe('normalizeFailOn', () => {
  it('accepts every canonical level', () => {
    for (const level of FAIL_ON_LEVELS) {
      expect(normalizeFailOn(level)).toBe(level);
    }
  });

  it('normalises any to warn (alias)', () => {
    expect(normalizeFailOn('any')).toBe('warn');
  });

  it('is case-insensitive', () => {
    expect(normalizeFailOn('CRITICAL')).toBe('critical');
    expect(normalizeFailOn('Any')).toBe('warn');
  });

  it('rejects unknown values', () => {
    expect(normalizeFailOn('severe')).toBeNull();
    expect(normalizeFailOn('')).toBeNull();
    expect(normalizeFailOn('info')).toBeNull();
  });

  it('exposes any as a CLI choice but not a canonical level', () => {
    expect(FAIL_ON_CHOICES).toContain('any');
    expect(FAIL_ON_LEVELS).not.toContain('any' as never);
  });
});

describe('countAtOrAbove', () => {
  const mixed: CheckResult[] = [
    result('fail', 'critical'),
    result('fail', 'high'),
    result('fail', 'high'),
    result('fail', 'medium'),
    result('fail', 'low'),
    result('fail', 'info'),
    result('warn', 'medium'),
    result('pass', 'info'),
    result('skip', 'info'),
  ];

  it('critical counts only critical fails', () => {
    expect(countAtOrAbove(mixed, 'critical')).toBe(1);
  });

  it('high counts high and critical fails', () => {
    expect(countAtOrAbove(mixed, 'high')).toBe(3);
  });

  it('medium counts medium and above fails', () => {
    expect(countAtOrAbove(mixed, 'medium')).toBe(4);
  });

  it('low counts low and above fails, excluding info', () => {
    expect(countAtOrAbove(mixed, 'low')).toBe(5);
  });

  it('warn counts every fail (including info severity) plus warn-status results', () => {
    expect(countAtOrAbove(mixed, 'warn')).toBe(7);
  });

  it('pass and skip results never count', () => {
    expect(countAtOrAbove([result('pass', 'critical'), result('skip', 'critical')], 'warn')).toBe(0);
  });

  it('returns 0 on an empty result set at every level', () => {
    for (const level of FAIL_ON_LEVELS) {
      expect(countAtOrAbove([], level)).toBe(0);
    }
  });
});
