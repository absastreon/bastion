import { describe, it, expect } from 'vitest';
import {
  generateSecurityTxt,
  normalizeContact,
  validateContact,
  validateExpires,
  defaultExpiresDate,
} from '../../src/generators/security-txt.js';
import type { SecurityTxtFields } from '../../src/generators/security-txt.js';

// ---------------------------------------------------------------------------
// generateSecurityTxt
// ---------------------------------------------------------------------------

describe('generateSecurityTxt', () => {
  const baseFields: SecurityTxtFields = {
    contact: 'mailto:security@example.com',
    expires: '2027-04-15T00:00:00.000Z',
    preferredLanguages: 'en',
  };

  it('includes Contact field', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output).toContain('Contact: mailto:security@example.com');
  });

  it('includes Expires field', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output).toContain('Expires: 2027-04-15T00:00:00.000Z');
  });

  it('includes Preferred-Languages field', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output).toContain('Preferred-Languages: en');
  });

  it('includes Policy when provided', () => {
    const output = generateSecurityTxt({
      ...baseFields,
      policy: 'https://example.com/security-policy',
    });
    expect(output).toContain('Policy: https://example.com/security-policy');
  });

  it('includes Acknowledgments when provided', () => {
    const output = generateSecurityTxt({
      ...baseFields,
      acknowledgments: 'https://example.com/hall-of-fame',
    });
    expect(output).toContain('Acknowledgments: https://example.com/hall-of-fame');
  });

  it('omits Policy when not provided', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output).not.toContain('Policy:');
  });

  it('omits Acknowledgments when not provided', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output).not.toContain('Acknowledgments:');
  });

  it('starts with RFC 9116 comment header', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output.startsWith('#')).toBe(true);
    expect(output).toContain('RFC 9116');
  });

  it('ends with trailing newline', () => {
    const output = generateSecurityTxt(baseFields);
    expect(output.endsWith('\n')).toBe(true);
  });

  it('includes all fields when everything is provided', () => {
    const allFields: SecurityTxtFields = {
      ...baseFields,
      policy: 'https://example.com/policy',
      acknowledgments: 'https://example.com/thanks',
    };
    const output = generateSecurityTxt(allFields);
    expect(output).toContain('Contact:');
    expect(output).toContain('Expires:');
    expect(output).toContain('Preferred-Languages:');
    expect(output).toContain('Policy:');
    expect(output).toContain('Acknowledgments:');
  });

  it('supports https:// contact URL', () => {
    const output = generateSecurityTxt({
      ...baseFields,
      contact: 'https://example.com/security',
    });
    expect(output).toContain('Contact: https://example.com/security');
  });

  it('handles multiple preferred languages', () => {
    const output = generateSecurityTxt({
      ...baseFields,
      preferredLanguages: 'en, fr, de',
    });
    expect(output).toContain('Preferred-Languages: en, fr, de');
  });

  it('omits Preferred-Languages when empty string', () => {
    const output = generateSecurityTxt({
      ...baseFields,
      preferredLanguages: '',
    });
    expect(output).not.toContain('Preferred-Languages:');
  });

  it('places Contact before Expires', () => {
    const output = generateSecurityTxt(baseFields);
    const contactIndex = output.indexOf('Contact:');
    const expiresIndex = output.indexOf('Expires:');
    expect(contactIndex).toBeLessThan(expiresIndex);
  });

  it('uses one line per field', () => {
    const allFields: SecurityTxtFields = {
      ...baseFields,
      policy: 'https://example.com/policy',
      acknowledgments: 'https://example.com/thanks',
    };
    const output = generateSecurityTxt(allFields);
    const fieldLines = output.split('\n').filter((l) => l.includes(': ') && !l.startsWith('#'));
    expect(fieldLines).toHaveLength(5);
  });
});

// ---------------------------------------------------------------------------
// normalizeContact
// ---------------------------------------------------------------------------

describe('normalizeContact', () => {
  it('prefixes mailto: for bare email', () => {
    expect(normalizeContact('security@example.com')).toBe('mailto:security@example.com');
  });

  it('preserves existing mailto: prefix', () => {
    expect(normalizeContact('mailto:security@example.com')).toBe('mailto:security@example.com');
  });

  it('preserves https:// URL', () => {
    expect(normalizeContact('https://example.com/security')).toBe('https://example.com/security');
  });

  it('trims whitespace from email', () => {
    expect(normalizeContact('  security@example.com  ')).toBe('mailto:security@example.com');
  });

  it('trims whitespace from URL', () => {
    expect(normalizeContact('  https://example.com  ')).toBe('https://example.com');
  });

  it('returns non-email non-URL values as-is (trimmed)', () => {
    expect(normalizeContact('  foobar  ')).toBe('foobar');
  });
});

// ---------------------------------------------------------------------------
// validateContact
// ---------------------------------------------------------------------------

describe('validateContact', () => {
  it('returns null for valid bare email', () => {
    expect(validateContact('security@example.com')).toBeNull();
  });

  it('returns null for mailto: URI', () => {
    expect(validateContact('mailto:security@example.com')).toBeNull();
  });

  it('returns null for https:// URL', () => {
    expect(validateContact('https://example.com/security')).toBeNull();
  });

  it('returns error for empty string', () => {
    expect(validateContact('')).toBe('Contact is required');
  });

  it('returns error for whitespace-only string', () => {
    expect(validateContact('   ')).toBe('Contact is required');
  });

  it('returns error for invalid format', () => {
    const error = validateContact('not-an-email-or-url');
    expect(error).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateExpires
// ---------------------------------------------------------------------------

describe('validateExpires', () => {
  it('returns null for valid future date', () => {
    const future = new Date();
    future.setFullYear(future.getFullYear() + 1);
    expect(validateExpires(future.toISOString())).toBeNull();
  });

  it('returns error for past date', () => {
    const error = validateExpires('2020-01-01T00:00:00.000Z');
    expect(error).not.toBeNull();
    expect(error).toContain('future');
  });

  it('returns error for invalid date string', () => {
    const error = validateExpires('not-a-date');
    expect(error).not.toBeNull();
    expect(error).toContain('Invalid');
  });

  it('returns error for empty string', () => {
    const error = validateExpires('');
    expect(error).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// defaultExpiresDate
// ---------------------------------------------------------------------------

describe('defaultExpiresDate', () => {
  it('returns a date approximately one year in the future', () => {
    const result = new Date(defaultExpiresDate());
    const oneYearFromNow = new Date();
    oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);

    const diff = Math.abs(result.getTime() - oneYearFromNow.getTime());
    expect(diff).toBeLessThan(10_000);
  });

  it('returns a valid ISO 8601 string', () => {
    const result = defaultExpiresDate();
    expect(new Date(result).toISOString()).toBe(result);
  });

  it('returns a date that passes validation', () => {
    expect(validateExpires(defaultExpiresDate())).toBeNull();
  });
});
