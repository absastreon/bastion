import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext } from '@bastion/shared';
import securityTxtCheck from '../../src/checks/security-txt.js';

/** Create a minimal ScanContext with overrides */
function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectPath: '/tmp/bastion-test-nonexistent',
    stack: { language: 'javascript' },
    files: [],
    verbose: false,
    ...overrides,
  };
}

/** A future ISO date string (1 year from now) */
function futureDate(): string {
  return new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
}

// ---------------------------------------------------------------------------
// Neither exists
// ---------------------------------------------------------------------------

describe('security-txt check', () => {
  describe('when neither security.txt nor SECURITY.md exists', () => {
    it('returns a fail result with medium severity', async () => {
      const results = await securityTxtCheck(makeContext({ files: ['package.json'] }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt',
        status: 'fail',
        severity: 'medium',
      });
    });

    it('includes fix instructions with securitytxt.org link', async () => {
      const results = await securityTxtCheck(makeContext());

      expect(results[0]?.fix).toContain('securitytxt.org');
    });

    it('includes an AI prompt mentioning RFC 9116', async () => {
      const results = await securityTxtCheck(makeContext());

      expect(results[0]?.aiPrompt).toBeDefined();
      expect(results[0]?.aiPrompt).toContain('security.txt');
      expect(results[0]?.aiPrompt).toContain('RFC 9116');
    });
  });

  // ---------------------------------------------------------------------------
  // SECURITY.md only
  // ---------------------------------------------------------------------------

  describe('when only SECURITY.md exists', () => {
    it('returns a pass result', async () => {
      const results = await securityTxtCheck(makeContext({ files: ['SECURITY.md'] }));

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        id: 'security-txt-md',
        status: 'pass',
        location: 'SECURITY.md',
      });
    });
  });

  // ---------------------------------------------------------------------------
  // security.txt at project root
  // ---------------------------------------------------------------------------

  describe('when security.txt exists at project root', () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), 'bastion-securitytxt-'));
    });

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });

    it('passes for a valid security.txt with Contact and Expires', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`,
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({ id: 'security-txt', status: 'pass' });
    });

    it('fails when Contact field is missing', async () => {
      await writeFile(join(tmpDir, 'security.txt'), `Expires: ${futureDate()}\n`);

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      const contact = results.find((r) => r.id === 'security-txt-contact');
      expect(contact).toBeDefined();
      expect(contact?.status).toBe('fail');
      expect(contact?.severity).toBe('medium');
    });

    it('fails when Expires field is missing', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        'Contact: mailto:security@example.com\n',
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      const expires = results.find((r) => r.id === 'security-txt-expires');
      expect(expires).toBeDefined();
      expect(expires?.status).toBe('fail');
      expect(expires?.severity).toBe('medium');
    });

    it('warns when Expires date is in the past', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        'Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00.000Z\n',
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      const expired = results.find((r) => r.id === 'security-txt-expired');
      expect(expired).toBeDefined();
      expect(expired?.status).toBe('warn');
      expect(expired?.description).toContain('2020-01-01');
    });

    it('produces two fail results when both fields are missing', async () => {
      await writeFile(join(tmpDir, 'security.txt'), '# Empty security.txt\n');

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      expect(results.filter((r) => r.status === 'fail')).toHaveLength(2);
      expect(results.some((r) => r.id === 'security-txt-contact')).toBe(true);
      expect(results.some((r) => r.id === 'security-txt-expires')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // .well-known/security.txt
  // ---------------------------------------------------------------------------

  describe('when security.txt exists at .well-known/security.txt', () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), 'bastion-securitytxt-'));
      await mkdir(join(tmpDir, '.well-known'), { recursive: true });
    });

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });

    it('validates and passes for a valid file', async () => {
      await writeFile(
        join(tmpDir, '.well-known', 'security.txt'),
        `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`,
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['.well-known/security.txt'] }),
      );

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({ id: 'security-txt', status: 'pass' });
      expect(results[0]?.location).toBe('.well-known/security.txt');
    });
  });

  // ---------------------------------------------------------------------------
  // Both exist
  // ---------------------------------------------------------------------------

  describe('when both security.txt and SECURITY.md exist', () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), 'bastion-securitytxt-'));
    });

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });

    it('returns pass results for both', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`,
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt', 'SECURITY.md'] }),
      );

      expect(results.some((r) => r.id === 'security-txt' && r.status === 'pass')).toBe(true);
      expect(results.some((r) => r.id === 'security-txt-md' && r.status === 'pass')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  describe('edge cases', () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), 'bastion-securitytxt-'));
    });

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });

    it('handles comments and empty lines in security.txt', async () => {
      const content = [
        '# This is a comment',
        '',
        'Contact: mailto:security@example.com',
        '# Another comment',
        `Expires: ${futureDate()}`,
        '',
      ].join('\n');
      await writeFile(join(tmpDir, 'security.txt'), content);

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      expect(results.find((r) => r.id === 'security-txt')?.status).toBe('pass');
    });

    it('handles case-insensitive field names', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        `contact: mailto:security@example.com\nexpires: ${futureDate()}\n`,
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      expect(results.find((r) => r.id === 'security-txt')?.status).toBe('pass');
    });

    it('prefers .well-known/security.txt over root security.txt', async () => {
      await mkdir(join(tmpDir, '.well-known'), { recursive: true });
      await writeFile(
        join(tmpDir, '.well-known', 'security.txt'),
        `Contact: mailto:security@example.com\nExpires: ${futureDate()}\n`,
      );

      const results = await securityTxtCheck(
        makeContext({
          projectPath: tmpDir,
          files: ['.well-known/security.txt', 'security.txt'],
        }),
      );

      const pass = results.find((r) => r.id === 'security-txt');
      expect(pass?.location).toBe('.well-known/security.txt');
    });

    it('returns skip when security.txt cannot be read', async () => {
      // File listed but does not exist on disk
      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({ id: 'security-txt', status: 'skip' });
    });

    it('treats an unparseable Expires date as not expired', async () => {
      await writeFile(
        join(tmpDir, 'security.txt'),
        'Contact: mailto:security@example.com\nExpires: not-a-date\n',
      );

      const results = await securityTxtCheck(
        makeContext({ projectPath: tmpDir, files: ['security.txt'] }),
      );

      // Contact present, Expires present (unparseable = not expired) → pass
      expect(results.find((r) => r.id === 'security-txt')?.status).toBe('pass');
    });
  });
});
