import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Exit-code contract integration tests — run the BUILT CLI (dist/, not src/)
 * as a real subprocess and assert actual process exit codes. The 0.2.2
 * bundle-vs-source lesson applies: the contract users get is the bundle's,
 * so at least these tests must exercise it. Requires `npm run build` first;
 * every gate that runs this suite (release.yml, mirror-sync gate, pre-push
 * hooks) builds before testing, per the standing order in lessons.md.
 *
 * ORDER MATTERS: run `npm run typecheck` BEFORE `npm run build`, never after.
 * tsc -b emits per-module files into the same dist/ as the tsup bundle and an
 * incremental emit after tsup's clean overwrites dist/index.js with a module
 * that imports files tsup deleted (H-38). All committed gates use the safe
 * order; this note exists for ad-hoc local runs.
 *
 * Contract (11 June 2026): 0 = clean/below threshold (or no --fail-on),
 * 1 = findings at/above threshold, 2 = scan error, 3 = usage error.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(__dirname, '..', 'dist', 'index.js');
const VULNERABLE = resolve(__dirname, 'fixtures', 'vulnerable-project');
const SECURE = resolve(__dirname, 'fixtures', 'secure-project');

/** Run the built CLI and resolve with its exit code (never rejects on non-zero). */
function runCli(args: readonly string[]): Promise<number> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile('node', [DIST, ...args], { timeout: 30_000 }, (error) => {
      if (error && typeof error.code !== 'number') {
        rejectPromise(error); // spawn failure, not a CLI exit code
        return;
      }
      resolvePromise(error && typeof error.code === 'number' ? error.code : 0);
    });
  });
}

describe('exit-code contract (built CLI)', () => {
  it('exits 0 on a scan with findings when --fail-on is not given (new default)', async () => {
    expect(await runCli(['scan', '--path', VULNERABLE])).toBe(0);
  });

  it('exits 1 when findings meet --fail-on critical', async () => {
    expect(await runCli(['scan', '--path', VULNERABLE, '--fail-on', 'critical'])).toBe(1);
  });

  it('exits 1 with the any alias on a project with findings', async () => {
    expect(await runCli(['scan', '--path', VULNERABLE, '--fail-on', 'any'])).toBe(1);
  });

  it('exits 0 when no findings reach --fail-on critical', async () => {
    expect(await runCli(['scan', '--path', SECURE, '--fail-on', 'critical'])).toBe(0);
  });

  it('exits 1 on --fail-on warn when only warn-status results exist (dep check warns in fixtures)', async () => {
    expect(await runCli(['scan', '--path', SECURE, '--fail-on', 'warn'])).toBe(1);
  });

  it('exits 3 on an invalid --fail-on value (usage error, not findings)', async () => {
    expect(await runCli(['scan', '--path', SECURE, '--fail-on', 'bogus'])).toBe(3);
  });

  it('exits 3 on an unknown option (Commander errors map to usage)', async () => {
    expect(await runCli(['scan', '--no-such-flag'])).toBe(3);
  });

  it('exits 2 when the scan cannot complete (nonexistent path)', async () => {
    expect(await runCli(['scan', '--path', '/nonexistent/definitely-not-here-bastion'])).toBe(2);
  });

  it('exits 0 for --help', async () => {
    expect(await runCli(['scan', '--help'])).toBe(0);
  });
});
