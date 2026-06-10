import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, rm } from 'node:fs/promises';
import { runScan } from '../src/cli.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(__dirname, 'fixtures', 'vulnerable-project');
const OUT = join(__dirname, 'fixtures', '.tmp-markdown-report.md');

describe('scan --format markdown (CLI dispatch)', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    // runScan sets process.exitCode=1 when findings exist; reset so it does not
    // leak into the test runner's own exit code.
    process.exitCode = 0;
    await rm(OUT, { force: true });
  });

  it('writes a real markdown file, not ANSI terminal output', async () => {
    await runScan(
      { path: FIXTURE, format: 'markdown', output: OUT, verbose: false, type: 'auto', urlOnly: false },
      '0.0.0-test',
    );

    const content = await readFile(OUT, 'utf-8');

    // Real markdown (heading verified against markdown-reporter.test.ts)
    expect(content.startsWith('# Bastion Security Report')).toBe(true);
    expect(content).toContain('## ');
    // The original bug wrote ANSI terminal output to the file. ESC + '[' is the
    // prefix of every chalk colour code; String.fromCharCode(27) is the ESC
    // character, keeping this check free of fragile backslash escapes.
    const ansiCsiPrefix = String.fromCharCode(27) + '[';
    expect(content).not.toContain(ansiCsiPrefix);
  });
});
