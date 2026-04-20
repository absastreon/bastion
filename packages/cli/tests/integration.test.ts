import { describe, it, expect } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildContext, scan } from '../src/scanner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(__dirname, 'fixtures');

describe('Integration: full scan', () => {
  it('vulnerable project scores below 50 with multiple failures', async () => {
    const context = await buildContext({
      path: resolve(FIXTURES, 'vulnerable-project'),
      verbose: false,
    });

    const report = await scan(context);

    expect(report.score).toBeLessThan(50);
    expect(report.summary.fail).toBeGreaterThan(1);
  });

  it('secure project scores 100 with zero failures', async () => {
    const context = await buildContext({
      path: resolve(FIXTURES, 'secure-project'),
      verbose: false,
    });

    const report = await scan(context);

    expect(report.score).toBe(100);
    expect(report.summary.fail).toBe(0);
  });
});
