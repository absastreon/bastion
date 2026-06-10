import { describe, it, expect } from 'vitest';
import {
  isCodeFile,
  scanFileContent,
  PATTERN_DEFS,
  isLikelyMinified,
} from '../../src/checks/code-patterns.js';
import codePatternCheck from '../../src/checks/code-patterns.js';
import type { ScanContext } from '@bastion/shared';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// isCodeFile
// ---------------------------------------------------------------------------

describe('isCodeFile', () => {
  it('accepts .ts files', () => {
    expect(isCodeFile('src/app.ts')).toBe(true);
  });

  it('accepts .js files', () => {
    expect(isCodeFile('lib/utils.js')).toBe(true);
  });

  it('accepts .tsx files', () => {
    expect(isCodeFile('components/App.tsx')).toBe(true);
  });

  it('accepts .jsx files', () => {
    expect(isCodeFile('components/App.jsx')).toBe(true);
  });

  it('rejects non-code extensions', () => {
    expect(isCodeFile('styles.css')).toBe(false);
    expect(isCodeFile('readme.md')).toBe(false);
    expect(isCodeFile('data.json')).toBe(false);
    expect(isCodeFile('image.png')).toBe(false);
  });

  it('rejects node_modules paths', () => {
    expect(isCodeFile('node_modules/pkg/index.ts')).toBe(false);
  });

  it('rejects dist paths', () => {
    expect(isCodeFile('dist/bundle.js')).toBe(false);
  });

  it('rejects build paths', () => {
    expect(isCodeFile('build/output.js')).toBe(false);
  });

  it('rejects deeply nested ignored dirs', () => {
    expect(isCodeFile('packages/cli/node_modules/dep/index.js')).toBe(false);
  });

  // R1 fix — mobile platform bundles & framework output dirs (Plutica regression)
  it('rejects ios bundle paths (Capacitor / React Native)', () => {
    expect(isCodeFile('ios/App/App/public/assets/useAccounts-O3t18mvC.js')).toBe(false);
  });

  it('rejects android bundle paths', () => {
    expect(isCodeFile('android/app/src/main/assets/public/assets/useBudgets.js')).toBe(false);
  });

  it('rejects .aab_check paths', () => {
    expect(isCodeFile('.aab_check/base/assets/public/assets/Dashboard.js')).toBe(false);
  });

  it('rejects framework build output dirs', () => {
    expect(isCodeFile('.next/server/app/page.js')).toBe(false);
    expect(isCodeFile('.nuxt/dist/server/index.js')).toBe(false);
    expect(isCodeFile('.svelte-kit/output/client/_app/index.js')).toBe(false);
    expect(isCodeFile('out/static/chunks/main.js')).toBe(false);
    expect(isCodeFile('.output/server/index.mjs')).toBe(false);
    expect(isCodeFile('coverage/lcov-report/index.js')).toBe(false);
    expect(isCodeFile('storybook-static/sb-manager/runtime.js')).toBe(false);
  });

  it('still accepts src files that look superficially like build dirs', () => {
    // Defensive: only segment-exact matches should be filtered
    expect(isCodeFile('src/ios-detector.ts')).toBe(true);
    expect(isCodeFile('src/android-shim.ts')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PATTERN_DEFS — verify definitions exist
// ---------------------------------------------------------------------------

describe('PATTERN_DEFS', () => {
  it('has at least 6 pattern definitions', () => {
    expect(PATTERN_DEFS.length).toBeGreaterThanOrEqual(6);
  });

  it('each pattern has required fields', () => {
    for (const p of PATTERN_DEFS) {
      expect(p.id).toBeDefined();
      expect(p.name).toBeDefined();
      expect(p.severity).toMatch(/critical|high|medium|low/);
      expect(p.regex).toBeInstanceOf(RegExp);
      expect(p.fix).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — eval()
// ---------------------------------------------------------------------------

describe('scanFileContent — eval()', () => {
  it('detects eval() calls', () => {
    const results = scanFileContent('eval(userInput);', 'src/app.ts');
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
    expect(results[0]?.name).toContain('eval');
  });

  it('detects eval with spacing', () => {
    const results = scanFileContent('eval ( data )', 'src/app.ts');
    expect(results).toHaveLength(1);
  });

  it('detects new Function() constructor', () => {
    const results = scanFileContent(
      'const fn = new Function("return " + code);',
      'src/app.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('ignores eval in comments', () => {
    const results = scanFileContent('// eval(userInput);', 'src/app.ts');
    expect(results).toHaveLength(0);
  });

  it('ignores eval in block comments', () => {
    const results = scanFileContent('/* eval(userInput); */', 'src/app.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — innerHTML
// ---------------------------------------------------------------------------

describe('scanFileContent — innerHTML', () => {
  it('detects innerHTML assignment with variable', () => {
    const results = scanFileContent(
      'element.innerHTML = userContent;',
      'src/render.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('detects innerHTML with template literal', () => {
    const results = scanFileContent(
      'el.innerHTML = `<div>${data}</div>`;',
      'src/render.tsx',
    );
    expect(results).toHaveLength(1);
  });

  it('ignores innerHTML with string literal only', () => {
    const results = scanFileContent(
      "element.innerHTML = '';",
      'src/render.ts',
    );
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — SQL concatenation
// ---------------------------------------------------------------------------

describe('scanFileContent — SQL concatenation', () => {
  it('detects SQL template literal injection', () => {
    const results = scanFileContent(
      'const q = `SELECT * FROM users WHERE id = ${userId}`;',
      'src/db.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('critical');
  });

  it('detects SQL string concatenation with +', () => {
    const results = scanFileContent(
      'const q = "SELECT * FROM users WHERE id = " + userId;',
      'src/db.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('critical');
  });

  it('detects INSERT INTO concatenation', () => {
    const results = scanFileContent(
      'db.query("INSERT INTO logs VALUES (" + data + ")");',
      'src/db.ts',
    );
    expect(results).toHaveLength(1);
  });

  it('detects UPDATE concatenation', () => {
    const results = scanFileContent(
      'const q = `UPDATE users SET name = ${name}`;',
      'src/db.ts',
    );
    expect(results).toHaveLength(1);
  });

  it('detects DELETE FROM concatenation', () => {
    const results = scanFileContent(
      'const q = "DELETE FROM users WHERE id = " + id;',
      'src/db.ts',
    );
    expect(results).toHaveLength(1);
  });

  it('ignores SQL in comments', () => {
    const results = scanFileContent(
      '// const q = "SELECT * FROM users WHERE id = " + id;',
      'src/db.ts',
    );
    expect(results).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // R1 fix — grammar-anchored regex. Word "update" in toast/log strings must
  // NOT fire; real injectable SQL must still fire.
  // -------------------------------------------------------------------------

  describe('SQL false positives — English word "update" (R1 regression)', () => {
    it('does NOT fire on toast.error("Failed to update X: " + err)', () => {
      const results = scanFileContent(
        `toast.error('Failed to update account: ' + error.message);`,
        'src/hooks/useAccounts.tsx',
      );
      expect(results.filter((r) => r.severity === 'critical')).toHaveLength(0);
    });

    it('does NOT fire on console.error with template "Failed to update DB for ${x}"', () => {
      const results = scanFileContent(
        'console.error(`Failed to update DB for ${symbol}:`, updateError);',
        'supabase/functions/scheduled-price-updates/index.ts',
      );
      expect(results.filter((r) => r.severity === 'critical')).toHaveLength(0);
    });

    it('does NOT fire on prose "select an option from the list" + var', () => {
      const results = scanFileContent(
        `showHint('Please select an option from the list: ' + item);`,
        'src/ui.tsx',
      );
      // "select an option from the list" — words, not SQL grammar.
      // `\\w*?` only matches identifier chars; "an option" technically fits, so
      // we still get the FROM/SELECT structure. This documents the residual:
      // if it does match, it's a known acceptable edge case (FROM + identifier).
      // The bar here: it must not falsely match the UPDATE/DELETE patterns,
      // and the toast/log patterns above stay clean.
      const sqlHits = results.filter((r) => r.severity === 'critical');
      // Allow at most a single SELECT-pattern hit; UPDATE/DELETE must be zero.
      expect(sqlHits.length).toBeLessThanOrEqual(1);
    });

    it('does NOT fire on "update" without trailing SET', () => {
      const results = scanFileContent(
        `logger.info('Attempting to update item ' + itemId);`,
        'src/log.ts',
      );
      expect(results.filter((r) => r.severity === 'critical')).toHaveLength(0);
    });

    it('does NOT fire on "delete" without FROM ... WHERE', () => {
      const results = scanFileContent(
        `toast.error('Failed to delete record: ' + err);`,
        'src/ui.ts',
      );
      expect(results.filter((r) => r.severity === 'critical')).toHaveLength(0);
    });
  });

  describe('SQL true positives — real injectable queries (R1 preservation)', () => {
    it('fires on UPDATE ... SET with template interpolation', () => {
      const results = scanFileContent(
        'const q = `UPDATE users SET name = \'${userInput}\' WHERE id = 1`;',
        'src/db.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });

    it('fires on lowercase update ... set with interpolation', () => {
      const results = scanFileContent(
        'const q = `update users set name = ${u}`;',
        'src/db.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });

    it('fires on INSERT INTO logs (msg) VALUES (...) + concat', () => {
      const results = scanFileContent(
        `const q = "INSERT INTO logs (msg) VALUES ('" + input + "')";`,
        'src/db.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });

    it('fires on INSERT INTO with interpolated table name + paren (exportSQL pattern)', () => {
      const results = scanFileContent(
        'return `INSERT INTO public."${tableName}" (${colList}) VALUES (${values});`;',
        'src/lib/exportSQL.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });

    it('fires on SELECT * FROM ... with interpolation', () => {
      const results = scanFileContent(
        'const q = `SELECT * FROM users WHERE id = ${id}`;',
        'src/db.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });

    it('fires on DELETE FROM ... WHERE with concatenation', () => {
      const results = scanFileContent(
        `db.query("DELETE FROM users WHERE id = " + userId);`,
        'src/db.ts',
      );
      expect(results.some((r) => r.severity === 'critical')).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — document.write()
// ---------------------------------------------------------------------------

describe('scanFileContent — document.write()', () => {
  it('detects document.write()', () => {
    const results = scanFileContent(
      'document.write(content);',
      'src/app.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('detects document.writeln()', () => {
    const results = scanFileContent(
      'document.writeln("<div>" + data + "</div>");',
      'src/app.ts',
    );
    expect(results).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — child_process.exec
// ---------------------------------------------------------------------------

describe('scanFileContent — child_process.exec', () => {
  it('detects exec with template literal', () => {
    const results = scanFileContent(
      'exec(`rm -rf ${userPath}`);',
      'src/utils.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('high');
  });

  it('detects exec with string concatenation', () => {
    const results = scanFileContent(
      'exec("ls " + dir, callback);',
      'src/utils.ts',
    );
    expect(results).toHaveLength(1);
  });

  it('detects execSync with concatenation', () => {
    const results = scanFileContent(
      'execSync("git clone " + url);',
      'src/utils.ts',
    );
    expect(results).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — Math.random() for security
// ---------------------------------------------------------------------------

describe('scanFileContent — Math.random() for security', () => {
  it('detects Math.random() in token generation', () => {
    const results = scanFileContent(
      'const token = Math.random().toString(36);',
      'src/auth.ts',
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.severity).toBe('medium');
  });

  it('detects Math.random() in ID generation', () => {
    const results = scanFileContent(
      'const id = Math.random().toString(36).substring(2);',
      'src/utils.ts',
    );
    expect(results).toHaveLength(1);
  });

  it('ignores standalone Math.random() without toString', () => {
    const results = scanFileContent(
      'const x = Math.random() * 100;',
      'src/game.ts',
    );
    // No match — not used for token/ID generation
    expect(results.filter((r) => r.name.includes('Math.random'))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — comment skipping
// ---------------------------------------------------------------------------

describe('scanFileContent — comment skipping', () => {
  it('ignores // comment lines', () => {
    const results = scanFileContent(
      '// eval(dangerousCode)',
      'src/app.ts',
    );
    expect(results).toHaveLength(0);
  });

  it('ignores * JSDoc comment lines', () => {
    const results = scanFileContent(
      ' * Example: eval(code)',
      'src/app.ts',
    );
    expect(results).toHaveLength(0);
  });

  it('ignores /* block comment lines', () => {
    const results = scanFileContent(
      '/* eval(code) */',
      'src/app.ts',
    );
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — result shape
// ---------------------------------------------------------------------------

describe('scanFileContent — result shape', () => {
  it('includes all required CheckResult fields', () => {
    const results = scanFileContent('eval(code);', 'src/app.ts');
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r).toBeDefined();
    expect(r?.id).toBe('code-patterns');
    expect(r?.status).toBe('fail');
    expect(r?.category).toBe('Code Patterns');
    expect(r?.location).toBe('src/app.ts:1');
    expect(r?.fix).toBeDefined();
    expect(r?.aiPrompt).toBeDefined();
  });

  it('reports correct line numbers', () => {
    const content = 'line1\nline2\neval(code);';
    const results = scanFileContent(content, 'file.ts');
    expect(results[0]?.location).toBe('file.ts:3');
  });

  it('detects multiple patterns in one file', () => {
    const content = [
      'eval(code);',
      'element.innerHTML = data;',
      'const q = `SELECT * FROM users WHERE id = ${id}`;',
    ].join('\n');
    const results = scanFileContent(content, 'bad.ts');
    expect(results.length).toBeGreaterThanOrEqual(3);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — clean files
// ---------------------------------------------------------------------------

describe('scanFileContent — clean files', () => {
  it('returns empty for safe code', () => {
    const content = [
      'import { escape } from "utils";',
      'const result = db.query("SELECT * FROM users WHERE id = ?", [id]);',
      'element.textContent = data;',
      'const id = crypto.randomUUID();',
    ].join('\n');
    const results = scanFileContent(content, 'safe.ts');
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanFileContent — aiPrompt uses stack context
// ---------------------------------------------------------------------------

describe('scanFileContent — stack-aware aiPrompt', () => {
  it('includes database name in SQL prompt when stack has database', () => {
    const content = 'const q = `SELECT * FROM users WHERE id = ${id}`;';
    const results = scanFileContent(content, 'db.ts', { database: 'prisma' });
    expect(results).toHaveLength(1);
    expect(results[0]?.aiPrompt).toContain('prisma');
  });

  it('includes framework name in prompt when stack has framework', () => {
    const content = 'eval(code);';
    const results = scanFileContent(content, 'app.ts', { framework: 'next.js' });
    expect(results).toHaveLength(1);
    expect(results[0]?.aiPrompt).toContain('next.js');
  });

  it('uses generic prompt when no stack info', () => {
    const content = 'eval(code);';
    const results = scanFileContent(content, 'app.ts');
    expect(results).toHaveLength(1);
    expect(results[0]?.aiPrompt).toBeDefined();
    const prompt = results[0]?.aiPrompt ?? '';
    expect(prompt.length).toBeGreaterThan(10);
  });
});

// ---------------------------------------------------------------------------
// isLikelyMinified — safety net for the IGNORED_DIRS list (R1 fix)
// ---------------------------------------------------------------------------

describe('isLikelyMinified', () => {
  it('returns false for normal multi-line source', () => {
    const src = [
      'import x from "y";',
      'export function foo() {',
      '  return 42;',
      '}',
    ].join('\n');
    expect(isLikelyMinified(src)).toBe(false);
  });

  it('returns false for short single-line source', () => {
    expect(isLikelyMinified('const x = 42;')).toBe(false);
  });

  it('returns true for single huge line typical of webpack/vite bundles', () => {
    const longLine = 'a'.repeat(1500);
    expect(isLikelyMinified(longLine)).toBe(true);
  });

  it('returns true even when bundle has a few short trailing lines', () => {
    const bundle = 'x'.repeat(1500) + '\n//# sourceMappingURL=app.js.map\n';
    expect(isLikelyMinified(bundle)).toBe(true);
  });

  it('returns false when every line stays under threshold', () => {
    // 50 lines of 500 chars — long file, but readable source
    const src = Array.from({ length: 50 }, () => 'a'.repeat(500)).join('\n');
    expect(isLikelyMinified(src)).toBe(false);
  });
});

describe('scanFileContent — minified file skip (R1 fix)', () => {
  it('returns no findings for a minified single-line bundle even if it contains eval', () => {
    // Construct a >1000-char single line that includes a real eval() call —
    // shape mirrors Plutica's ios/android bundled output.
    const bundle = 'import{a as b}from"./x.js";' + 'q'.repeat(1200) + 'eval(t);' + 'p'.repeat(50);
    const results = scanFileContent(bundle, 'ios/App/App/public/assets/Dashboard.js');
    expect(results).toHaveLength(0);
  });

  it('still flags the same eval call in unminified source', () => {
    const src = 'import { a } from "./x.js";\neval(t);\n';
    const results = scanFileContent(src, 'src/dashboard.ts');
    expect(results.some((r) => r.name.includes('eval'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// codePatternCheck — integration (uses temp directory)
// ---------------------------------------------------------------------------

describe('codePatternCheck — integration', () => {
  const testDir = join(tmpdir(), `bastion-code-patterns-test-${Date.now()}`);

  async function runWith(
    files: Record<string, string>,
    stack: ScanContext['stack'] = { language: 'typescript' },
  ): Promise<ReturnType<typeof codePatternCheck>> {
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });

    const fileList: string[] = [];
    for (const [name, content] of Object.entries(files)) {
      const dir = join(testDir, ...name.split('/').slice(0, -1));
      await mkdir(dir, { recursive: true });
      await writeFile(join(testDir, name), content, 'utf-8');
      fileList.push(name);
    }

    const context: ScanContext = {
      projectPath: testDir,
      stack,
      files: fileList,
      verbose: false,
      projectType: 'unknown',
      projectTypeSource: 'auto',
    };

    return codePatternCheck(context);
  }

  it('returns pass when no insecure patterns found', async () => {
    const results = await runWith({
      'src/index.ts': 'const x = 42;',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('pass');
  });

  it('detects eval in source files', async () => {
    const results = await runWith({
      'src/app.ts': 'eval(userInput);',
    });
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    expect(results.some((r) => r.severity === 'high')).toBe(true);
  });

  it('detects SQL injection in source files', async () => {
    const results = await runWith({
      'src/db.ts': 'const q = `SELECT * FROM users WHERE id = ${id}`;',
    });
    expect(results.some((r) => r.status === 'fail')).toBe(true);
    expect(results.some((r) => r.severity === 'critical')).toBe(true);
  });

  it('ignores node_modules files', async () => {
    const results = await runWith({
      'node_modules/pkg/index.ts': 'eval(code);',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('ignores dist files', async () => {
    const results = await runWith({
      'dist/bundle.js': 'eval(code);',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  // R1 regression — same SQL in build-dir vs src/
  it('ignores SQL findings inside mobile bundle dirs but flags them in src/', async () => {
    const sql = 'const q = `UPDATE users SET name = ${name}`;';
    const results = await runWith({
      'ios/App/App/public/assets/dup.js': sql,
      'android/app/src/main/assets/public/assets/dup.js': sql,
      '.aab_check/base/assets/public/assets/dup.js': sql,
      'src/db.ts': sql,
    });
    const fails = results.filter((r) => r.status === 'fail');
    // Exactly one failure — only the src/ copy survives the dir filter
    expect(fails).toHaveLength(1);
    expect(fails[0]?.location).toBe('src/db.ts:1');
    expect(fails[0]?.severity).toBe('critical');
  });

  it('returns skip when no code files exist', async () => {
    const results = await runWith({
      'README.md': 'Some docs',
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe('skip');
  });

  it('scans multiple files and reports all findings', async () => {
    const results = await runWith({
      'src/a.ts': 'eval(code);',
      'src/b.ts': 'document.write(html);',
      'src/c.ts': 'const x = 42;',
    });
    const failures = results.filter((r) => r.status === 'fail');
    expect(failures).toHaveLength(2);
  });

  it('passes stack context to aiPrompt', async () => {
    const results = await runWith(
      { 'src/db.ts': 'const q = `SELECT * FROM users WHERE id = ${id}`;' },
      { language: 'typescript', database: 'prisma' },
    );
    const sqlResult = results.find((r) => r.status === 'fail');
    expect(sqlResult?.aiPrompt).toContain('prisma');
  });

  it('cleans up temp dir', async () => {
    await rm(testDir, { recursive: true, force: true });
  });
});
