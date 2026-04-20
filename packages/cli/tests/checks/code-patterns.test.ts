import { describe, it, expect } from 'vitest';
import {
  isCodeFile,
  scanFileContent,
  PATTERN_DEFS,
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
