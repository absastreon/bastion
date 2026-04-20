/**
 * F015: Insecure code pattern detection
 *
 * Scans .ts, .js, .tsx, .jsx source files for dangerous patterns:
 * eval(), new Function(), innerHTML assignment, SQL concatenation,
 * document.write(), child_process.exec injection, Math.random() for security.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction, CheckResult, Severity } from '@bastion/shared';

/** File extensions to scan for insecure code patterns */
const CODE_EXTENSIONS = new Set(['.ts', '.js', '.tsx', '.jsx']);

/** Directory segments to skip */
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'tests', '__tests__', 'test', 'fixtures']);

/** A pattern definition for insecure code */
interface PatternDef {
  readonly id: string;
  readonly name: string;
  readonly severity: Severity;
  readonly regex: RegExp;
  readonly fix: string;
  readonly aiPromptTemplate: (stack?: StackHint) => string;
}

/** Subset of DetectedStack relevant to prompt generation */
interface StackHint {
  readonly framework?: string;
  readonly database?: string;
}

/** All insecure code patterns to detect */
const PATTERN_DEFS: readonly PatternDef[] = [
  {
    id: 'eval',
    name: 'eval() or new Function()',
    severity: 'high',
    regex: /\b(?:eval\s*\(|new\s+Function\s*\()/,
    fix: 'Replace eval() with a safe parser (e.g. JSON.parse for data, a sandboxed interpreter for expressions). Never pass user input to eval() or new Function().',
    aiPromptTemplate: (stack) =>
      `I have an eval() or new Function() call in my ${stack?.framework ?? 'JavaScript'} project. ` +
      'Help me replace it with a safe alternative. ' +
      'Show me: (1) why eval is dangerous (code injection), ' +
      '(2) what safe alternative to use for my specific case (JSON.parse, a schema validator, or a sandboxed parser), ' +
      'and (3) the refactored code.',
  },
  {
    id: 'innerHTML',
    name: 'innerHTML assignment with variable',
    severity: 'medium',
    regex: /\.innerHTML\s*=\s*(?:[a-zA-Z_$`]|['"][^'"]*['"]\s*\+)/,
    fix: 'Use textContent for plain text, or use a DOM API (createElement, appendChild) to build markup safely. In React/Vue, use framework-provided rendering instead of innerHTML.',
    aiPromptTemplate: (stack) =>
      `I'm assigning to innerHTML with a variable in my ${stack?.framework ?? 'JavaScript'} project. ` +
      'Help me replace it safely. ' +
      'Show me: (1) why innerHTML with variables enables XSS, ' +
      '(2) how to use textContent or DOM APIs instead, ' +
      `${stack?.framework ? `(3) the idiomatic ${stack.framework} approach (e.g. JSX, template syntax)` : '(3) how to sanitize if HTML is truly needed (DOMPurify)'}.`,
  },
  {
    id: 'sql-injection',
    name: 'SQL string concatenation',
    severity: 'critical',
    regex: /\b(?:SELECT\s+|INSERT\s+INTO\s+|UPDATE\s+|DELETE\s+FROM\s+)[^;]*?(?:\$\{|['"]\s*\+)/i,
    fix: 'Use parameterized queries or a query builder. Never concatenate user input into SQL strings.',
    aiPromptTemplate: (stack) => {
      const db = stack?.database;
      const dbHint = db
        ? `I'm using ${db}. Show me the ${db} way to use parameterized queries.`
        : 'Show me how to use parameterized queries with my database driver.';
      return (
        `I have SQL string concatenation in my ${stack?.framework ?? 'Node.js'} project. ` +
        'This is vulnerable to SQL injection. ' +
        `${dbHint} ` +
        'Show me: (1) how the current code is exploitable, ' +
        '(2) the safe version with parameterized queries or a query builder, ' +
        'and (3) how to validate/sanitize input as defense-in-depth.'
      );
    },
  },
  {
    id: 'document-write',
    name: 'document.write()',
    severity: 'medium',
    regex: /\bdocument\.write(?:ln)?\s*\(/,
    fix: 'Use DOM APIs (createElement, appendChild, textContent) instead of document.write(). document.write() can overwrite the entire page and enables XSS if used with untrusted input.',
    aiPromptTemplate: (stack) =>
      `I have document.write() in my ${stack?.framework ?? 'JavaScript'} project. ` +
      'Help me replace it. ' +
      'Show me: (1) why document.write() is dangerous (XSS, page overwrite), ' +
      '(2) the safe DOM API alternative (createElement, textContent), ' +
      `${stack?.framework ? `(3) the idiomatic ${stack.framework} approach` : '(3) how to safely inject content into the DOM'}.`,
  },
  {
    id: 'exec-injection',
    name: 'child_process.exec with dynamic input',
    severity: 'high',
    regex: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    fix: 'Use execFile() or spawn() with an argument array instead of exec() with string concatenation. This prevents shell injection by separating the command from its arguments.',
    aiPromptTemplate: (stack) =>
      `I have a child_process.exec() call with dynamic input in my ${stack?.framework ?? 'Node.js'} project. ` +
      'Help me fix this command injection vulnerability. ' +
      'Show me: (1) why exec with string interpolation is dangerous, ' +
      '(2) how to refactor to execFile() or spawn() with an argument array, ' +
      'and (3) how to validate the input before passing it to any shell command.',
  },
  {
    id: 'math-random-security',
    name: 'Math.random() for tokens/IDs',
    severity: 'medium',
    regex: /\bMath\.random\(\)\.toString\(/,
    fix: 'Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive random values. Math.random() is not cryptographically secure.',
    aiPromptTemplate: (stack) =>
      `I'm using Math.random().toString() to generate tokens or IDs in my ${stack?.framework ?? 'JavaScript'} project. ` +
      'Help me replace it with a cryptographically secure alternative. ' +
      'Show me: (1) why Math.random() is predictable and unsuitable for security, ' +
      '(2) how to use crypto.randomUUID() for IDs, ' +
      'and (3) how to use crypto.getRandomValues() for custom token formats.',
  },
];

/** Variable names suggesting display/UI context — not real SQL execution */
const DISPLAY_VAR_PATTERN = /\b(?:const|let|var)\s+(?:example|code|snippet|demo|preview|diff|before|after|label|text|content|description|title|display|render|show|mock|sample|placeholder)\w*\s*=/i;

/** Check if a line with SQL is likely display/UI text, not a real query */
function isSqlDisplayContext(trimmed: string): boolean {
  // Assigned to a display-purpose variable
  if (DISPLAY_VAR_PATTERN.test(trimmed)) return true;
  // Inside a JSX expression (starts with {) or JSX element (starts with <)
  if (trimmed.startsWith('{') || trimmed.startsWith('<')) return true;
  return false;
}

/** Check whether a file path is a code file that should be scanned */
function isCodeFile(relativePath: string): boolean {
  const segments = relativePath.split('/');
  const fileName = segments[segments.length - 1] ?? '';
  const ext = fileName.includes('.') ? '.' + (fileName.split('.').pop() ?? '') : '';

  if (!CODE_EXTENSIONS.has(ext)) return false;
  if (segments.some((s) => IGNORED_DIRS.has(s))) return false;
  if (/\.(?:test|spec)\.[jt]sx?$/.test(fileName)) return false;

  return true;
}

/** Scan a single file's content for insecure code patterns */
function scanFileContent(
  content: string,
  relativePath: string,
  stack?: StackHint,
): readonly CheckResult[] {
  const lines = content.split('\n');
  const results: CheckResult[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;

    // Skip comment lines
    const trimmed = line.trim();
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*')
    ) {
      continue;
    }

    // Skip string constants, template literals, and regex literals
    if (trimmed.startsWith("'") || trimmed.startsWith('"') || trimmed.startsWith('`') || trimmed.startsWith('/')) {
      continue;
    }
    // Skip object property values — pattern definitions, fix text, AI prompts
    if (/^\w+\s*:\s*['"`/([]/.test(trimmed)) {
      continue;
    }

    for (const pattern of PATTERN_DEFS) {
      if (pattern.regex.test(line)) {
        // SQL injection: skip display/UI contexts (JSX, display variables)
        if (pattern.id === 'sql-injection' && isSqlDisplayContext(trimmed)) {
          continue;
        }
        results.push({
          id: 'code-patterns',
          name: `Insecure pattern: ${pattern.name}`,
          status: 'fail',
          severity: pattern.severity,
          category: 'Code Patterns',
          location: `${relativePath}:${i + 1}`,
          description: `${pattern.name} detected — ${pattern.fix.split('.')[0]}.`,
          fix: pattern.fix,
          aiPrompt: pattern.aiPromptTemplate(stack),
        });
      }
    }
  }

  return results;
}

/** F015 check: scan project files for insecure code patterns */
const codePatternCheck: CheckFunction = async (context) => {
  const filesToScan = context.files.filter(isCodeFile);

  if (filesToScan.length === 0) {
    return [
      {
        id: 'code-patterns',
        name: 'Insecure code patterns',
        status: 'skip',
        severity: 'info',
        description: 'No code files (.ts, .js, .tsx, .jsx) found to scan',
      },
    ];
  }

  const stackHint: StackHint = {
    framework: context.stack.framework,
    database: context.stack.database,
  };

  const allResults: CheckResult[] = [];

  const settled = await Promise.allSettled(
    filesToScan.map(async (file) => {
      const content = await readFile(join(context.projectPath, file), 'utf-8');
      return scanFileContent(content, file, stackHint);
    }),
  );

  for (const outcome of settled) {
    if (outcome.status === 'fulfilled') {
      allResults.push(...outcome.value);
    }
    // Silently skip files that can't be read
  }

  if (allResults.length === 0) {
    return [
      {
        id: 'code-patterns',
        name: 'Insecure code patterns',
        status: 'pass',
        severity: 'info',
        description: 'No insecure code patterns detected',
      },
    ];
  }

  return allResults;
};

export default codePatternCheck;

// Exported for testing
export { isCodeFile, scanFileContent, PATTERN_DEFS };
