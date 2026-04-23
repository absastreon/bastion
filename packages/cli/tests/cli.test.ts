import { describe, it, expect } from 'vitest';
import { createProgram } from '../src/cli.js';

/**
 * Parse scan command options by overriding the action handler
 * to capture parsed options without side effects (chalk, ora, etc.)
 */
function parseScanOptions(args: string[]): Record<string, unknown> {
  const program = createProgram('0.0.0-test');
  program.exitOverride();

  let captured: Record<string, unknown> = {};
  const scan = program.commands.find((c) => c.name() === 'scan');
  if (!scan) throw new Error('scan command not found');
  scan.action((opts: Record<string, unknown>) => {
    captured = opts;
  });

  program.parse(args, { from: 'user' });
  return captured;
}

describe('createProgram', () => {
  it('sets program name to bastion', () => {
    const program = createProgram('1.0.0');
    expect(program.name()).toBe('bastion');
  });

  it('sets version from argument', () => {
    const program = createProgram('2.5.0');
    expect(program.version()).toBe('2.5.0');
  });

  it('registers scan command', () => {
    const program = createProgram('1.0.0');
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    expect(scan?.description()).toBe('Scan a project for security issues');
  });
});

describe('scan command options', () => {
  it('uses default values when no options provided', () => {
    const opts = parseScanOptions(['scan']);
    expect(opts['path']).toBe('.');
    expect(opts['format']).toBe('terminal');
    expect(opts['verbose']).toBe(false);
    expect(opts['url']).toBeUndefined();
    expect(opts['type']).toBe('auto');
  });

  it('parses --path option', () => {
    const opts = parseScanOptions(['scan', '--path', '/tmp/project']);
    expect(opts['path']).toBe('/tmp/project');
  });

  it('parses -p short option', () => {
    const opts = parseScanOptions(['scan', '-p', './my-app']);
    expect(opts['path']).toBe('./my-app');
  });

  it('parses --format option', () => {
    const opts = parseScanOptions(['scan', '--format', 'json']);
    expect(opts['format']).toBe('json');
  });

  it('parses --format markdown', () => {
    const opts = parseScanOptions(['scan', '--format', 'markdown']);
    expect(opts['format']).toBe('markdown');
  });

  it('parses --verbose flag', () => {
    const opts = parseScanOptions(['scan', '--verbose']);
    expect(opts['verbose']).toBe(true);
  });

  it('parses -v short flag', () => {
    const opts = parseScanOptions(['scan', '-v']);
    expect(opts['verbose']).toBe(true);
  });

  it('parses --url option', () => {
    const opts = parseScanOptions(['scan', '--url', 'https://example.com']);
    expect(opts['url']).toBe('https://example.com');
  });

  it('parses -u short option', () => {
    const opts = parseScanOptions(['scan', '-u', 'https://example.com']);
    expect(opts['url']).toBe('https://example.com');
  });

  it('parses all options together', () => {
    const opts = parseScanOptions([
      'scan',
      '--path',
      '/my/project',
      '--format',
      'markdown',
      '--verbose',
      '--url',
      'https://example.com',
    ]);
    expect(opts['path']).toBe('/my/project');
    expect(opts['format']).toBe('markdown');
    expect(opts['verbose']).toBe(true);
    expect(opts['url']).toBe('https://example.com');
  });

  it('parses --type option with valid choices', () => {
    expect(parseScanOptions(['scan', '--type', 'static'])['type']).toBe('static');
    expect(parseScanOptions(['scan', '--type', 'api'])['type']).toBe('api');
    expect(parseScanOptions(['scan', '--type', 'fullstack'])['type']).toBe('fullstack');
    expect(parseScanOptions(['scan', '--type', 'auto'])['type']).toBe('auto');
  });

  it('parses -t short option for type', () => {
    const opts = parseScanOptions(['scan', '-t', 'static']);
    expect(opts['type']).toBe('static');
  });

  it('rejects invalid --type values', () => {
    expect(() => parseScanOptions(['scan', '--type', 'invalid'])).toThrow();
  });
});
