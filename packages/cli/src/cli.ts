/**
 * CLI program setup — Commander.js configuration
 * Separated from index.ts for testability
 */
import { writeFile } from 'node:fs/promises';
import { Command, Option } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { OUTPUT_FORMATS } from '@bastion/shared';
import type { OutputFormat } from '@bastion/shared';
import { buildContext, scan } from './scanner.js';
import { formatTerminalReport } from './reporters/terminal.js';
import { formatJsonReport } from './reporters/json.js';
import type { JsonReportMetadata } from './reporters/json.js';
import { writeMarkdownReport } from './reporters/markdown.js';
import { generateConfigs, formatConfigOutput, writeConfigFiles } from './generators/config.js';
import { runSecurityTxtGenerator, type SecurityTxtOptions } from './generators/security-txt.js';
import { FAIL_ON_CHOICES, FAIL_ON_LEVELS, normalizeFailOn, countAtOrAbove } from './utils/fail-on.js';

interface RawScanOptions {
  readonly path: string;
  readonly format: string;
  readonly verbose: boolean;
  readonly url?: string;
  readonly output?: string;
  readonly generateConfigs?: boolean;
  readonly outputDir?: string;
  readonly type: 'auto' | 'static' | 'api' | 'fullstack';
  readonly urlOnly?: boolean;
  readonly failOn?: string;
}

/** Determine whether the scan should run in URL-only mode */
export function computeUrlOnly(
  options: { readonly url?: string },
  command: { getOptionValueSource(key: string): string | undefined },
): boolean {
  return !!options.url && command.getOptionValueSource('path') === 'default';
}

/** Create and configure the Bastion CLI program */
export function createProgram(version: string): Command {
  const program = new Command();

  // Exit-code contract: usage errors must exit 3, never Commander's default 1
  // (1 is reserved for findings). exitOverride makes Commander throw instead
  // of exiting; the entry point catches and maps. It MUST be set before the
  // subcommands are created — the callback is copied to them at creation time
  // (verified against commander 14; set after, subcommands still process.exit).
  program.exitOverride();

  program
    .name('bastion')
    .description('Privacy-first security checker for web projects')
    .version(version);

  program
    .command('scan')
    .description('Scan a project for security issues')
    .option('-p, --path <dir>', 'path to project directory', '.')
    .option('-f, --format <type>', 'output format (terminal, json, markdown)', 'terminal')
    .option('-v, --verbose', 'show detailed output', false)
    .option('-u, --url <url>', 'URL for HTTP-based checks')
    .option('-o, --output <file>', 'output file path (for markdown/json formats)')
    .option('--generate-configs', 'generate security config snippets for detected stack', false)
    .option('--output-dir <dir>', 'write generated config files to directory')
    .addOption(
      new Option('-t, --type <type>', 'project type override')
        .choices(['auto', 'static', 'api', 'fullstack'])
        .default('auto'),
    )
    .addOption(
      new Option(
        '--fail-on <level>',
        'exit 1 if any failed check is at or above this severity; warn is strictest (any = alias)',
      ).choices([...FAIL_ON_CHOICES]),
    )
    .action(async (options: RawScanOptions, command: Command) => {
      await runScan({ ...options, urlOnly: computeUrlOnly(options, command) }, version);
    });

  const generate = program
    .command('generate')
    .description('Generate security configuration files');

  generate
    .command('security-txt')
    .description('Create a valid security.txt file (RFC 9116)')
    .option('-c, --contact <value>', 'contact email or URL (enables non-interactive mode)')
    .option('-e, --expires <date>', 'expires date in ISO 8601 (default: 1 year from now)')
    .option('-l, --languages <langs>', 'preferred languages (default: en)')
    .option('--policy <url>', 'policy URL')
    .option('--acknowledgments <url>', 'acknowledgments URL')
    .option('-p, --path <dir>', 'project directory', '.')
    .action(async (options: SecurityTxtOptions) => {
      await runSecurityTxtGenerator(options);
    });

  return program;
}

export async function runScan(options: RawScanOptions, version: string): Promise<void> {
  const isJson = options.format === 'json';

  if (!isJson) {
    printBanner(version);
  }

  if (!isValidFormat(options.format)) {
    console.error(
      chalk.red(`\n  Error: Invalid format "${options.format}". Use: ${OUTPUT_FORMATS.join(', ')}`),
    );
    process.exitCode = 3; // usage error, per the exit-code contract
    return;
  }

  if (!isJson && options.verbose) {
    const { resolve } = await import('node:path');
    console.log(chalk.dim(`  Path:   ${resolve(options.path)}`));
    console.log(chalk.dim(`  Format: ${options.format}`));
    if (options.url) {
      console.log(chalk.dim(`  URL:    ${options.url}`));
    }
    if (options.type !== 'auto') {
      console.log(chalk.dim(`  Type:   ${options.type} (manual override)`));
    }
    console.log();
  }

  const spinner = isJson ? null : ora({ text: 'Scanning...', indent: 2 }).start();

  try {
    const context = await buildContext({
      path: options.path,
      url: options.url,
      verbose: options.verbose,
      type: options.type,
      urlOnly: options.urlOnly,
    });

    const report = await scan(context);

    if (isJson) {
      const metadata: JsonReportMetadata = {
        timestamp: new Date().toISOString(),
        version,
        projectPath: context.projectPath,
        detectedStack: context.stack,
        projectType: report.projectType,
        projectTypeSource: report.projectTypeSource,
      };
      const json = formatJsonReport(report, metadata);
      if (options.output) {
        await writeFile(options.output, json, 'utf-8');
      } else {
        console.log(json);
      }
    } else if (options.format === 'markdown') {
      spinner?.succeed(`Scan complete (${report.duration}ms)`);
      const outputPath = await writeMarkdownReport(report, context, version, options.output);
      console.log(chalk.green(`\n  ✓ Markdown report written to ${outputPath}\n`));
    } else {
      spinner?.succeed(`Scan complete (${report.duration}ms)`);
      if (report.urlOnly) {
        console.log(chalk.yellow('\n  URL-only scan — 6 HTTP checks performed.'));
        console.log(chalk.dim('  Point --path at your source code for a full 15-check audit.\n'));
      }
      if (report.projectType && report.projectType !== 'unknown') {
        const source = report.projectTypeSource === 'manual' ? 'manual' : 'auto-detected';
        console.log(chalk.dim(`\n  Project type: ${report.projectType} (${source})`));
      }
      if (report.projectType === 'static' && report.summary.notApplicable > 0) {
        console.log(chalk.dim(`  Static site detected — ${report.summary.notApplicable} checks not applicable`));
      }
      console.log(formatTerminalReport(report, options.verbose));
    }

    // Config generation (after scan output)
    if (options.generateConfigs || options.outputDir) {
      const snippets = generateConfigs(context.stack);

      if (options.outputDir) {
        const paths = await writeConfigFiles(snippets, options.outputDir);
        if (!isJson) {
          console.log(chalk.green(`\n  ✓ Wrote ${paths.length} config file${paths.length === 1 ? '' : 's'} to ${options.outputDir}/`));
          for (const p of paths) {
            console.log(chalk.dim(`    ${p}`));
          }
          console.log();
        }
      } else if (!isJson) {
        console.log(formatConfigOutput(snippets));
      }
    }

    // Exit-code contract (11 June 2026): findings affect the exit code only
    // when --fail-on is given. Without it the scan exits 0 regardless of
    // findings (deliberate change from the pre-0.2.3 exit-1-on-any-fail).
    if (options.failOn) {
      const level = normalizeFailOn(options.failOn);
      if (level === null) {
        // Unreachable via Commander (choices validate), kept for direct runScan calls
        console.error(chalk.red(`\n  Error: Invalid --fail-on "${options.failOn}". Use: ${FAIL_ON_CHOICES.join(', ')}`));
        process.exitCode = 3;
        return;
      }
      if (countAtOrAbove(report.results, level) > 0) {
        process.exitCode = 1;
      }
    } else if (!isJson && options.format === 'terminal' && report.summary.fail > 0) {
      console.log(
        chalk.dim(`  Tip: gate CI on these findings with --fail-on ${FAIL_ON_LEVELS.join('|')}`),
      );
      console.log('');
    }
  } catch (error) {
    if (isJson) {
      console.error(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
    } else {
      spinner?.fail('Scan failed');
      console.error(
        chalk.red(`\n  ${error instanceof Error ? error.message : String(error)}\n`),
      );
    }
    process.exitCode = 2; // scan error, per the exit-code contract
  }
}

function printBanner(version: string): void {
  console.log();
  console.log(chalk.bold.cyan('  Bastion') + chalk.dim(` v${version}`));
  console.log(chalk.dim('  Privacy-first security checker'));
  console.log();
}

function isValidFormat(format: string): format is OutputFormat {
  return (OUTPUT_FORMATS as readonly string[]).includes(format);
}
