/**
 * CLI program setup — Commander.js configuration
 * Separated from index.ts for testability
 */
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { OUTPUT_FORMATS } from '@bastion/shared';
import type { OutputFormat } from '@bastion/shared';
import { buildContext, scan } from './scanner.js';
import { formatTerminalReport } from './reporters/terminal.js';
import { formatJsonReport } from './reporters/json.js';
import type { JsonReportMetadata } from './reporters/json.js';
import { generateConfigs, formatConfigOutput, writeConfigFiles } from './generators/config.js';

interface RawScanOptions {
  readonly path: string;
  readonly format: string;
  readonly verbose: boolean;
  readonly url?: string;
  readonly output?: string;
  readonly generateConfigs?: boolean;
  readonly outputDir?: string;
}

/** Create and configure the Bastion CLI program */
export function createProgram(version: string): Command {
  const program = new Command();

  program
    .name('bastion')
    .description('Privacy-first security checker for AI-era builders')
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
    .action(async (options: RawScanOptions) => {
      await runScan(options, version);
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

async function runScan(options: RawScanOptions, version: string): Promise<void> {
  const isJson = options.format === 'json';

  if (!isJson) {
    printBanner(version);
  }

  if (!isValidFormat(options.format)) {
    console.error(
      chalk.red(`\n  Error: Invalid format "${options.format}". Use: ${OUTPUT_FORMATS.join(', ')}`),
    );
    process.exitCode = 1;
    return;
  }

  if (!isJson && options.verbose) {
    const { resolve } = await import('node:path');
    console.log(chalk.dim(`  Path:   ${resolve(options.path)}`));
    console.log(chalk.dim(`  Format: ${options.format}`));
    if (options.url) {
      console.log(chalk.dim(`  URL:    ${options.url}`));
    }
    console.log();
  }

  const spinner = isJson ? null : ora({ text: 'Scanning...', indent: 2 }).start();

  try {
    const context = await buildContext({
      path: options.path,
      url: options.url,
      verbose: options.verbose,
    });

    const report = await scan(context);

    if (isJson) {
      const metadata: JsonReportMetadata = {
        timestamp: new Date().toISOString(),
        version,
        projectPath: context.projectPath,
        detectedStack: context.stack,
      };
      console.log(formatJsonReport(report, metadata));
    } else {
      spinner?.succeed(`Scan complete (${report.duration}ms)`);
      if (report.urlOnly) {
        console.log(chalk.yellow('\n  URL-only scan — 6 HTTP checks performed.'));
        console.log(chalk.dim('  Point --path at your source code for a full 15-check audit.\n'));
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

    if (report.summary.fail > 0) {
      process.exitCode = 1;
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
    process.exitCode = 1;
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
