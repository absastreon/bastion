/**
 * Bastion CLI entry point
 * Privacy-first security checker for web projects
 */
import { createRequire } from 'node:module';
import { CommanderError } from 'commander';
import { createProgram } from './cli.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

// Exit-code contract: Commander's own errors (unknown option, bad choice)
// are usage errors and must exit 3, never 1 — 1 is reserved for findings.
// createProgram sets exitOverride (before subcommand creation, which matters);
// this catch maps the thrown CommanderError to the contract's exit codes.
const program = createProgram(pkg.version);
try {
  program.parse();
} catch (error) {
  if (error instanceof CommanderError) {
    // --help and --version "errors" carry exitCode 0; real usage errors map to 3
    process.exitCode = error.exitCode === 0 ? 0 : 3;
  } else {
    throw error;
  }
}
