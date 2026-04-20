/**
 * Bastion CLI entry point
 * Privacy-first security checker for AI-era builders
 */
import { createRequire } from 'node:module';
import { createProgram } from './cli.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

createProgram(pkg.version).parse();
