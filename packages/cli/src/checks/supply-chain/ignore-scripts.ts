/**
 * Check: BSTN-SUP-007 — ignore-scripts protection
 *
 * Detects whether .npmrc has ignore-scripts=true configured.
 * Without this, malicious preinstall/install/postinstall scripts in
 * dependencies execute during npm install — the primary attack vector
 * exploited by Shai-Hulud and SHA1-Hulud worms.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckFunction } from '@bastion/shared';

const CHECK_ID = 'ignore-scripts';
const CHECK_NAME = 'ignore-scripts protection';
const CATEGORY = 'supply-chain';

/**
 * Parse .npmrc INI-style content into a key-value record.
 * Skips comments (# or ;) and empty lines. Trims whitespace.
 */
export function parseNpmrc(content: string): Record<string, string> {
  const result: Record<string, string> = {};

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) {
      continue;
    }

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;

    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();

    if (key) {
      result[key] = value;
    }
  }

  return result;
}

const ignoreScriptsCheck: CheckFunction = async (context) => {
  let content: string;

  try {
    content = await readFile(join(context.projectPath, '.npmrc'), 'utf-8');
  } catch (error: unknown) {
    const isNotFound =
      error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT';

    if (isNotFound) {
      return [
        {
          id: CHECK_ID,
          name: CHECK_NAME,
          status: 'warn',
          severity: 'medium',
          category: CATEGORY,
          location: '.npmrc',
          description:
            'No .npmrc file found. Without ignore-scripts=true, malicious postinstall ' +
            'scripts in dependencies will execute during npm install. This was the primary ' +
            'attack vector for Shai-Hulud and similar worm-style attacks.',
          fix: 'Create .npmrc in the project root and add:\n  ignore-scripts=true',
          aiPrompt:
            'My project has no .npmrc file. Create one with ignore-scripts=true to prevent ' +
            'malicious postinstall scripts from running during npm install. Explain what ' +
            'legitimate postinstall scripts I might need to run manually after installing ' +
            'with this setting enabled.',
        },
      ];
    }

    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'skip',
        severity: 'info',
        category: CATEGORY,
        description: `Check failed: ${error instanceof Error ? error.message : String(error)}`,
      },
    ];
  }

  const config = parseNpmrc(content);

  if (config['ignore-scripts'] === 'true') {
    return [
      {
        id: CHECK_ID,
        name: CHECK_NAME,
        status: 'pass',
        severity: 'info',
        category: CATEGORY,
        location: '.npmrc',
        description: 'ignore-scripts=true is configured — postinstall scripts are blocked by default',
      },
    ];
  }

  return [
    {
      id: CHECK_ID,
      name: CHECK_NAME,
      status: 'warn',
      severity: 'medium',
      category: CATEGORY,
      location: '.npmrc',
      description:
        'Project does not have ignore-scripts=true configured. Without this setting, ' +
        'malicious postinstall scripts in dependencies will execute during npm install. ' +
        'This was the primary attack vector for Shai-Hulud and similar worm-style attacks.',
      fix: 'Edit .npmrc in the project root and add:\n  ignore-scripts=true',
      aiPrompt:
        'My project .npmrc does not have ignore-scripts=true. Update it to add this setting. ' +
        'Explain what legitimate postinstall scripts I might need to run manually after ' +
        'installing with this setting enabled, and how to allowlist specific packages ' +
        'if needed.',
    },
  ];
};

export default ignoreScriptsCheck;
