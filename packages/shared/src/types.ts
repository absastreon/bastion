/**
 * Core types shared across @bastion/cli and @bastion/web
 */

/** Severity levels for security findings */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Output format for scan results */
export type OutputFormat = 'terminal' | 'json' | 'markdown';

/** Valid output formats — runtime array matching OutputFormat type */
export const OUTPUT_FORMATS: readonly OutputFormat[] = ['terminal', 'json', 'markdown'];

/** CLI-parsed scan options (raw from Commander.js) */
export interface ScanOptions {
  readonly path: string;
  readonly format: OutputFormat;
  readonly verbose: boolean;
  readonly url?: string;
}

/** Detected technology stack of the scanned project */
export interface DetectedStack {
  readonly language: string;
  readonly framework?: string;
  readonly packageManager?: string;
  readonly database?: string;
  readonly auth?: string;
  readonly hosting?: string;
  readonly dependencies?: readonly string[];
}

/** Full context passed to each check module */
export interface ScanContext {
  readonly projectPath: string;
  readonly url?: string;
  readonly stack: DetectedStack;
  readonly packageJson?: Record<string, unknown>;
  readonly files: readonly string[];
  readonly verbose: boolean;
}

/** Result from a single check module */
export interface CheckResult {
  readonly id: string;
  readonly name: string;
  readonly status: 'pass' | 'fail' | 'warn' | 'skip';
  readonly severity: Severity;
  readonly category?: string;
  readonly location?: string;
  readonly description: string;
  readonly fix?: string;
  readonly aiPrompt?: string;
}

/** Signature for check modules in packages/cli/src/checks/ */
export type CheckFunction = (context: ScanContext) => Promise<readonly CheckResult[]>;

/** Aggregated counts by result status */
export interface ScanSummary {
  readonly pass: number;
  readonly fail: number;
  readonly warn: number;
  readonly skip: number;
  readonly checksRun: number;
  readonly total: number;
}

/** Complete scan output returned by the scanner */
export interface ScanReport {
  readonly results: readonly CheckResult[];
  readonly score: number;
  readonly summary: ScanSummary;
  readonly duration: number;
  /** True when only HTTP checks ran (no project files detected) */
  readonly urlOnly?: boolean;
}

/** A generated security configuration snippet */
export interface ConfigSnippet {
  readonly name: string;
  readonly filename: string;
  readonly language: string;
  readonly code: string;
  readonly description: string;
}
