/**
 * Core types shared across @bastion/cli and @bastion/web
 */

/**
 * Severity levels for security findings.
 *
 * Calibration rubric (R2, 26 May 2026) — apply when adding new checks so the
 * scale stays trustworthy. When Bastion says "critical", users must be able to
 * believe it; over-rating drives them to discount real criticals.
 *
 * - **critical** — Active exploitability with no further preconditions. A
 *   leaked credential matched in source, an exploitable injection sink, an
 *   invalid/expired TLS certificate. If shipping this means an attacker can
 *   act today, it's critical.
 * - **high** — Misconfiguration that becomes exploitable under common dev
 *   mistakes: missing .gitignore patterns for secret-bearing files, missing
 *   auth or rate-limit, plain HTTP transit, exposed PEM/key patterns. The
 *   pre-condition is realistic, not certain.
 * - **medium** — Hygiene / defense-in-depth: missing security headers,
 *   missing security.txt, missing DMARC, build-output noise, generic
 *   supply-chain hardening.
 * - **low** — Minor advisory; nice-to-fix.
 * - **info** — Informational only (passing checks, skipped checks, context).
 *
 * Third-party exemption (decided 11 June 2026, disposition ledger 2.7):
 * severities imported from third-party advisories — the npm audit
 * pass-through in dep-vuln findings — are reported verbatim and are EXEMPT
 * from this rubric. The rubric calibrates Bastion's own checks; upstream
 * advisories carry upstream's calibration, and users can cross-reference the
 * linked GHSA. The pressure valve for noisy dev-dependency criticals in CI is
 * the --fail-on threshold (and the baseline file), not severity rewriting.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Output format for scan results */
export type OutputFormat = 'terminal' | 'json' | 'markdown';

/** Project type for static-site detection and check filtering */
export type ProjectType = 'static' | 'api' | 'fullstack' | 'unknown';

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
  /** Detected or manually specified project type */
  readonly projectType: ProjectType;
  /** Whether the project type was auto-detected or manually set */
  readonly projectTypeSource: 'auto' | 'manual';
  /** True when running in URL-only mode (--url without explicit --path) */
  readonly urlOnly?: boolean;
}

/** Result from a single check module */
export interface CheckResult {
  readonly id: string;
  readonly name: string;
  readonly status: 'pass' | 'fail' | 'warn' | 'skip' | 'not-applicable';
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
  readonly notApplicable: number;
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
  /** Detected or manually specified project type */
  readonly projectType?: ProjectType;
  /** Whether the project type was auto-detected or manually set */
  readonly projectTypeSource?: 'auto' | 'manual';
}

/** A generated security configuration snippet */
export interface ConfigSnippet {
  readonly name: string;
  readonly filename: string;
  readonly language: string;
  readonly code: string;
  readonly description: string;
}
