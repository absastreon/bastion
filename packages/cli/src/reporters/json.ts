/**
 * JSON reporter — machine-readable output for CI/CD integration
 */
import type { CheckResult, DetectedStack, ProjectType, ScanReport } from 'bastion-shared';

/** Metadata included in JSON report output */
export interface JsonReportMetadata {
  readonly timestamp: string;
  readonly version: string;
  readonly projectPath: string;
  readonly detectedStack: DetectedStack;
  readonly projectType?: ProjectType;
  readonly projectTypeSource?: 'auto' | 'manual';
}

/** Map a CheckResult to the public JSON schema */
function mapResult(result: CheckResult): Record<string, unknown> {
  return {
    id: result.id,
    title: result.name,
    severity: result.severity,
    status: result.status,
    category: result.category ?? 'General',
    location: result.location ?? null,
    description: result.description,
    fix: result.fix ?? null,
    aiPrompt: result.aiPrompt ?? null,
  };
}

/**
 * Format a ScanReport as a JSON string.
 * The caller is responsible for printing the returned string.
 */
export function formatJsonReport(
  report: ScanReport,
  metadata: JsonReportMetadata,
): string {
  return JSON.stringify(
    {
      score: report.score,
      summary: report.summary,
      results: report.results.map(mapResult),
      metadata,
    },
    null,
    2,
  );
}
