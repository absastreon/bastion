/**
 * bastion-shared — Types, constants, and data shared across packages
 */
export const VERSION = '0.1.1';

export { OUTPUT_FORMATS } from './types.js';

export type {
  Severity,
  OutputFormat,
  ProjectType,
  ScanOptions,
  DetectedStack,
  ScanContext,
  CheckResult,
  CheckFunction,
  ScanSummary,
  ScanReport,
  ConfigSnippet,
} from './types.js';

// Checklist data
export { SECURITY_CHECKLIST } from './checklist.js';
export type { ChecklistItem } from './checklist.js';

// OWASP 2025 data
export { OWASP_2025_TOP_10 } from './owasp.js';
export type { OwaspCategory } from './owasp.js';

// Recommended tools data
export { RECOMMENDED_TOOLS } from './tools.js';
export type { SecurityTool, ToolPricing, ToolCategory } from './tools.js';

// Stack-specific checklists
export {
  FRAMEWORK_OPTIONS,
  DATABASE_OPTIONS,
  AUTH_OPTIONS,
  generateStackChecklist,
} from './stack-checklists.js';
export type {
  StackChecklistItem,
  StackOption,
  StackChecklist,
} from './stack-checklists.js';
