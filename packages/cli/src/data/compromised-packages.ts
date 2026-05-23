/**
 * Known-compromised package list — Tier 1 seed data.
 *
 * Entries sourced from Shai-Hulud and SHA1-Hulud IoC reports,
 * StepSecurity advisories, and Snyk vulnerability database.
 *
 * v1 scope: small curated seed list. Future iterations will add
 * automated sourcing from advisory feeds.
 */

export interface CompromisedPackage {
  readonly name: string;
  readonly versionRange: string;
  readonly advisoryId: string;
  readonly source: 'shai-hulud' | 'sha1-hulud' | 'manual';
  readonly dateAdded: string;
  readonly description: string;
}

/**
 * Curated list of known-compromised packages.
 *
 * TODO: Populate from maintained source after researching the
 * Shai-Hulud and SHA1-Hulud IoC reports in detail.
 * The check functions correctly with an empty array (no findings).
 */
export const COMPROMISED_PACKAGES: readonly CompromisedPackage[] = [
  // Initial seed entries to be added after reviewing:
  // - StepSecurity SHA1-Hulud IoC report
  // - Snyk vulnerability database entries
  // - npm security advisories for worm-propagated packages
  //
  // Example structure for future entries:
  // {
  //   name: 'example-malicious-pkg',
  //   versionRange: '>=1.0.0 <1.2.0',
  //   advisoryId: 'GHSA-xxxx-xxxx-xxxx',
  //   source: 'shai-hulud',
  //   dateAdded: '2026-05-16',
  //   description: 'Malicious postinstall script exfiltrating env vars',
  // },
];
