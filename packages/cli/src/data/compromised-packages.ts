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

// Seed list of verified historically-compromised npm packages, each traceable
// to a real GitHub Security Advisory (GHSA). This is a curated SEED for
// demonstrating and testing the check, NOT comprehensive current-threat
// coverage. Automated advisory-feed integration (live IoC data) is planned --
// see HANDOFF. Entries here are well-documented historical incidents; most have
// aged out of typical dependency trees, so this seed primarily proves the check
// functions against real data rather than catching actively-circulating threats.
export const COMPROMISED_PACKAGES: readonly CompromisedPackage[] = [
  // 1. event-stream -- cryptocurrency wallet theft (2018)
  {
    name: 'event-stream',
    versionRange: '=3.3.6',
    advisoryId: 'GHSA-mh6f-8j2x-4483',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'Backdoor injected via flatmap-stream dependency targeting Copay bitcoin wallet private keys.',
  },
  // 2. ua-parser-js -- account takeover, cryptominer (2021)
  {
    name: 'ua-parser-js',
    versionRange: '=0.7.29 || =0.8.0 || =1.0.0',
    advisoryId: 'GHSA-pjwm-rvh2-c87w',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'npm account compromised; three versions published with cryptominer and password stealer.',
  },
  // 3. coa -- credential harvesting (2021)
  {
    name: 'coa',
    versionRange: '=2.0.3 || =2.0.4 || =2.1.1 || =2.1.3 || =3.0.1 || =3.1.3',
    advisoryId: 'GHSA-73qr-pfmq-6rp8',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'npm account compromised; six malicious versions published with credential-harvesting payload.',
  },
  // 4. rc -- credential harvesting (2021, same campaign as coa)
  {
    name: 'rc',
    versionRange: '=1.2.9 || =1.3.9 || =2.3.9',
    advisoryId: 'GHSA-g2q5-5433-rhrf',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'npm account compromised in the same campaign as coa; three malicious versions with credential-harvesting payload.',
  },
  // 5. node-ipc -- destructive protestware (2022)
  {
    name: 'node-ipc',
    versionRange: '>=10.1.1 <10.1.3',
    advisoryId: 'GHSA-97m3-w2cp-4xx6',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'Maintainer added code to overwrite files with heart emojis on systems with Russian or Belarusian IP addresses.',
  },
  // 6. node-ipc -- hidden functionality (2022, same maintainer)
  {
    name: 'node-ipc',
    versionRange: '=9.2.2',
    advisoryId: 'GHSA-8gr3-2gjw-jj7g',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'Hidden functionality added by maintainer in a separate version line from the destructive 10.1.x protestware.',
  },
  // 7. faker -- sabotaged by maintainer (2022)
  {
    name: 'faker',
    versionRange: '=6.6.6',
    advisoryId: 'GHSA-5w9c-rv96-fr7g',
    source: 'manual',
    dateAdded: '2026-05-23',
    description: 'Maintainer replaced all functional code with empty exports as a protest. Still live on npm as latest. Use @faker-js/faker instead.',
  },
];
