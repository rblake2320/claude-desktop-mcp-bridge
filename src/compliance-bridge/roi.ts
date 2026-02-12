/**
 * Compliance Navigator - ROI Estimator
 *
 * Provides rough estimates of manual remediation effort per finding class.
 *
 * IMPORTANT: These are configurable defaults, NOT validated measurements.
 * The constants below are informed guesses based on typical DevSecOps
 * workflows but have not been validated against real-world remediation
 * time tracking data. Users should adjust these constants based on their
 * own team's measured remediation times.
 *
 * Use these estimates for prioritization and rough planning only.
 * Do not cite them as measured or validated metrics.
 */

import type { NormalizedFinding, ScannerId, ROIResult } from './contracts.js';

// ── Default Estimates (NOT VALIDATED -- adjust for your team) ────
//
// Each constant is an estimated average human-hours per finding to triage + remediate.
// These are rough defaults, not empirical measurements.
//
// Sources of informed guesswork:
//   - Secret rotation (0.75h): assumes triage, credential rotation, PR, verification.
//     Real-world range: 0.25h (simple API key) to 4h+ (database credential with dependencies).
//   - Dependency vuln (0.25h): assumes npm update, test, verify.
//     Real-world range: 0.1h (minor bump) to 8h+ (major version with breaking changes).
//   - IaC misconfig (0.5h): assumes config fix, plan, apply.
//     Real-world range: 0.15h (add a tag) to 4h+ (network architecture change).

const HOURS_PER_SECRET = 0.75;
const HOURS_PER_VULN = 0.25;
const HOURS_PER_IAC = 0.5;

const SCANNER_HOURS: Record<ScannerId, number> = {
  gitleaks: HOURS_PER_SECRET,
  npm_audit: HOURS_PER_VULN,
  checkov: HOURS_PER_IAC,
};

const CONSERVATIVE_MULTIPLIER = 1.0;
const LIKELY_MULTIPLIER = 1.8;

const BASIS =
  'ESTIMATE ONLY (not validated against real data). ' +
  'Conservative: triage+remediation using default per-finding estimates. ' +
  'Likely: 1.8x multiplier for context switching, code review, and deployment. ' +
  'Adjust HOURS_PER_SECRET/VULN/IAC constants for your team\'s actual remediation times.';

/**
 * Calculate estimated ROI in hours saved.
 *
 * @param findings - Normalized findings from all scanners
 * @returns ROI breakdown by scanner type and total, with conservative and likely estimates
 */
export function calculateROI(findings: NormalizedFinding[]): ROIResult {
  const countsByScanner: Record<ScannerId, number> = {
    gitleaks: 0,
    npm_audit: 0,
    checkov: 0,
  };

  for (const finding of findings) {
    if (finding.scanner in countsByScanner) {
      countsByScanner[finding.scanner]++;
    }
  }

  const breakdown: ROIResult['breakdown'] = {} as ROIResult['breakdown'];
  let totalHours = 0;

  for (const [scanner, count] of Object.entries(countsByScanner) as [ScannerId, number][]) {
    const hoursPerFinding = SCANNER_HOURS[scanner];
    const scannerTotal = count * hoursPerFinding;
    totalHours += scannerTotal;

    breakdown[scanner] = {
      count,
      hoursPerFinding,
      totalHours: Math.round(scannerTotal * 100) / 100,
    };
  }

  const r = (n: number) => Math.round(n * 100) / 100;

  return {
    hoursSaved: r(totalHours),
    hoursSavedConservative: r(totalHours * CONSERVATIVE_MULTIPLIER),
    hoursSavedLikely: r(totalHours * LIKELY_MULTIPLIER),
    basis: BASIS,
    breakdown,
  };
}
