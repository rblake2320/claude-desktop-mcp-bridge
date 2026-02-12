/**
 * Compliance Navigator - ROI Calculator
 *
 * Conservative model for estimating hours saved by automated compliance scanning.
 * Based on fixed triage+remediation times per finding class.
 */

import type { NormalizedFinding, ScannerId, ROIResult } from './contracts.js';

// ── Conservative Defaults ────────────────────────────────────────
// Each constant represents average human-hours per finding to triage + remediate.

const HOURS_PER_SECRET = 0.75;     // triage + rotation + PR + verification
const HOURS_PER_VULN = 0.25;       // review + update + test
const HOURS_PER_IAC = 0.5;         // fix + deploy + validate

const SCANNER_HOURS: Record<ScannerId, number> = {
  gitleaks: HOURS_PER_SECRET,
  npm_audit: HOURS_PER_VULN,
  checkov: HOURS_PER_IAC,
};

// Conservative multiplier: bare minimum (just triage + fix)
const CONSERVATIVE_MULTIPLIER = 1.0;
// Likely multiplier: includes context switching, PR review, deployment verification
const LIKELY_MULTIPLIER = 1.8;

const BASIS = 'Conservative: triage+remediation only. Likely: includes context switching, code review, and deployment verification.';

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
