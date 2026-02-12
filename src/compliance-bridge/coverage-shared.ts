/**
 * Shared Coverage Computation
 *
 * Parameterized coverage helper used by both soc2-map.ts and hipaa-map.ts.
 * Extracted to avoid duplication of the coverage calculation logic.
 */

import type { ScannerId, CoverageResult, ScannerStatus } from './contracts.js';

// ── Generic interfaces for control/mapping compatibility ─────────

export interface ControlLike {
  id: string;
  name: string;
  scannerMappings: Array<{ scanner: ScannerId; confidence: number }>;
}

export interface MappingLike {
  controlId: string;
  findings: Array<{ id: string }>;
}

// ── Shared helpers ───────────────────────────────────────────────

/**
 * Compute which controls a set of scanners could potentially cover
 * (regardless of whether findings were produced).
 */
function getControlsForScanners(
  controls: ControlLike[],
  scannerIds: ScannerId[],
): Set<string> {
  const controlIds = new Set<string>();
  const scannerSet = new Set(scannerIds);
  for (const control of controls) {
    for (const mapping of control.scannerMappings) {
      if (scannerSet.has(mapping.scanner)) {
        controlIds.add(control.id);
        break;
      }
    }
  }
  return controlIds;
}

/**
 * Compute coverage against a target control set.
 *
 * Returns three coverage metrics:
 *   - coveragePct: "scanner reach" -- controls where at least one finding was detected.
 *   - coveragePctPotential: controls addressable by installed scanners (even with 0 findings).
 *   - coveragePctFull: controls addressable when ALL 3 scanners are installed.
 *
 * IMPORTANT: These metrics measure scanner reach, not compliance status.
 */
export function computeCoverageForControls(
  controls: ControlLike[],
  mappings: MappingLike[],
  scannerStatuses?: ScannerStatus[],
): CoverageResult {
  // Defensive: only include control IDs that exist in the target control set.
  // This prevents accidental inflation if a mapping emits a typo control ID.
  const controlIdSet = new Set(controls.map(c => c.id));
  const coveredIds = new Set(
    mappings.map(m => m.controlId).filter(id => controlIdSet.has(id)),
  );

  // Potential: controls reachable by scanners that actually ran (status ok or skipped)
  const activeScanners: ScannerId[] = scannerStatuses
    ? scannerStatuses
        .filter(s => s.status === 'ok' || s.status === 'skipped')
        .map(s => s.scanner)
    : [];
  const potentialIds = getControlsForScanners(controls, activeScanners);

  // Full: controls reachable when all 3 scanners are available
  const allScanners: ScannerId[] = ['gitleaks', 'npm_audit', 'checkov'];
  const fullIds = getControlsForScanners(controls, allScanners);

  const controlDetails = controls.map(control => ({
    controlId: control.id,
    controlName: control.name,
    status: coveredIds.has(control.id) ? 'covered' as const : 'gap' as const,
    findingCount: mappings.find(m => m.controlId === control.id)?.findings.length ?? 0,
  }));

  const pct = (n: number) => controls.length > 0
    ? Math.round((n / controls.length) * 100)
    : 0;

  return {
    coveredControls: Array.from(coveredIds),
    missingControls: controls
      .filter(c => !coveredIds.has(c.id))
      .map(c => c.id),
    coveragePct: pct(coveredIds.size),
    coveragePctPotential: pct(potentialIds.size),
    coveragePctFull: pct(fullIds.size),
    coveredControlsPotential: Array.from(potentialIds),
    controlDetails,
  };
}
