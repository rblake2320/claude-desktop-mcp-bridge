/**
 * SOC2-Lite Control Mapping
 *
 * Maps scanner findings to 20 SOC2 Trust Services Criteria controls.
 * Computes coverage percentage against the target control set.
 *
 * IMPORTANT: Confidence scores and control mappings are HEURISTIC.
 *
 * How confidence scores were assigned:
 *   - 0.8-0.9: Scanner directly detects the control's primary concern.
 *     Example: gitleaks→CC6.1 (Logical Access) at 0.9 because leaked
 *     credentials are a direct logical access control failure.
 *   - 0.5-0.7: Scanner detects a related but indirect signal.
 *     Example: checkov→CC6.3 (Role-Based Access) at 0.5 because IaC
 *     misconfigs may indicate access role issues, but don't prove it.
 *   - 0.4: Weakest mappings where the connection is plausible but tenuous.
 *     Example: gitleaks→CC7.4 (Incident Response) at 0.4 -- a leaked
 *     secret suggests incident response may be needed, but doesn't
 *     test whether an incident response process exists.
 *
 * These scores were NOT derived from empirical data or validated against
 * auditor assessments. They represent the author's judgment about how
 * directly each scanner type relates to each control. Users should
 * review and adjust these mappings for their specific compliance context.
 *
 * Scanner findings indicate POTENTIAL control gaps, not proven failures.
 * A high confidence score means the scanner is relevant to the control,
 * not that the control is definitively failed or passed.
 */

import type { NormalizedFinding, ScannerId, SOC2Control, SOC2Mapping, CoverageResult, ScannerStatus } from './contracts.js';

// ── 20 SOC2-Lite Controls ────────────────────────────────────────

export const SOC2_CONTROLS: SOC2Control[] = [
  // Common Criteria 6: Logical and Physical Access Controls
  {
    id: 'CC6.1', name: 'Logical Access Security',
    description: 'The entity implements logical access security measures to protect against unauthorized access.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.9 },
      { scanner: 'checkov', confidence: 0.7 },
    ],
  },
  {
    id: 'CC6.2', name: 'User Access Administration',
    description: 'The entity registers and authorizes users prior to granting access.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.6 },
    ],
  },
  {
    id: 'CC6.3', name: 'Role-Based Access',
    description: 'The entity authorizes, modifies, or removes access based on roles.',
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.5 },
    ],
  },
  {
    id: 'CC6.6', name: 'System Boundaries Protection',
    description: 'The entity implements logical access security measures to protect boundaries.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.8 },
      { scanner: 'checkov', confidence: 0.8 },
    ],
  },
  {
    id: 'CC6.7', name: 'Data Transmission Protection',
    description: 'The entity restricts data transmission and movement to authorized channels.',
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.7 },
    ],
  },
  {
    id: 'CC6.8', name: 'Malicious Software Prevention',
    description: 'The entity implements controls to prevent or detect malicious software.',
    scannerMappings: [
      { scanner: 'npm_audit', confidence: 0.7 },
    ],
  },

  // Common Criteria 7: System Operations
  {
    id: 'CC7.1', name: 'Infrastructure Monitoring',
    description: 'The entity monitors system components and detects anomalies.',
    scannerMappings: [
      { scanner: 'npm_audit', confidence: 0.6 },
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },
  {
    id: 'CC7.2', name: 'Security Event Detection',
    description: 'The entity monitors system components for security anomalies and evaluates events.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.8 },
      { scanner: 'npm_audit', confidence: 0.7 },
      { scanner: 'checkov', confidence: 0.7 },
    ],
  },
  {
    id: 'CC7.3', name: 'Security Incident Evaluation',
    description: 'The entity evaluates security events to determine if they constitute incidents.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.5 },
    ],
  },
  {
    id: 'CC7.4', name: 'Incident Response',
    description: 'The entity responds to identified security incidents.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.4 },
    ],
  },

  // Common Criteria 8: Change Management
  {
    id: 'CC8.1', name: 'Change Management Process',
    description: 'The entity authorizes, designs, develops, configures, documents, tests, and implements changes.',
    scannerMappings: [
      { scanner: 'npm_audit', confidence: 0.7 },
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },

  // Common Criteria 9: Risk Mitigation
  {
    id: 'CC9.1', name: 'Risk Identification and Assessment',
    description: 'The entity identifies, selects, and develops risk mitigation activities.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.6 },
      { scanner: 'npm_audit', confidence: 0.6 },
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },

  // Availability criteria
  {
    id: 'A1.1', name: 'System Availability Objectives',
    description: 'The entity maintains, monitors, and evaluates availability commitments.',
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.5 },
    ],
  },
  {
    id: 'A1.2', name: 'Environmental Protections',
    description: 'The entity authorizes, designs, and implements environmental protections.',
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },

  // Confidentiality criteria
  {
    id: 'C1.1', name: 'Confidential Information Identification',
    description: 'The entity identifies and maintains confidential information.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.9 },
    ],
  },
  {
    id: 'C1.2', name: 'Confidential Information Disposal',
    description: 'The entity disposes of confidential information per objectives.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.5 },
    ],
  },

  // Processing Integrity
  {
    id: 'PI1.1', name: 'Processing Integrity Definitions',
    description: 'The entity obtains or generates data that is complete, accurate, and timely.',
    scannerMappings: [
      { scanner: 'npm_audit', confidence: 0.4 },
    ],
  },

  // Privacy
  {
    id: 'P6.1', name: 'Data Retention and Disposal',
    description: 'Personal information is retained and disposed of per policies.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.5 },
    ],
  },

  // Additional controls
  {
    id: 'CC3.1', name: 'Risk Assessment',
    description: 'The entity specifies objectives and identifies risks to achievement.',
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.5 },
      { scanner: 'npm_audit', confidence: 0.5 },
      { scanner: 'checkov', confidence: 0.5 },
    ],
  },
  {
    id: 'CC5.1', name: 'Control Activities',
    description: 'The entity selects and develops control activities.',
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },
];

// ── Scanner-Level Rationale ──────────────────────────────────────

const SCANNER_RATIONALE: Record<ScannerId, string> = {
  gitleaks: 'Secrets in code increase unauthorized access risk and incident likelihood.',
  npm_audit: 'Vulnerable dependencies increase likelihood/impact of security events.',
  checkov: 'Misconfigurations weaken logical access controls and monitoring.',
};

// ── Mapping Logic ────────────────────────────────────────────────

/**
 * Map normalized findings to SOC2 controls.
 * Returns one SOC2Mapping per control that has associated findings.
 */
export function mapFindingsToControls(findings: NormalizedFinding[]): SOC2Mapping[] {
  const mappings: SOC2Mapping[] = [];

  for (const control of SOC2_CONTROLS) {
    const matchedFindings: NormalizedFinding[] = [];
    let maxConfidence = 0;

    for (const mapping of control.scannerMappings) {
      const scannerFindings = findings.filter(f => f.scanner === mapping.scanner);
      if (scannerFindings.length > 0) {
        matchedFindings.push(...scannerFindings);
        maxConfidence = Math.max(maxConfidence, mapping.confidence);
      }
    }

    if (matchedFindings.length > 0) {
      // Deduplicate findings by id
      const unique = Array.from(new Map(matchedFindings.map(f => [f.id, f])).values());

      mappings.push({
        controlId: control.id,
        controlName: control.name,
        findings: unique,
        confidence: maxConfidence,
      });
    }
  }

  return mappings;
}

/**
 * Compute which controls a set of scanners could potentially cover
 * (regardless of whether findings were produced).
 */
function getControlsForScanners(scannerIds: ScannerId[]): Set<string> {
  const controlIds = new Set<string>();
  const scannerSet = new Set(scannerIds);
  for (const control of SOC2_CONTROLS) {
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
 * Compute coverage against the 20-control SOC2-lite target set.
 *
 * Returns three coverage metrics:
 *   - coveragePct: "scanner reach" -- controls where at least one finding was detected.
 *     This does NOT mean the control is implemented or compliant. It means
 *     a scanner produced findings relevant to the control.
 *   - coveragePctPotential: controls addressable by installed scanners (even with 0 findings).
 *   - coveragePctFull: controls addressable when ALL 3 scanners are installed.
 *
 * IMPORTANT: These metrics measure scanner reach, not compliance status.
 * A "covered" control means "a scanner looked at something relevant to this control
 * and found items to report." It does NOT mean the control passes audit.
 */
export function computeCoverage(
  mappings: SOC2Mapping[],
  scannerStatuses?: ScannerStatus[],
): CoverageResult {
  const coveredIds = new Set(mappings.map(m => m.controlId));

  // Potential: controls reachable by scanners that actually ran (status ok or skipped)
  const activeScanners: ScannerId[] = scannerStatuses
    ? scannerStatuses
        .filter(s => s.status === 'ok' || s.status === 'skipped')
        .map(s => s.scanner)
    : [];
  const potentialIds = getControlsForScanners(activeScanners);

  // Full: controls reachable when all 3 scanners are available
  const allScanners: ScannerId[] = ['gitleaks', 'npm_audit', 'checkov'];
  const fullIds = getControlsForScanners(allScanners);

  const controlDetails = SOC2_CONTROLS.map(control => ({
    controlId: control.id,
    controlName: control.name,
    status: coveredIds.has(control.id) ? 'covered' as const : 'gap' as const,
    findingCount: mappings.find(m => m.controlId === control.id)?.findings.length ?? 0,
  }));

  const pct = (n: number) => Math.round((n / SOC2_CONTROLS.length) * 100);

  return {
    coveredControls: Array.from(coveredIds),
    missingControls: SOC2_CONTROLS
      .filter(c => !coveredIds.has(c.id))
      .map(c => c.id),
    coveragePct: pct(coveredIds.size),
    coveragePctPotential: pct(potentialIds.size),
    coveragePctFull: pct(fullIds.size),
    coveredControlsPotential: Array.from(potentialIds),
    controlDetails,
  };
}

/**
 * Annotate findings with SOC2 control mappings.
 * Mutates findings in place by adding .soc2 property.
 */
export function annotateFindingsWithControls(
  findings: NormalizedFinding[],
  mappings: SOC2Mapping[]
): void {
  for (const finding of findings) {
    const controls: string[] = [];
    for (const mapping of mappings) {
      if (mapping.findings.some(f => f.id === finding.id)) {
        controls.push(mapping.controlId);
      }
    }
    if (controls.length > 0) {
      finding.soc2 = {
        controls,
        rationale: SCANNER_RATIONALE[finding.scanner],
        confidence: Math.max(
          ...mappings
            .filter(m => controls.includes(m.controlId))
            .map(m => m.confidence)
        ),
      };
    }
  }
}
