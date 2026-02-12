/**
 * HIPAA Security Rule Control Mapping
 *
 * Maps scanner findings to HIPAA 45 CFR 164.312 Technical Safeguards (12 controls)
 * and lists 164.308 Administrative Safeguard placeholders (7 controls).
 *
 * Technical safeguards are what automated scanners can assess.
 * Administrative safeguards ALWAYS require human/policy evidence and are
 * never included in the scanner reach percentage.
 *
 * IMPORTANT: Confidence scores and control mappings are HEURISTIC.
 *
 * How confidence scores were assigned:
 *   - 0.8-0.9: Scanner directly detects the control's primary concern.
 *     Example: checkov→164.312(e)(2)(ii) (Encryption) at 0.8 because IaC
 *     misconfigs directly reveal missing encryption at rest/in transit.
 *   - 0.5-0.7: Scanner detects a related but indirect signal.
 *     Example: gitleaks→164.312(b) (Audit Controls) at 0.5 because leaked
 *     credentials suggest audit logging may not have caught the exposure.
 *   - 0.4: Weakest mappings where the connection is plausible but tenuous.
 *   - 0.0: Administrative safeguards — no scanner mapping applicable.
 *
 * These scores were NOT derived from empirical data or validated against
 * auditor assessments. They represent the author's judgment about how
 * directly each scanner type relates to each HIPAA safeguard. Users should
 * review and adjust these mappings for their specific compliance context.
 *
 * Scanner findings indicate POTENTIAL safeguard gaps, not proven failures.
 */

import type {
  NormalizedFinding,
  ScannerId,
  HIPAAControl,
  HIPAAMapping,
  HIPAACoverageResult,
  ScannerStatus,
} from './contracts.js';
import { computeCoverageForControls } from './coverage-shared.js';

// ── 12 HIPAA Technical Safeguards (164.312) ──────────────────────

export const HIPAA_TECHNICAL_CONTROLS: HIPAAControl[] = [
  {
    id: '164.312(a)(1)',
    name: 'Access Control',
    description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.',
    cfrSection: '45 CFR 164.312(a)(1)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.8 },
      { scanner: 'checkov', confidence: 0.7 },
    ],
  },
  {
    id: '164.312(a)(2)(i)',
    name: 'Unique User Identification',
    description: 'Assign a unique name and/or number for identifying and tracking user identity.',
    cfrSection: '45 CFR 164.312(a)(2)(i)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.6 },
    ],
  },
  {
    id: '164.312(a)(2)(ii)',
    name: 'Emergency Access Procedure',
    description: 'Establish and implement procedures for obtaining necessary ePHI during an emergency.',
    cfrSection: '45 CFR 164.312(a)(2)(ii)',
    safeguardType: 'technical',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.312(a)(2)(iii)',
    name: 'Automatic Logoff',
    description: 'Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.',
    cfrSection: '45 CFR 164.312(a)(2)(iii)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.5 },
    ],
  },
  {
    id: '164.312(a)(2)(iv)',
    name: 'Encryption and Decryption',
    description: 'Implement a mechanism to encrypt and decrypt ePHI.',
    cfrSection: '45 CFR 164.312(a)(2)(iv)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.7 },
    ],
  },
  {
    id: '164.312(b)',
    name: 'Audit Controls',
    description: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems that contain or use ePHI.',
    cfrSection: '45 CFR 164.312(b)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.6 },
      { scanner: 'gitleaks', confidence: 0.5 },
    ],
  },
  {
    id: '164.312(c)(1)',
    name: 'Integrity',
    description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
    cfrSection: '45 CFR 164.312(c)(1)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'npm_audit', confidence: 0.7 },
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },
  {
    id: '164.312(c)(2)',
    name: 'Mechanism to Authenticate ePHI',
    description: 'Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed.',
    cfrSection: '45 CFR 164.312(c)(2)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.6 },
    ],
  },
  {
    id: '164.312(d)',
    name: 'Person or Entity Authentication',
    description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.',
    cfrSection: '45 CFR 164.312(d)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'gitleaks', confidence: 0.7 },
      { scanner: 'checkov', confidence: 0.5 },
    ],
  },
  {
    id: '164.312(e)(1)',
    name: 'Transmission Security',
    description: 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.',
    cfrSection: '45 CFR 164.312(e)(1)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.8 },
    ],
  },
  {
    id: '164.312(e)(2)(i)',
    name: 'Integrity Controls',
    description: 'Implement security measures to ensure that electronically transmitted ePHI is not improperly modified without detection.',
    cfrSection: '45 CFR 164.312(e)(2)(i)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.7 },
      { scanner: 'npm_audit', confidence: 0.6 },
    ],
  },
  {
    id: '164.312(e)(2)(ii)',
    name: 'Encryption',
    description: 'Implement a mechanism to encrypt ePHI whenever deemed appropriate.',
    cfrSection: '45 CFR 164.312(e)(2)(ii)',
    safeguardType: 'technical',
    requiresHumanEvidence: false,
    scannerMappings: [
      { scanner: 'checkov', confidence: 0.8 },
    ],
  },
];

// ── 7 HIPAA Administrative Safeguard Placeholders (164.308) ──────

export const HIPAA_ADMIN_CONTROLS: HIPAAControl[] = [
  {
    id: '164.308(a)(1)',
    name: 'Security Management Process',
    description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.',
    cfrSection: '45 CFR 164.308(a)(1)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(3)',
    name: 'Workforce Security',
    description: 'Implement policies and procedures to ensure all workforce members have appropriate access to ePHI.',
    cfrSection: '45 CFR 164.308(a)(3)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(4)',
    name: 'Information Access Management',
    description: 'Implement policies and procedures for authorizing access to ePHI.',
    cfrSection: '45 CFR 164.308(a)(4)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(5)',
    name: 'Security Awareness and Training',
    description: 'Implement a security awareness and training program for all workforce members.',
    cfrSection: '45 CFR 164.308(a)(5)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(6)',
    name: 'Security Incident Procedures',
    description: 'Implement policies and procedures to address security incidents.',
    cfrSection: '45 CFR 164.308(a)(6)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(7)',
    name: 'Contingency Plan',
    description: 'Establish and implement policies and procedures for responding to an emergency that damages systems containing ePHI.',
    cfrSection: '45 CFR 164.308(a)(7)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
  {
    id: '164.308(a)(8)',
    name: 'Evaluation',
    description: 'Perform periodic technical and nontechnical evaluation based on standards implemented under the Security Rule.',
    cfrSection: '45 CFR 164.308(a)(8)',
    safeguardType: 'administrative',
    requiresHumanEvidence: true,
    scannerMappings: [],
  },
];

// ── Scanner-Level Rationale ──────────────────────────────────────

const SCANNER_RATIONALE: Record<ScannerId, string> = {
  gitleaks: 'Exposed credentials in code threaten ePHI access controls and authentication safeguards.',
  npm_audit: 'Vulnerable dependencies can be exploited to compromise ePHI integrity and confidentiality.',
  checkov: 'Infrastructure misconfigurations weaken technical safeguards protecting ePHI.',
};

// ── Mapping Logic ────────────────────────────────────────────────

/**
 * Map normalized findings to HIPAA 164.312 Technical Safeguard controls.
 * Only maps against technical controls — administrative placeholders have no scanner mappings.
 * Returns one HIPAAMapping per control that has associated findings.
 */
export function mapFindingsToHIPAAControls(findings: NormalizedFinding[]): HIPAAMapping[] {
  const mappings: HIPAAMapping[] = [];

  for (const control of HIPAA_TECHNICAL_CONTROLS) {
    if (control.scannerMappings.length === 0) continue;

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
 * Compute HIPAA coverage with dual metrics:
 *   - technical: CoverageResult computed on 164.312 controls only (what scanners can assess)
 *   - administrative: 164.308 placeholder list (always "requires human evidence")
 *
 * The technical CoverageResult is the headline metric. Administrative safeguards
 * are NEVER mixed into the percentage to avoid permanently depressing the number.
 */
export function computeHIPAACoverage(
  mappings: HIPAAMapping[],
  scannerStatuses?: ScannerStatus[],
): HIPAACoverageResult {
  const technical = computeCoverageForControls(
    HIPAA_TECHNICAL_CONTROLS,
    mappings,
    scannerStatuses,
  );

  const administrative = {
    controls: HIPAA_ADMIN_CONTROLS.map(c => ({
      controlId: c.id,
      controlName: c.name,
      cfrSection: c.cfrSection,
    })),
    total: HIPAA_ADMIN_CONTROLS.length,
    requiresHumanEvidence: true as const,
  };

  return {
    technical,
    administrative,
    totalControls: HIPAA_TECHNICAL_CONTROLS.length + HIPAA_ADMIN_CONTROLS.length,
  };
}

/**
 * Annotate findings with HIPAA control mappings.
 * Mutates findings in place by adding .hipaa property.
 */
export function annotateFindingsWithHIPAAControls(
  findings: NormalizedFinding[],
  mappings: HIPAAMapping[],
): void {
  for (const finding of findings) {
    const controls: string[] = [];
    for (const mapping of mappings) {
      if (mapping.findings.some(f => f.id === finding.id)) {
        controls.push(mapping.controlId);
      }
    }
    if (controls.length > 0) {
      finding.hipaa = {
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

/**
 * Get HIPAA 164.308 Administrative Safeguard placeholders for display.
 * These always require human/policy evidence that scanners cannot assess.
 */
export function getHIPAAAdminPlaceholders(): Array<{
  controlId: string;
  controlName: string;
  cfrSection: string;
}> {
  return HIPAA_ADMIN_CONTROLS.map(c => ({
    controlId: c.id,
    controlName: c.name,
    cfrSection: c.cfrSection,
  }));
}
