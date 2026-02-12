/**
 * Checkov Output Normalizer
 *
 * Parses `checkov -o json` output into NormalizedFinding[].
 * Detects IaC misconfigurations (Terraform, CloudFormation, Docker, K8s, etc.)
 */

import { createHash } from 'node:crypto';
import type { NormalizedFinding, Severity, ScannerId } from '../contracts.js';

const SCANNER: ScannerId = 'checkov';

interface CheckovFailedCheck {
  check_id: string;
  bc_check_id?: string;
  check_result: { result: string; evaluated_keys?: string[] };
  resource: string;
  file_path: string;
  file_line_range: [number, number];
  evaluations?: Record<string, unknown>;
  check_class?: string;
  guideline?: string;
  severity?: string;
  description?: string;
}

interface CheckovCheckType {
  check_type: string;
  results: {
    passed_checks: unknown[];
    failed_checks: CheckovFailedCheck[];
    skipped_checks: unknown[];
  };
  summary: {
    passed: number;
    failed: number;
    skipped: number;
    parsing_errors: number;
  };
}

type CheckovOutput = CheckovCheckType | CheckovCheckType[];

function makeFindingId(input: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
    .slice(0, 16);
}

function mapSeverity(checkovSeverity?: string): Severity {
  if (!checkovSeverity) return 'medium';
  switch (checkovSeverity.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    case 'INFO': return 'info';
    default: return 'medium';
  }
}

function checkIdToTitle(checkId: string, description?: string): string {
  if (description) return description;
  return `IaC misconfiguration: ${checkId}`;
}

/**
 * Normalize checkov JSON output into unified findings.
 *
 * @param rawJson - Raw JSON string from `checkov -o json`
 * @param evidenceRef - Path to the checkov output file
 */
export function normalizeCheckov(
  rawJson: string,
  evidenceRef: string
): NormalizedFinding[] {
  let parsed: CheckovOutput;

  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return [];
  }

  // Checkov can return a single object or array of check types
  const checkTypes: CheckovCheckType[] = Array.isArray(parsed) ? parsed : [parsed];

  const findings: NormalizedFinding[] = [];

  for (const checkType of checkTypes) {
    if (!checkType.results?.failed_checks) continue;

    for (const check of checkType.results.failed_checks) {
      findings.push({
        id: makeFindingId({
          scanner: SCANNER,
          checkId: check.check_id,
          resource: check.resource,
          file: check.file_path,
        }),
        scanner: SCANNER,
        severity: mapSeverity(check.severity),
        title: checkIdToTitle(check.check_id, check.description),
        description: `${checkType.check_type} check "${check.check_id}" failed on resource "${check.resource}" in ${check.file_path}`,
        file: check.file_path,
        line: check.file_line_range?.[0],
        evidence: {
          kind: 'scanner_native',
          ref: evidenceRef,
        },
        remediation: check.guideline
          ? `See guidance: ${check.guideline}`
          : `Fix the misconfiguration identified by ${check.check_id} in resource "${check.resource}".`,
        tags: ['iac', checkType.check_type, check.check_id],
      });
    }
  }

  return findings;
}
