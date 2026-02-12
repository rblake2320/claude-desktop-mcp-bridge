/**
 * Gitleaks Output Normalizer
 *
 * Parses gitleaks JSON report into NormalizedFinding[].
 * Gitleaks detects secrets in code (API keys, passwords, tokens).
 */

import { createHash } from 'node:crypto';
import type { NormalizedFinding, ScannerId } from '../contracts.js';

const SCANNER: ScannerId = 'gitleaks';

/**
 * Gitleaks native finding shape (from --report-format json).
 */
interface GitleaksFinding {
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  RuleID: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  Fingerprint: string;
}

function makeFindingId(input: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
    .slice(0, 16);
}

/**
 * Map gitleaks RuleID to a human-friendly title.
 */
function ruleToTitle(ruleId: string, description: string): string {
  return description || `Secret detected: ${ruleId}`;
}

/**
 * All secrets are high severity by default.
 * Exposed credentials are always a critical security risk.
 */
function mapSeverity(ruleId: string): 'critical' | 'high' {
  // Private keys and high-entropy tokens are critical
  const criticalPatterns = ['private-key', 'aws-secret', 'github-pat'];
  if (criticalPatterns.some(p => ruleId.toLowerCase().includes(p))) {
    return 'critical';
  }
  return 'high';
}

/**
 * Normalize gitleaks JSON output into unified findings.
 *
 * @param rawJson - Raw JSON string from gitleaks report file
 * @param evidenceRef - Path to the gitleaks output file (for evidence linkage)
 */
export function normalizeGitleaks(
  rawJson: string,
  evidenceRef: string
): NormalizedFinding[] {
  let parsed: GitleaksFinding[];

  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) {
    return [];
  }

  return parsed.map((f): NormalizedFinding => ({
    id: makeFindingId({ scanner: SCANNER, rule: f.RuleID, file: f.File, line: f.StartLine }),
    scanner: SCANNER,
    severity: mapSeverity(f.RuleID),
    title: ruleToTitle(f.RuleID, f.Description),
    description: `Secret detected by rule "${f.RuleID}" in ${f.File}:${f.StartLine}`,
    file: f.File,
    line: f.StartLine,
    evidence: {
      kind: 'scanner_native',
      ref: evidenceRef,
    },
    remediation: `Rotate the exposed credential and remove it from source code. Consider using environment variables or a secrets manager.`,
    tags: ['secret', f.RuleID, ...(f.Tags ?? [])],
  }));
}
