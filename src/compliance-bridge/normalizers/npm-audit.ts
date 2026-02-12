/**
 * npm audit Output Normalizer
 *
 * Parses `npm audit --json` output into NormalizedFinding[].
 * Detects vulnerable dependencies in Node.js projects.
 */

import { createHash } from 'node:crypto';
import type { NormalizedFinding, Severity, ScannerId } from '../contracts.js';

const SCANNER: ScannerId = 'npm_audit';

interface NpmVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | { title: string; url: string; severity: string; cwe: string[]; range: string }>;
  effects: string[];
  range: string;
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
  nodes: string[];
}

interface NpmAuditOutput {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, NpmVulnerability>;
  metadata?: {
    vulnerabilities: Record<string, number>;
    dependencies: number;
    totalDependencies: number;
  };
}

function makeFindingId(input: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
    .slice(0, 16);
}

function mapSeverity(npmSeverity: string): Severity {
  switch (npmSeverity.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

function getFixAdvice(fixAvailable: NpmVulnerability['fixAvailable']): string {
  if (fixAvailable === true) {
    return 'Run `npm audit fix` to update to a patched version.';
  }
  if (fixAvailable && typeof fixAvailable === 'object') {
    const breaking = fixAvailable.isSemVerMajor ? ' (BREAKING CHANGE)' : '';
    return `Update ${fixAvailable.name} to ${fixAvailable.version}${breaking}.`;
  }
  return 'No automated fix available. Review and manually update the dependency.';
}

function getVulnTitle(vuln: NpmVulnerability): string {
  for (const v of vuln.via) {
    if (typeof v === 'object' && v.title) {
      return `${vuln.name}: ${v.title}`;
    }
  }
  return `Vulnerable dependency: ${vuln.name}`;
}

/**
 * Normalize npm audit JSON output into unified findings.
 *
 * @param rawJson - Raw JSON string from `npm audit --json`
 * @param evidenceRef - Path to the npm audit output file
 */
export function normalizeNpmAudit(
  rawJson: string,
  evidenceRef: string
): NormalizedFinding[] {
  let parsed: NpmAuditOutput;

  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return [];
  }

  if (!parsed.vulnerabilities) {
    return [];
  }

  const findings: NormalizedFinding[] = [];

  for (const [pkgName, vuln] of Object.entries(parsed.vulnerabilities)) {
    findings.push({
      id: makeFindingId({ scanner: SCANNER, pkg: pkgName, severity: vuln.severity }),
      scanner: SCANNER,
      severity: mapSeverity(vuln.severity),
      title: getVulnTitle(vuln),
      description: `${vuln.isDirect ? 'Direct' : 'Transitive'} dependency "${pkgName}" has known vulnerabilities (severity: ${vuln.severity}).`,
      file: 'package.json',
      evidence: {
        kind: 'scanner_native',
        ref: evidenceRef,
      },
      remediation: getFixAdvice(vuln.fixAvailable),
      tags: ['dependency', pkgName, vuln.severity],
    });
  }

  return findings;
}
