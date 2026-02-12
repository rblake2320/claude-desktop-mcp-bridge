/**
 * Audit Packet Generator
 *
 * Produces an evidence-grade audit directory containing:
 *   audit_packet/
 *     index.md          -- Executive summary
 *     findings.json     -- Normalized findings array
 *     coverage.json     -- SOC2 control coverage
 *     roi.json          -- ROI estimate
 *     evidence/         -- Raw scanner output copies
 */

import { mkdirSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { assertCompliancePath } from '../shared/path-policy.js';
import type {
  ScanRepoResponse,
  GenerateAuditPacketResponse,
  Severity,
} from './contracts.js';

// ── Severity ordering for display ────────────────────────────────

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ── Markdown Generation ──────────────────────────────────────────

function severityBadge(severity: Severity): string {
  const badges: Record<Severity, string> = {
    critical: '**CRITICAL**',
    high: '**HIGH**',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
  };
  return badges[severity] ?? severity;
}

function generateIndexMd(scan: ScanRepoResponse): string {
  const lines: string[] = [];
  const ts = new Date().toISOString();

  // Filter real findings for display (exclude scanner-missing meta-findings)
  const realFindings = scan.findings.filter(f => !f.tags?.includes('scanner-missing'));
  const missingFindings = scan.findings.filter(f => f.tags?.includes('scanner-missing'));

  lines.push('# Compliance Audit Report');
  lines.push('');
  lines.push(`**Generated**: ${ts}`);
  lines.push(`**Repository**: \`${scan.repoPath}\``);
  lines.push(`**Framework**: SOC2-Lite (20 controls)`);
  lines.push(`**Run ID**: ${scan.runId}`);
  lines.push(`**Scan Period**: ${scan.startedAt} to ${scan.finishedAt}`);
  if (scan.manifest.repoCommitHash) {
    lines.push(`**Commit**: \`${scan.manifest.repoCommitHash}\``);
  }
  lines.push('');

  // Executive summary
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Findings | ${realFindings.length} |`);
  lines.push(`| Critical | ${scan.countsBySeverity.critical ?? 0} |`);
  lines.push(`| High | ${scan.countsBySeverity.high ?? 0} |`);
  lines.push(`| Medium | ${scan.countsBySeverity.medium ?? 0} |`);
  lines.push(`| Low | ${scan.countsBySeverity.low ?? 0} |`);
  const totalControls = scan.controlCoverage.coveredControls.length + scan.controlCoverage.missingControls.length;
  const potentialControls = scan.controlCoverage.coveredControlsPotential?.length ?? 0;
  lines.push(`| SOC2 Coverage (observed) | ${scan.controlCoverage.coveragePct}% (${scan.controlCoverage.coveredControls.length}/${totalControls}) |`);
  lines.push(`| SOC2 Coverage (potential) | ${scan.controlCoverage.coveragePctPotential ?? 0}% (${potentialControls}/${totalControls}) |`);
  lines.push(`| SOC2 Coverage (full pack) | ${scan.controlCoverage.coveragePctFull ?? 100}% |`);
  lines.push(`| Hours Saved (conservative) | ${scan.roiEstimate.hoursSavedConservative} |`);
  lines.push(`| Hours Saved (likely) | ${scan.roiEstimate.hoursSavedLikely} |`);
  lines.push('');

  // Top 3 Risk Themes
  lines.push('## Top Risk Themes');
  lines.push('');
  const themes: { theme: string; count: number; description: string }[] = [];
  if (scan.countsByScanner.gitleaks > 0) {
    themes.push({ theme: 'Exposed Secrets', count: scan.countsByScanner.gitleaks, description: 'API keys, tokens, or credentials detected in source code' });
  }
  if (scan.countsByScanner.npm_audit > 0) {
    themes.push({ theme: 'Supply Chain Vulnerabilities', count: scan.countsByScanner.npm_audit, description: 'Known vulnerabilities in project dependencies' });
  }
  if (scan.countsByScanner.checkov > 0) {
    themes.push({ theme: 'Infrastructure Misconfigurations', count: scan.countsByScanner.checkov, description: 'IaC resources that deviate from security best practices' });
  }
  if (themes.length === 0) {
    lines.push('No risk themes identified from scanner findings.');
  } else {
    themes.sort((a, b) => b.count - a.count);
    for (let i = 0; i < Math.min(3, themes.length); i++) {
      lines.push(`${i + 1}. **${themes[i].theme}** (${themes[i].count} findings) - ${themes[i].description}`);
    }
  }
  lines.push('');

  // Scanner Status
  lines.push('## Scanner Status');
  lines.push('');
  lines.push(`| Scanner | Status | Version | Findings |`);
  lines.push(`|---------|--------|---------|----------|`);
  for (const s of scan.scannerStatuses) {
    const icon = s.status === 'ok' ? 'OK' : s.status === 'missing' ? 'NOT INSTALLED' : s.status === 'skipped' ? 'SKIPPED' : 'ERROR';
    const ver = s.version ?? '-';
    const count = scan.countsByScanner[s.scanner] ?? 0;
    lines.push(`| ${s.scanner} | ${icon} | ${ver} | ${s.status === 'ok' ? count : s.message ?? '-'} |`);
  }
  lines.push('');

  if (missingFindings.length > 0) {
    lines.push('> **Note**: Some scanners are not installed. Install them to expand coverage.');
    lines.push('');
  }

  // SOC2 Control Coverage
  lines.push('## SOC2 Control Coverage');
  lines.push('');
  lines.push(`| Control | Name | Status | Findings |`);
  lines.push(`|---------|------|--------|----------|`);
  for (const detail of scan.controlCoverage.controlDetails) {
    const status = detail.status === 'covered' ? 'Covered' : 'GAP';
    lines.push(`| ${detail.controlId} | ${detail.controlName} | ${status} | ${detail.findingCount} |`);
  }
  lines.push('');

  if (scan.controlCoverage.missingControls.length > 0) {
    lines.push('### Coverage Gaps');
    lines.push('');
    lines.push('The following controls have no scanner coverage and require manual review:');
    lines.push('');
    for (const controlId of scan.controlCoverage.missingControls) {
      lines.push(`- ${controlId}`);
    }
    lines.push('');
  }

  // Top findings (up to 10)
  const topFindings = [...realFindings]
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .slice(0, 10);

  lines.push('## Top Findings');
  lines.push('');
  if (topFindings.length === 0) {
    lines.push('No findings detected.');
  } else {
    lines.push(`| # | Severity | Scanner | Title | File |`);
    lines.push(`|---|----------|---------|-------|------|`);
    topFindings.forEach((f, i) => {
      lines.push(`| ${i + 1} | ${severityBadge(f.severity)} | ${f.scanner} | ${f.title} | ${f.file ?? '-'} |`);
    });
  }
  lines.push('');

  // Recommended Next Actions
  lines.push('## Recommended Next Actions');
  lines.push('');
  const actions: string[] = [];
  if (scan.countsBySeverity.critical > 0) {
    actions.push(`Address ${scan.countsBySeverity.critical} **critical** finding(s) immediately - these represent active security risks`);
  }
  if (scan.countsBySeverity.high > 0) {
    actions.push(`Remediate ${scan.countsBySeverity.high} **high**-severity finding(s) within current sprint`);
  }
  if (missingFindings.length > 0) {
    const missing = scan.scannerStatuses.filter(s => s.status === 'missing').map(s => s.scanner);
    actions.push(`Install missing scanners (${missing.join(', ')}) to expand control coverage`);
  }
  if (scan.controlCoverage.missingControls.length > 0) {
    actions.push(`Review ${scan.controlCoverage.missingControls.length} uncovered SOC2 controls for manual assessment`);
  }
  actions.push('Run `compliance.plan_remediation` for a prioritized step-by-step fix plan');
  for (const action of actions) {
    lines.push(`- ${action}`);
  }
  lines.push('');

  // ROI
  lines.push('## ROI Estimate');
  lines.push('');
  lines.push(`| Estimate | Hours Saved |`);
  lines.push(`|----------|-------------|`);
  lines.push(`| Conservative (triage + fix only) | ${scan.roiEstimate.hoursSavedConservative} |`);
  lines.push(`| Likely (incl. context switching, review) | ${scan.roiEstimate.hoursSavedLikely} |`);
  lines.push('');
  lines.push(`_${scan.roiEstimate.basis}_`);
  lines.push('');

  // What this does NOT cover
  lines.push('## Scope Limitations');
  lines.push('');
  lines.push('This automated scan does **not** cover:');
  lines.push('');
  lines.push('- Business logic vulnerabilities or authorization flaws');
  lines.push('- SOC2 Type II operational effectiveness (only point-in-time detection)');
  lines.push('- Physical security controls or HR policies');
  lines.push('- Penetration testing or dynamic application security testing (DAST)');
  lines.push('- Custom application code review beyond secret detection');
  lines.push('- Third-party vendor risk assessment');
  lines.push('');
  lines.push('For full SOC2 compliance, combine these results with manual control assessments and an external auditor review.');
  lines.push('');

  // Security Policy
  if (scan.manifest.policy) {
    lines.push('## Security Policy');
    lines.push('');
    lines.push('| Gate | Detail |');
    lines.push('|------|--------|');
    lines.push(`| Command Allowlist | ${scan.manifest.policy.commandAllowlist.join(', ')} |`);
    lines.push(`| Shell Execution | ${scan.manifest.policy.shellExecution} |`);
    lines.push(`| Path Policy | ${scan.manifest.policy.pathPolicy} |`);
    if (scan.manifest.excludedPaths && scan.manifest.excludedPaths.length > 0) {
      lines.push(`| Excluded Paths | ${scan.manifest.excludedPaths.map(p => `\`${p}\``).join(', ')} |`);
    }
    lines.push('');
  }

  // Evidence
  lines.push('## Evidence');
  lines.push('');
  lines.push('Raw scanner outputs are preserved in the `evidence/` directory:');
  lines.push('');
  for (const transcript of scan.transcripts) {
    lines.push(`- **${transcript.tool}**: \`${basename(transcript.stdoutPath)}\` (exit code: ${transcript.exitCode}, ${transcript.durationMs}ms)`);
  }
  lines.push('');

  // Footer
  lines.push('---');
  lines.push('');
  lines.push(`*Generated by Compliance Navigator v${scan.manifest.complianceNavigatorVersion} | Node ${scan.manifest.nodeVersion} | ${scan.manifest.os}*`);
  lines.push('');

  return lines.join('\n');
}

// ── Packet Generation ────────────────────────────────────────────

export interface AuditPacketOptions {
  repoPath: string;
  scanResult: ScanRepoResponse;
  outputDir?: string;
}

/**
 * Generate a complete audit packet directory.
 *
 * All paths are validated against the compliance path policy
 * to prevent directory escape.
 */
export function generateAuditPacket(options: AuditPacketOptions): GenerateAuditPacketResponse {
  const { repoPath, scanResult, outputDir } = options;

  // Determine output location
  const packetRoot = outputDir
    ? resolve(outputDir)
    : resolve(repoPath, '.compliance', 'runs', scanResult.runId, 'audit_packet');

  // Security: verify all write targets are under .compliance/
  assertCompliancePath(repoPath, resolve(packetRoot, 'placeholder'));

  const evidenceDir = resolve(packetRoot, 'evidence');

  // Create directories
  mkdirSync(packetRoot, { recursive: true });
  mkdirSync(evidenceDir, { recursive: true });

  const files: string[] = [];

  // 1. Write index.md
  const indexPath = resolve(packetRoot, 'index.md');
  assertCompliancePath(repoPath, indexPath);
  writeFileSync(indexPath, generateIndexMd(scanResult), 'utf-8');
  files.push(indexPath);

  // 2. Write findings.json
  const findingsPath = resolve(packetRoot, 'findings.json');
  assertCompliancePath(repoPath, findingsPath);
  writeFileSync(findingsPath, JSON.stringify(scanResult.findings, null, 2), 'utf-8');
  files.push(findingsPath);

  // 3. Write coverage.json
  const coveragePath = resolve(packetRoot, 'coverage.json');
  assertCompliancePath(repoPath, coveragePath);
  writeFileSync(coveragePath, JSON.stringify(scanResult.controlCoverage, null, 2), 'utf-8');
  files.push(coveragePath);

  // 4. Write roi.json
  const roiPath = resolve(packetRoot, 'roi.json');
  assertCompliancePath(repoPath, roiPath);
  writeFileSync(roiPath, JSON.stringify(scanResult.roiEstimate, null, 2), 'utf-8');
  files.push(roiPath);

  // 5. Write manifest.json (deterministic export metadata)
  const manifestPath = resolve(packetRoot, 'manifest.json');
  assertCompliancePath(repoPath, manifestPath);
  writeFileSync(manifestPath, JSON.stringify(scanResult.manifest, null, 2), 'utf-8');
  files.push(manifestPath);

  // 6. Copy evidence artifacts (raw scanner outputs)
  for (const transcript of scanResult.transcripts) {
    for (const srcPath of [transcript.stdoutPath, transcript.stderrPath]) {
      if (existsSync(srcPath)) {
        const destPath = resolve(evidenceDir, basename(srcPath));
        assertCompliancePath(repoPath, destPath);
        copyFileSync(srcPath, destPath);
        files.push(destPath);
      }
    }
  }

  return {
    auditPacketPath: packetRoot,
    indexPath,
    findingsJsonPath: findingsPath,
    evidencePath: evidenceDir,
    generatedAt: new Date().toISOString(),
    files,
  };
}
