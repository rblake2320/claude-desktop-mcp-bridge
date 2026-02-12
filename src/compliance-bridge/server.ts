/**
 * Compliance Navigator - MCP Server
 *
 * Standalone MCP server with 3 tools:
 *   1. compliance.scan_repo       - Run gitleaks + npm audit + checkov, normalize, map SOC2, compute ROI
 *   2. compliance.generate_audit_packet - Write evidence-grade audit directory
 *   3. compliance.plan_remediation      - Prioritized remediation plan
 *
 * Transport: StdioServerTransport (JSON-RPC over stdin/stdout)
 * All diagnostic output goes to stderr.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { platform, homedir } from 'node:os';

import { ScanRepoSchema, GenerateAuditPacketSchema, PlanRemediationSchema, CreateTicketsSchema, ApproveTicketPlanSchema } from './schemas.js';
import { getToolRisk } from './policy.js';
import { assertAllowedCommand, COMPLIANCE_COMMAND_ALLOWLIST } from '../shared/command-allowlist.js';
import { assertCompliancePath, validateRepoPath } from '../shared/path-policy.js';
import { AuditChain } from '../shared/audit-chain.js';
import { normalizeGitleaks } from './normalizers/gitleaks.js';
import { normalizeNpmAudit } from './normalizers/npm-audit.js';
import { normalizeCheckov } from './normalizers/checkov.js';
import { mapFindingsToControls, computeCoverage, annotateFindingsWithControls } from './soc2-map.js';
import { calculateROI } from './roi.js';
import { generateAuditPacket } from './audit-packet.js';
import { handleCreateTickets, handleApproveTicketPlan } from './ticket-writer.js';
import type {
  NormalizedFinding,
  ScanRepoResponse,
  GenerateAuditPacketResponse,
  PlanRemediationResponse,
  RemediationStep,
  Severity,
  ScannerId,
  ToolRunTranscript,
  ScannerStatus,
  AuditManifest,
  CreateTicketsResponse,
  ApproveTicketPlanResponse,
} from './contracts.js';

// ── Constants ────────────────────────────────────────────────────

const SERVER_NAME = 'compliance-navigator';
const SERVER_VERSION = '0.1.0';
const isWindows = platform() === 'win32';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Effort estimates in minutes per finding severity
const EFFORT_MINUTES: Record<Severity, number> = {
  critical: 120,
  high: 60,
  medium: 30,
  low: 15,
  info: 5,
};

// ── Audit Chain ──────────────────────────────────────────────────

const auditChain = new AuditChain(
  resolve(process.cwd(), 'logs', 'compliance-audit-chain.jsonl')
);

// ── Scanner Execution ────────────────────────────────────────────

interface SpawnResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

// On Windows, augment PATH with common tool install locations
function getAugmentedEnv(): NodeJS.ProcessEnv {
  if (!isWindows) return process.env;
  const home = homedir();
  const extraPaths = [
    resolve(home, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links'),
    resolve(home, 'AppData', 'Local', 'Programs', 'Python', 'Python312', 'Scripts'),
    resolve(home, '.local', 'bin'),
  ];
  // Also search for winget package directories
  const wingetPkgs = resolve(home, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
  if (existsSync(wingetPkgs)) {
    try {
      const pkgDirs = readdirSync(wingetPkgs, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => resolve(wingetPkgs, d.name));
      extraPaths.push(...pkgDirs);
    } catch { /* ignore */ }
  }
  const currentPath = process.env.PATH ?? '';
  return { ...process.env, PATH: `${currentPath};${extraPaths.join(';')}` };
}

const augmentedEnv = getAugmentedEnv();

function runCommand(command: string, args: string[], cwd: string, timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    // On Windows, use shell for .cmd resolution and augmented PATH
    const proc = isWindows
      ? spawn(command, args, { cwd, shell: true, timeout: timeoutMs, stdio: ['ignore', 'pipe', 'pipe'], windowsVerbatimArguments: true, env: augmentedEnv })
      : spawn(command, args, { cwd, timeout: timeoutMs, stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on('close', (code) => {
      resolve({
        exitCode: code ?? 1,
        stdout,
        stderr,
        durationMs: Date.now() - start,
      });
    });

    proc.on('error', (err) => {
      resolve({
        exitCode: 127,
        stdout,
        stderr: stderr + '\n' + (err as Error).message,
        durationMs: Date.now() - start,
      });
    });
  });
}

// ── Scanner Result with Status ────────────────────────────────────

interface ScannerRunResult {
  findings: NormalizedFinding[];
  transcript: ToolRunTranscript | null;
  status: ScannerStatus;
}

function isScannerMissing(result: SpawnResult): boolean {
  // exit code 127 = command not found (Unix), ENOENT in stderr (Windows/Node)
  return result.exitCode === 127
    || result.stderr.includes('ENOENT')
    || result.stderr.includes('is not recognized')
    || result.stderr.includes('not found');
}

function makeMissingFinding(scanner: ScannerId, label: string): NormalizedFinding {
  return {
    id: `missing-${scanner}`,
    scanner,
    severity: 'info',
    title: `Scanner unavailable: ${label}`,
    description: `The ${label} scanner is not installed on this system. Install it to enable ${scanner === 'gitleaks' ? 'secret detection' : scanner === 'npm_audit' ? 'dependency vulnerability scanning' : 'IaC misconfiguration scanning'}.`,
    evidence: { kind: 'scanner_native', ref: 'N/A' },
    remediation: scanner === 'gitleaks'
      ? 'Install gitleaks: https://github.com/gitleaks/gitleaks#installing'
      : scanner === 'checkov'
      ? 'Install checkov: pip install checkov'
      : 'npm audit is built into Node.js - ensure Node.js is installed.',
    tags: ['scanner-missing', scanner],
  };
}

function getRepoCommitHash(repoPath: string): string | undefined {
  const headPath = resolve(repoPath, '.git', 'HEAD');
  if (!existsSync(headPath)) return undefined;
  try {
    const head = readFileSync(headPath, 'utf-8').trim();
    if (head.startsWith('ref: ')) {
      const refPath = resolve(repoPath, '.git', head.slice(5));
      if (existsSync(refPath)) {
        return readFileSync(refPath, 'utf-8').trim().slice(0, 12);
      }
    }
    return head.slice(0, 12);
  } catch {
    return undefined;
  }
}

function buildManifest(
  runId: string,
  repoPath: string,
  scannerStatuses: ScannerStatus[],
): AuditManifest {
  const versions: Record<ScannerId, string | null> = {
    gitleaks: null,
    npm_audit: null,
    checkov: null,
  };
  for (const s of scannerStatuses) {
    versions[s.scanner] = s.version ?? null;
  }

  // Build policy record from allowlist
  const commandAllowlist = COMPLIANCE_COMMAND_ALLOWLIST.map(r => r.description);

  // Read excluded paths from .gitleaks.toml if present
  const excludedPaths: string[] = [];
  try {
    const tomlPath = resolve(repoPath, '.gitleaks.toml');
    if (existsSync(tomlPath)) {
      const tomlContent = readFileSync(tomlPath, 'utf-8');
      const pathMatches = tomlContent.match(/'''([^']+)'''/g);
      if (pathMatches) {
        for (const m of pathMatches) {
          excludedPaths.push(m.replace(/'''/g, ''));
        }
      }
    }
  } catch { /* non-fatal */ }

  return {
    generatedAt: new Date().toISOString(),
    runId,
    repoPath,
    repoCommitHash: getRepoCommitHash(repoPath),
    os: `${platform()} ${process.arch}`,
    nodeVersion: process.version,
    scannerVersions: versions,
    framework: 'soc2',
    complianceNavigatorVersion: SERVER_VERSION,
    policy: {
      commandAllowlist,
      shellExecution: isWindows ? 'shell: true (Windows, cmd resolution)' : 'shell: false (direct exec)',
      pathPolicy: 'All writes pinned to <repo>/.compliance/ -- directory escape blocked',
    },
    excludedPaths,
  };
}

// ── Tool Definitions ─────────────────────────────────────────────

const tools: Tool[] = [
  {
    name: 'compliance.scan_repo',
    description: 'Scan a repository for security findings using gitleaks (secrets), npm audit (dependencies), and checkov (IaC). Maps findings to SOC2 controls and estimates ROI.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository to scan' },
        framework: { type: 'string', enum: ['soc2'], default: 'soc2', description: 'Compliance framework' },
        mode: { type: 'string', enum: ['report-only', 'generate-remediation'], default: 'report-only' },
        maxMinutes: { type: 'number', default: 10, description: 'Max scan duration in minutes' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.generate_audit_packet',
    description: 'Generate an evidence-grade audit packet directory with index.md, findings.json, coverage.json, roi.json, and raw scanner evidence.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
        outputDir: { type: 'string', description: 'Custom output directory (must be under .compliance/)' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.plan_remediation',
    description: 'Generate a prioritized remediation plan from scan findings, sorted by severity with effort estimates and SOC2 control mappings.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
        maxItems: { type: 'number', default: 20, description: 'Maximum remediation items to include' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.create_tickets',
    description: 'Create GitHub Issues from scan findings. Always generates a preview plan first (dryRun=true). To execute, approve the plan first with compliance.approve_ticket_plan, then call again with approvedPlanId and dryRun=false.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
        maxItems: { type: 'number', default: 10, description: 'Maximum tickets to create (default 10)' },
        target: { type: 'string', enum: ['github', 'jira'], default: 'github', description: 'Ticket system target' },
        targetRepo: { type: 'string', description: 'Explicit owner/name override (e.g. "acme/api"). If omitted, derived from git remote.' },
        dryRun: { type: 'boolean', default: true, description: 'Preview plan without creating tickets (default true)' },
        approvedPlanId: { type: 'string', description: 'Plan ID from a previously approved dry-run (required for execution)' },
        reopenClosed: { type: 'boolean', default: false, description: 'Reopen closed duplicate issues instead of skipping (default false)' },
        labelPolicy: { type: 'string', enum: ['require-existing', 'create-if-missing'], default: 'require-existing', description: 'Label creation policy (default require-existing)' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.approve_ticket_plan',
    description: 'Approve a pending ticket creation plan. Required before executing compliance.create_tickets with dryRun=false.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        planId: { type: 'string', description: 'Plan ID from the dry-run response' },
        approvedBy: { type: 'string', description: 'Name or identifier of the person approving' },
        reason: { type: 'string', description: 'Optional reason for approval' },
      },
      required: ['repoPath', 'planId', 'approvedBy'],
    },
  },
];

// ── Scan Result Storage ──────────────────────────────────────────

// In-memory store of recent scan results (also persisted to disk)
const scanResults = new Map<string, ScanRepoResponse>();

function getLatestRunId(repoPath: string): string | undefined {
  const runsDir = resolve(repoPath, '.compliance', 'runs');
  if (!existsSync(runsDir)) return undefined;

  const dirs = readdirSync(runsDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name)
    .sort()
    .reverse();

  return dirs[0];
}

function loadScanResult(repoPath: string, runId: string): ScanRepoResponse | undefined {
  // Check in-memory cache first
  const cached = scanResults.get(runId);
  if (cached) return cached;

  // Try loading from disk
  const resultPath = resolve(repoPath, '.compliance', 'runs', runId, 'scan_result.json');
  if (existsSync(resultPath)) {
    try {
      const result = JSON.parse(readFileSync(resultPath, 'utf-8')) as ScanRepoResponse;
      scanResults.set(runId, result);
      return result;
    } catch {
      return undefined;
    }
  }

  return undefined;
}

// ── Scanner Runners ──────────────────────────────────────────────

async function runGitleaks(
  repoPath: string, outputDir: string, timeoutMs: number
): Promise<ScannerRunResult> {
  const outputPath = resolve(outputDir, 'gitleaks.json');
  const cmd = isWindows ? 'gitleaks.exe' : 'gitleaks';
  const args = ['detect', '--source', repoPath, '--report-format', 'json', '--report-path', outputPath, '--no-git'];

  // Use .gitleaks.toml config if present in repo root (excludes dist/, node_modules/, etc.)
  const tomlPath = resolve(repoPath, '.gitleaks.toml');
  if (existsSync(tomlPath)) {
    args.push('--config', tomlPath);
  }

  const fullCommand = `${cmd} ${args.join(' ')}`;
  assertAllowedCommand(fullCommand);

  const startedAt = new Date().toISOString();
  const result = await runCommand(cmd, args, repoPath, timeoutMs);

  const transcript: ToolRunTranscript = {
    tool: 'gitleaks',
    command: fullCommand,
    cwd: repoPath,
    startedAt,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stdoutPath: outputPath,
    stderrPath: resolve(outputDir, 'gitleaks-stderr.txt'),
  };

  writeFileSync(transcript.stderrPath, result.stderr, 'utf-8');

  // Check if scanner is missing
  if (isScannerMissing(result)) {
    writeFileSync(outputPath, '[]', 'utf-8');
    return {
      findings: [makeMissingFinding('gitleaks', 'gitleaks')],
      transcript,
      status: { scanner: 'gitleaks', status: 'missing', message: 'gitleaks binary not found' },
    };
  }

  // If gitleaks wrote report to file, read it; otherwise use stdout
  let rawJson = '';
  if (existsSync(outputPath)) {
    rawJson = readFileSync(outputPath, 'utf-8');
  } else {
    rawJson = result.stdout;
    writeFileSync(outputPath, rawJson, 'utf-8');
  }

  const findings = normalizeGitleaks(rawJson, outputPath);

  // Capture version (allowlisted, failure is non-fatal)
  let version: string | undefined;
  try {
    const versionCmd = `${cmd} version`;
    assertAllowedCommand(versionCmd);
    const versionResult = await runCommand(cmd, ['version'], repoPath, 5000);
    version = versionResult.exitCode === 0 ? versionResult.stdout.trim().split('\n')[0] : undefined;
  } catch { /* version capture is best-effort */ }

  return {
    findings,
    transcript,
    status: { scanner: 'gitleaks', status: 'ok', version },
  };
}

async function runNpmAudit(
  repoPath: string, outputDir: string, timeoutMs: number
): Promise<ScannerRunResult> {
  const outputPath = resolve(outputDir, 'npm-audit.json');
  const cmd = isWindows ? 'npm.cmd' : 'npm';
  const args = ['audit', '--json'];

  const fullCommand = `${cmd} ${args.join(' ')}`;
  assertAllowedCommand(fullCommand);

  // Only run if package.json exists
  if (!existsSync(resolve(repoPath, 'package.json'))) {
    const emptyTranscript: ToolRunTranscript = {
      tool: 'npm_audit',
      command: fullCommand,
      cwd: repoPath,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      exitCode: -1,
      durationMs: 0,
      stdoutPath: outputPath,
      stderrPath: resolve(outputDir, 'npm-audit-stderr.txt'),
    };
    writeFileSync(outputPath, '{}', 'utf-8');
    writeFileSync(emptyTranscript.stderrPath, 'Skipped: no package.json found', 'utf-8');
    return {
      findings: [],
      transcript: emptyTranscript,
      status: { scanner: 'npm_audit', status: 'skipped', message: 'No package.json found' },
    };
  }

  const startedAt = new Date().toISOString();
  const result = await runCommand(cmd, args, repoPath, timeoutMs);

  const transcript: ToolRunTranscript = {
    tool: 'npm_audit',
    command: fullCommand,
    cwd: repoPath,
    startedAt,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stdoutPath: outputPath,
    stderrPath: resolve(outputDir, 'npm-audit-stderr.txt'),
  };

  writeFileSync(outputPath, result.stdout, 'utf-8');
  writeFileSync(transcript.stderrPath, result.stderr, 'utf-8');

  if (isScannerMissing(result)) {
    return {
      findings: [makeMissingFinding('npm_audit', 'npm audit')],
      transcript,
      status: { scanner: 'npm_audit', status: 'missing', message: 'npm not found' },
    };
  }

  // npm audit exits non-zero when vulnerabilities exist, which is expected
  // Validate that stdout is parseable JSON (npm can emit non-JSON warnings)
  try {
    JSON.parse(result.stdout);
  } catch {
    return {
      findings: [],
      transcript,
      status: {
        scanner: 'npm_audit',
        status: 'error',
        message: `npm audit output is not valid JSON. Check ${transcript.stderrPath}`,
      },
    };
  }

  const findings = normalizeNpmAudit(result.stdout, outputPath);

  // Capture npm version (allowlisted, failure is non-fatal)
  let version: string | undefined;
  try {
    const versionCmd = `${cmd} --version`;
    assertAllowedCommand(versionCmd);
    const versionResult = await runCommand(cmd, ['--version'], repoPath, 5000);
    version = versionResult.exitCode === 0 ? versionResult.stdout.trim().split('\n')[0] : undefined;
  } catch { /* version capture is best-effort */ }

  return {
    findings,
    transcript,
    status: { scanner: 'npm_audit', status: 'ok', version },
  };
}

async function runCheckov(
  repoPath: string, outputDir: string, timeoutMs: number
): Promise<ScannerRunResult> {
  const outputPath = resolve(outputDir, 'checkov.json');
  const cmd = 'checkov';
  const args = ['-d', repoPath, '-o', 'json'];

  const fullCommand = `${cmd} ${args.join(' ')}`;
  assertAllowedCommand(fullCommand);

  const startedAt = new Date().toISOString();
  const result = await runCommand(cmd, args, repoPath, timeoutMs);

  const transcript: ToolRunTranscript = {
    tool: 'checkov',
    command: fullCommand,
    cwd: repoPath,
    startedAt,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stdoutPath: outputPath,
    stderrPath: resolve(outputDir, 'checkov-stderr.txt'),
  };

  writeFileSync(outputPath, result.stdout, 'utf-8');
  writeFileSync(transcript.stderrPath, result.stderr, 'utf-8');

  if (isScannerMissing(result)) {
    return {
      findings: [makeMissingFinding('checkov', 'checkov')],
      transcript,
      status: { scanner: 'checkov', status: 'missing', message: 'checkov binary not found' },
    };
  }

  const findings = normalizeCheckov(result.stdout, outputPath);

  // Capture version (allowlisted, failure is non-fatal)
  let version: string | undefined;
  try {
    const versionCmd = `${cmd} --version`;
    assertAllowedCommand(versionCmd);
    const versionResult = await runCommand(cmd, ['--version'], repoPath, 10000);
    version = versionResult.exitCode === 0 ? versionResult.stdout.trim().split('\n')[0] : undefined;
  } catch { /* version capture is best-effort */ }

  return {
    findings,
    transcript,
    status: { scanner: 'checkov', status: 'ok', version },
  };
}

// ── Tool Handlers ────────────────────────────────────────────────

async function handleScanRepo(args: unknown): Promise<ScanRepoResponse> {
  const input = ScanRepoSchema.parse(args);
  const { repoPath, maxMinutes } = input;

  // Validate repo path
  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = randomUUID().slice(0, 8) + '-' + Date.now();
  const runDir = resolve(repoPath, '.compliance', 'runs', runId);
  const evidenceDir = resolve(runDir, 'evidence');
  mkdirSync(evidenceDir, { recursive: true });

  // Validate write target
  assertCompliancePath(repoPath, resolve(evidenceDir, 'placeholder'));

  const startedAt = new Date().toISOString();
  const timeoutMs = maxMinutes * 60 * 1000;

  auditChain.append('tool_start', 'compliance.scan_repo', { runId, repoPath });

  // Run all 3 scanners concurrently, gracefully handling errors
  const defaultResult = (scanner: ScannerId, err: Error): ScannerRunResult => {
    console.error(`[${scanner}] Scanner error: ${err.message}`);
    return {
      findings: [makeMissingFinding(scanner, scanner)],
      transcript: null,
      status: { scanner, status: 'error', message: err.message },
    };
  };

  const [gitleaksResult, npmResult, checkovResult] = await Promise.all([
    runGitleaks(repoPath, evidenceDir, timeoutMs)
      .catch(err => defaultResult('gitleaks', err as Error)),
    runNpmAudit(repoPath, evidenceDir, timeoutMs)
      .catch(err => defaultResult('npm_audit', err as Error)),
    runCheckov(repoPath, evidenceDir, timeoutMs)
      .catch(err => defaultResult('checkov', err as Error)),
  ]);

  // Collect scanner statuses
  const scannerStatuses: ScannerStatus[] = [
    gitleaksResult.status,
    npmResult.status,
    checkovResult.status,
  ];

  // Merge all findings (excluding scanner-missing meta-findings from real counts)
  const allFindings: NormalizedFinding[] = [
    ...gitleaksResult.findings,
    ...npmResult.findings,
    ...checkovResult.findings,
  ];

  const transcripts: ToolRunTranscript[] = [
    gitleaksResult.transcript,
    npmResult.transcript,
    checkovResult.transcript,
  ].filter((t): t is ToolRunTranscript => t !== null);

  // Only count real findings (not scanner-missing meta-findings) for SOC2 and ROI
  const realFindings = allFindings.filter(f => !f.tags?.includes('scanner-missing'));

  // SOC2 mapping (pass scanner statuses for potential coverage)
  const mappings = mapFindingsToControls(realFindings);
  annotateFindingsWithControls(realFindings, mappings);
  const coverage = computeCoverage(mappings, scannerStatuses);

  // ROI (only real findings)
  const roi = calculateROI(realFindings);

  // Actionable counts (excludes meta-findings)
  const countsBySeverity: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  const countsByScanner: Record<ScannerId, number> = {
    gitleaks: 0, npm_audit: 0, checkov: 0,
  };
  for (const f of realFindings) {
    countsBySeverity[f.severity]++;
    countsByScanner[f.scanner]++;
  }

  // All counts (includes scanner-missing meta-findings)
  const countsBySeverityAll: Record<Severity, number> = { ...countsBySeverity };
  for (const f of allFindings) {
    if (f.tags?.includes('scanner-missing')) {
      countsBySeverityAll[f.severity]++;
    }
  }

  const finishedAt = new Date().toISOString();

  // Build manifest
  const manifest = buildManifest(runId, repoPath, scannerStatuses);

  const response: ScanRepoResponse = {
    runId,
    framework: 'soc2',
    repoPath,
    startedAt,
    finishedAt,
    findings: allFindings,
    countsBySeverity,
    countsBySeverityAll,
    countsByScanner,
    controlCoverage: coverage,
    roiEstimate: roi,
    scannerStatuses,
    manifest,
    transcripts,
    evidenceDir,
  };

  // Persist scan result
  const resultPath = resolve(runDir, 'scan_result.json');
  assertCompliancePath(repoPath, resultPath);
  writeFileSync(resultPath, JSON.stringify(response, null, 2), 'utf-8');
  scanResults.set(runId, response);

  auditChain.append('tool_end', 'compliance.scan_repo', {
    runId,
    findingsCount: allFindings.length,
    coveragePct: coverage.coveragePct,
    hoursSaved: roi.hoursSaved,
  });

  return response;
}

async function handleGenerateAuditPacket(args: unknown): Promise<GenerateAuditPacketResponse> {
  const input = GenerateAuditPacketSchema.parse(args);
  const { repoPath, runId: requestedRunId, outputDir } = input;

  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = requestedRunId ?? getLatestRunId(repoPath);
  if (!runId) {
    throw new Error('No scan runs found. Run compliance.scan_repo first.');
  }

  const scanResult = loadScanResult(repoPath, runId);
  if (!scanResult) {
    throw new Error(`Scan result not found for runId: ${runId}`);
  }

  auditChain.append('tool_start', 'compliance.generate_audit_packet', { runId, repoPath });

  const result = generateAuditPacket({
    repoPath,
    scanResult,
    outputDir,
  });

  auditChain.append('tool_end', 'compliance.generate_audit_packet', {
    runId,
    auditPacketPath: result.auditPacketPath,
    filesCount: result.files.length,
  });

  return result;
}

async function handlePlanRemediation(args: unknown): Promise<PlanRemediationResponse> {
  const input = PlanRemediationSchema.parse(args);
  const { repoPath, runId: requestedRunId, maxItems } = input;

  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = requestedRunId ?? getLatestRunId(repoPath);
  if (!runId) {
    throw new Error('No scan runs found. Run compliance.scan_repo first.');
  }

  const scanResult = loadScanResult(repoPath, runId);
  if (!scanResult) {
    throw new Error(`Scan result not found for runId: ${runId}`);
  }

  auditChain.append('tool_start', 'compliance.plan_remediation', { runId, repoPath });

  // Sort findings by severity, then generate remediation steps
  const sorted = [...scanResult.findings]
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .slice(0, maxItems);

  const steps: RemediationStep[] = sorted.map((finding, idx) => ({
    id: `REM-${idx + 1}`,
    priority: idx + 1,
    title: finding.title,
    description: finding.remediation ?? `Address: ${finding.description ?? finding.title}`,
    severity: finding.severity,
    files: finding.file ? [finding.file] : undefined,
    soc2Controls: finding.soc2?.controls,
    estimatedMinutes: EFFORT_MINUTES[finding.severity],
  }));

  const totalEstimatedHours = steps.reduce(
    (sum, s) => sum + (s.estimatedMinutes ?? 0), 0
  ) / 60;

  // Persist plan
  const runDir = resolve(repoPath, '.compliance', 'runs', runId);
  const planJsonPath = resolve(runDir, 'remediation_plan.json');
  const planMdPath = resolve(runDir, 'remediation_plan.md');

  assertCompliancePath(repoPath, planJsonPath);
  assertCompliancePath(repoPath, planMdPath);

  const response: PlanRemediationResponse = {
    planJsonPath,
    planMdPath,
    steps,
    totalEstimatedHours: Math.round(totalEstimatedHours * 100) / 100,
  };

  writeFileSync(planJsonPath, JSON.stringify(response, null, 2), 'utf-8');

  // Generate markdown plan
  const mdLines: string[] = [
    '# Remediation Plan',
    '',
    `**Run ID**: ${runId}`,
    `**Generated**: ${new Date().toISOString()}`,
    `**Total Items**: ${steps.length}`,
    `**Estimated Total Effort**: ${response.totalEstimatedHours} hours`,
    '',
    '---',
    '',
  ];

  for (const step of steps) {
    mdLines.push(`## ${step.id}: ${step.title}`);
    mdLines.push('');
    mdLines.push(`- **Priority**: ${step.priority}`);
    mdLines.push(`- **Severity**: ${step.severity.toUpperCase()}`);
    if (step.files?.length) {
      mdLines.push(`- **Files**: ${step.files.join(', ')}`);
    }
    if (step.soc2Controls?.length) {
      mdLines.push(`- **SOC2 Controls**: ${step.soc2Controls.join(', ')}`);
    }
    mdLines.push(`- **Estimated Effort**: ${step.estimatedMinutes} minutes`);
    mdLines.push('');
    mdLines.push(step.description);
    mdLines.push('');
    mdLines.push('---');
    mdLines.push('');
  }

  writeFileSync(planMdPath, mdLines.join('\n'), 'utf-8');

  auditChain.append('tool_end', 'compliance.plan_remediation', {
    runId,
    stepsCount: steps.length,
    totalEstimatedHours: response.totalEstimatedHours,
  });

  return response;
}

// ── Ticket Handlers ──────────────────────────────────────────────

async function handleCreateTicketsTool(args: unknown): Promise<CreateTicketsResponse> {
  const input = CreateTicketsSchema.parse(args);
  const { repoPath, runId: requestedRunId, maxItems, target, targetRepo, dryRun, approvedPlanId, reopenClosed, labelPolicy } = input;

  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = requestedRunId ?? getLatestRunId(repoPath);
  if (!runId) {
    throw new Error('No scan runs found. Run compliance.scan_repo first.');
  }

  const scanResult = loadScanResult(repoPath, runId);
  if (!scanResult) {
    throw new Error(`Scan result not found for runId: ${runId}`);
  }

  auditChain.append('tool_start', 'compliance.create_tickets', {
    runId, repoPath, target, targetRepo: targetRepo ?? null, dryRun, approvedPlanId: approvedPlanId ?? null,
  });

  const result = await handleCreateTickets(
    repoPath, scanResult, runId, maxItems, target, dryRun, approvedPlanId, targetRepo, reopenClosed, labelPolicy,
  );

  auditChain.append('tool_end', 'compliance.create_tickets', {
    runId,
    planId: result.planId,
    dryRun: result.dryRun,
    wouldCreate: result.summary.wouldCreate,
    duplicates: result.summary.duplicates,
    created: result.summary.created,
  });

  return result;
}

async function handleApproveTicketPlanTool(args: unknown): Promise<ApproveTicketPlanResponse> {
  const input = ApproveTicketPlanSchema.parse(args);
  const { repoPath, planId, approvedBy, reason } = input;

  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  auditChain.append('approval_requested', 'compliance.approve_ticket_plan', {
    planId, approvedBy,
  });

  const result = handleApproveTicketPlan(repoPath, planId, approvedBy, reason);

  auditChain.append('approval_granted', 'compliance.approve_ticket_plan', {
    planId, approvedBy, approvalPath: result.approvalPath,
  });

  return result;
}

// ── MCP Server ───────────────────────────────────────────────────

export function createComplianceServer() {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const risk = getToolRisk(name);

    console.error(`[${name}] risk=${risk}`);

    try {
      let result: unknown;

      switch (name) {
        case 'compliance.scan_repo':
          result = await handleScanRepo(args);
          break;
        case 'compliance.generate_audit_packet':
          result = await handleGenerateAuditPacket(args);
          break;
        case 'compliance.plan_remediation':
          result = await handlePlanRemediation(args);
          break;
        case 'compliance.create_tickets':
          result = await handleCreateTicketsTool(args);
          break;
        case 'compliance.approve_ticket_plan':
          result = await handleApproveTicketPlanTool(args);
          break;
        default:
          throw new Error(`Unknown tool: ${name}`);
      }

      // Return structured response
      const text = typeof result === 'string'
        ? result
        : JSON.stringify(result, null, 2);

      return { content: [{ type: 'text', text }] };

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[${name}] Error: ${message}`);

      auditChain.append('tool_end', name, { error: message });

      return {
        content: [{ type: 'text', text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ── Main Entry ───────────────────────────────────────────────────

async function main() {
  const server = createComplianceServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`${SERVER_NAME} v${SERVER_VERSION} running on stdio`);
}

import { fileURLToPath } from 'node:url';
const __currentFile = fileURLToPath(import.meta.url);
const __entryFile = process.argv[1] ? resolve(process.argv[1]) : '';

if (__currentFile === __entryFile) {
  main().catch((err) => {
    console.error('Server failed to start:', err);
    process.exit(1);
  });
}
