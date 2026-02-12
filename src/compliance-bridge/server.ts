/**
 * Compliance Navigator - MCP Server
 *
 * Standalone MCP server with 9 tools + MCP resource handlers:
 *   1. compliance.scan_repo              - Run gitleaks + npm audit + checkov, normalize, map SOC2, compute ROI
 *   2. compliance.generate_audit_packet  - Write structured audit-support directory
 *   3. compliance.plan_remediation       - Prioritized remediation plan
 *   4. compliance.create_tickets         - Create GitHub Issues or Jira tickets from findings
 *   5. compliance.approve_ticket_plan    - Approve a ticket creation plan
 *   6. compliance.verify_audit_chain     - Verify hash chain integrity of audit log
 *   7. compliance.open_dashboard         - Open interactive compliance dashboard (returns resource URI)
 *   8. compliance.create_demo_fixture    - Generate a demo repo with intentional findings for all 3 scanners
 *   9. compliance.export_audit_packet    - ZIP export of audit packet with SHA-256 integrity hash
 *
 * Resources:
 *   - compliance://dashboard              - Interactive HTML dashboard (MCP App)
 *
 * Transport: StdioServerTransport (JSON-RPC over stdin/stdout)
 * All diagnostic output goes to stderr.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { platform, homedir } from 'node:os';

import { ScanRepoSchema, GenerateAuditPacketSchema, PlanRemediationSchema, CreateTicketsSchema, ApproveTicketPlanSchema, VerifyAuditChainSchema, OpenDashboardSchema, CreateDemoFixtureSchema, ExportAuditPacketSchema } from './schemas.js';
import { generateDashboardHtml } from './dashboard.js';
import { createDemoFixture, type CreateDemoFixtureResponse } from './demo-fixture.js';
import { exportAuditPacket, type ExportAuditPacketResponse } from './zip-export.js';
import { getToolRisk } from './policy.js';
import { assertAllowedCommand, COMPLIANCE_COMMAND_ALLOWLIST } from '../shared/command-allowlist.js';
import { assertCompliancePath, validateRepoPath } from '../shared/path-policy.js';
import { AuditChain, type VerifyResult } from '../shared/audit-chain.js';
import { normalizeGitleaks } from './normalizers/gitleaks.js';
import { normalizeNpmAudit } from './normalizers/npm-audit.js';
import { normalizeCheckov } from './normalizers/checkov.js';
import { mapFindingsToControls, computeCoverage, annotateFindingsWithControls } from './soc2-map.js';
import { mapFindingsToHIPAAControls, computeHIPAACoverage, annotateFindingsWithHIPAAControls } from './hipaa-map.js';
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
  Framework,
  ToolRunTranscript,
  ScannerStatus,
  CoverageResult,
  HIPAACoverageResult,
  AuditManifest,
  CreateTicketsResponse,
  ApproveTicketPlanResponse,
} from './contracts.js';

// â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const SERVER_NAME = 'compliance-navigator';
const SERVER_VERSION = '0.9.0';
const isWindows = platform() === 'win32';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Effort estimates in minutes per finding severity.
// These are rough defaults for prioritization, NOT validated measurements.
// Adjust for your team's actual remediation times.
const EFFORT_MINUTES: Record<Severity, number> = {
  critical: 120,
  high: 60,
  medium: 30,
  low: 15,
  info: 5,
};

// â”€â”€ Audit Chain â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const auditChain = new AuditChain(
  resolve(process.cwd(), 'logs', 'compliance-audit-chain.jsonl')
);

// â”€â”€ Scanner Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// ── Windows Shell Safety ────────────────────────────────────────

/** cmd.exe metacharacters that must be hard-rejected when shell:true is unavoidable. */
const CMD_METACHARS = /[&|<>^%!\x00-\x1f]/;

/**
 * Hard-reject cmd.exe metacharacters in arguments.
 * Called BEFORE spawn when shell:true is required (e.g. npm.cmd).
 * Quoting alone is insufficient for cmd.exe safety.
 */
function assertNoCmdMetachars(values: string[]): void {
  for (const val of values) {
    if (CMD_METACHARS.test(val)) {
      throw new Error(
        `Argument contains cmd.exe metacharacters (unsafe with shell:true): ${val.slice(0, 60)}`
      );
    }
  }
}

/**
 * Wrap a single argument in double quotes for cmd.exe.
 * Applied as a second layer of defense alongside metachar rejection.
 */
function sanitizeForCmd(arg: string): string {
  const escaped = arg.replace(/"/g, '""');
  return `"${escaped}"`;
}

// ── Robust Checkov Resolution (Windows) ─────────────────────────

let _resolvedCheckovCmd: string | null = null;

/**
 * On Windows, resolve the best checkov command:
 *   prefer checkov.exe → checkov.cmd → checkov (bare).
 * Uses `where` (Windows built-in) to probe. Caches result.
 * On non-Windows, always returns 'checkov'.
 */
function resolveCheckovCmd(): string {
  if (!isWindows) return 'checkov';
  if (_resolvedCheckovCmd !== null) return _resolvedCheckovCmd;

  for (const candidate of ['checkov.exe', 'checkov.cmd', 'checkov']) {
    try {
      const result = spawnSync('where', [candidate], {
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: augmentedEnv,
      });
      if (result.status === 0 && result.stdout.toString().trim()) {
        _resolvedCheckovCmd = candidate;
        return candidate;
      }
    } catch { /* continue to next candidate */ }
  }

  // Fallback: let isScannerMissing() handle ENOENT
  _resolvedCheckovCmd = 'checkov';
  return 'checkov';
}

// ── Command Execution ───────────────────────────────────────────

function runCommand(command: string, args: string[], cwd: string, timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolve) => {
    const start = Date.now();

    let proc;
    if (isWindows) {
      // .exe binaries can run without cmd.exe shell — strongest safety
      const useShell = !command.endsWith('.exe');
      if (useShell) {
        // Hard-reject metacharacters in all user-influenced values
        assertNoCmdMetachars(args);
        assertNoCmdMetachars([cwd]);
      }
      const sanitizedArgs = useShell ? args.map(sanitizeForCmd) : args;
      proc = spawn(command, sanitizedArgs, {
        cwd,
        shell: useShell,
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsVerbatimArguments: !useShell,
        env: augmentedEnv,
      });
    } else {
      proc = spawn(command, args, {
        cwd,
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    }

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

// â”€â”€ Scanner Result with Status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
  framework: Framework = 'soc2',
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
    framework,
    complianceNavigatorVersion: SERVER_VERSION,
    policy: {
      commandAllowlist,
      shellExecution: isWindows
        ? 'shell: false for .exe (gitleaks, checkov); shell: true + metachar rejection + quoting for .cmd (npm)'
        : 'shell: false (direct exec)',
      pathPolicy: 'All writes pinned to <repo>/.compliance/ -- directory escape blocked',
    },
    excludedPaths,
  };
}

// â”€â”€ Tool Definitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const tools: Tool[] = [
  {
    name: 'compliance.scan_repo',
    description: 'Scan a repository for security findings using gitleaks (secrets), npm audit (dependencies), and checkov (IaC). Maps findings to SOC2 or HIPAA controls and estimates ROI.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository to scan' },
        framework: { type: 'string', enum: ['soc2', 'hipaa'], default: 'soc2', description: 'Compliance framework (soc2 or hipaa)' },
        mode: { type: 'string', enum: ['report-only', 'generate-remediation'], default: 'report-only' },
        maxMinutes: { type: 'number', default: 10, description: 'Max scan duration in minutes' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.generate_audit_packet',
    description: 'Generate a structured audit-support packet directory with index.md, findings.json, coverage.json, roi.json, and raw scanner output.',
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
    description: 'Create GitHub Issues or Jira tickets from scan findings. Always generates a preview plan first (dryRun=true). To execute, approve the plan first with compliance.approve_ticket_plan, then call again with approvedPlanId and dryRun=false. For Jira: set target="jira" and provide targetRepo="PROJECT_KEY" (or set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY env vars).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
        maxItems: { type: 'number', default: 10, description: 'Maximum tickets to create (default 10)' },
        target: { type: 'string', enum: ['github', 'jira'], default: 'github', description: 'Ticket system target' },
        targetRepo: { type: 'string', description: 'For GitHub: owner/name override (e.g. "acme/api"). For Jira: project key (e.g. "SEC"). If omitted, derived from git remote (GitHub) or JIRA_PROJECT_KEY env (Jira).' },
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
  {
    name: 'compliance.verify_audit_chain',
    description: 'Verify integrity of the hash-chained audit log. Recomputes every SHA-256 hash from entry 1 and checks each link. Returns PASS/FAIL with the first broken line number if tampered.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        logPath: { type: 'string', description: 'Path to audit chain JSONL file (defaults to the server\'s active log)' },
      },
      required: [],
    },
  },
  {
    name: 'compliance.open_dashboard',
    description: 'Open the Compliance Navigator dashboard. Returns a resource URI that MCP clients can render as HTML. The dashboard provides workflow controls for all compliance tools.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
      },
      required: ['repoPath'],
    },
  },
  {
    name: 'compliance.create_demo_fixture',
    description: 'Create a demo repository with intentional compliance findings for all 3 scanners (gitleaks, npm audit, checkov). Use this to test the full workflow end-to-end without touching real code. All secrets are fake test values. All IaC configs are marked DO-NOT-DEPLOY.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        outputDir: { type: 'string', description: 'Directory to create the demo repo in (defaults to ./compliance-demo-repo)' },
        preset: { type: 'string', enum: ['soc2-demo', 'hipaa-demo'], default: 'soc2-demo', description: 'Fixture preset (soc2-demo or hipaa-demo)' },
      },
      required: [],
    },
  },
  {
    name: 'compliance.export_audit_packet',
    description: 'Export an audit packet as a portable ZIP archive with SHA-256 integrity hash. Bundles the audit_packet/ directory (and optionally raw scanner evidence) into a single file suitable for sharing, CI artifacts, or archive. Writes to .compliance/exports/<runId>/audit_packet.zip.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        repoPath: { type: 'string', description: 'Absolute path to the repository' },
        runId: { type: 'string', description: 'Run ID from a previous scan (defaults to most recent)' },
        format: { type: 'string', enum: ['zip'], default: 'zip', description: 'Export format' },
        includeEvidence: { type: 'boolean', default: true, description: 'Include raw scanner output in the ZIP (default true)' },
      },
      required: ['repoPath'],
    },
  },
];

// â”€â”€ Scan Result Storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Scanner Runners â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
  const cmd = resolveCheckovCmd();
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

// â”€â”€ Tool Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

  // Only count real findings (not scanner-missing meta-findings) for mapping and ROI
  const realFindings = allFindings.filter(f => !f.tags?.includes('scanner-missing'));

  // Framework-specific control mapping
  let coverage: CoverageResult;
  let hipaaCoverageDetail: HIPAACoverageResult | undefined;

  if (input.framework === 'hipaa') {
    const mappings = mapFindingsToHIPAAControls(realFindings);
    annotateFindingsWithHIPAAControls(realFindings, mappings);
    hipaaCoverageDetail = computeHIPAACoverage(mappings, scannerStatuses);
    coverage = hipaaCoverageDetail.technical; // headline metric is technical-only
  } else {
    const mappings = mapFindingsToControls(realFindings);
    annotateFindingsWithControls(realFindings, mappings);
    coverage = computeCoverage(mappings, scannerStatuses);
  }

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
  const manifest = buildManifest(runId, repoPath, scannerStatuses, input.framework);

  const response: ScanRepoResponse = {
    runId,
    framework: input.framework,
    repoPath,
    startedAt,
    finishedAt,
    findings: allFindings,
    countsBySeverity,
    countsBySeverityAll,
    countsByScanner,
    controlCoverage: coverage,
    hipaaCoverageDetail,
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

  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
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

  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
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
    hipaaControls: finding.hipaa?.controls,
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
    if (step.hipaaControls?.length) {
      mdLines.push(`- **HIPAA Controls**: ${step.hipaaControls.join(', ')}`);
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

// â”€â”€ Ticket Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function handleCreateTicketsTool(args: unknown): Promise<CreateTicketsResponse> {
  const input = CreateTicketsSchema.parse(args);
  const { repoPath, runId: requestedRunId, maxItems, target, targetRepo, dryRun, approvedPlanId, reopenClosed, labelPolicy } = input;

  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
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

  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
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

// â”€â”€ Verify Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function handleVerifyAuditChain(args: unknown): VerifyResult {
  const input = VerifyAuditChainSchema.parse(args);

  // If a custom logPath is provided, verify that chain instead
  if (input.logPath) {
    const customChain = new AuditChain(resolve(input.logPath));
    return customChain.verify();
  }

  // Default: verify the server's active audit chain
  return auditChain.verify();
}

// â”€â”€ Demo Fixture Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function handleCreateDemoFixture(args: unknown): CreateDemoFixtureResponse {
  const input = CreateDemoFixtureSchema.parse(args);

  auditChain.append('tool_start', 'compliance.create_demo_fixture', {
    outputDir: input.outputDir ?? null,
    preset: input.preset ?? 'soc2-demo',
  });

  const result = createDemoFixture({
    outputDir: input.outputDir,
    preset: input.preset,
  });

  auditChain.append('tool_end', 'compliance.create_demo_fixture', {
    outputDir: result.outputDir,
    filesCreated: result.filesCreated.length,
  });

  return result;
}

// â"€â"€ Export Handler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

async function handleExportAuditPacket(args: unknown): Promise<ExportAuditPacketResponse> {
  const input = ExportAuditPacketSchema.parse(args);
  const { repoPath, runId: requestedRunId, includeEvidence } = input;

  // Validate repo path
  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = requestedRunId ?? getLatestRunId(repoPath);
  if (!runId) {
    throw new Error('No scan runs found. Run compliance.scan_repo first.');
  }

  auditChain.append('tool_start', 'compliance.export_audit_packet', {
    runId, repoPath, includeEvidence,
  });

  const result = await exportAuditPacket(repoPath, runId, includeEvidence);

  auditChain.append('file_written', 'compliance.export_audit_packet', {
    runId,
    zipPath: result.zipPath,
    bytes: result.bytes,
    sha256: result.sha256,
  });

  auditChain.append('tool_end', 'compliance.export_audit_packet', {
    runId,
    zipPath: result.zipPath,
    bytes: result.bytes,
    sha256: result.sha256,
  });

  return result;
}

// â"€â"€ Dashboard Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

interface OpenDashboardResponse {
  resourceUri: string;
  repoPath: string;
  runId: string | null;
  message: string;
}

function handleOpenDashboard(args: unknown): OpenDashboardResponse {
  const input = OpenDashboardSchema.parse(args);
  const { repoPath, runId: requestedRunId } = input;

  const pathCheck = validateRepoPath(repoPath);
  if (!pathCheck.valid) {
    throw new Error(`Invalid repository path: ${pathCheck.reason}`);
  }
  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  const runId = requestedRunId ?? getLatestRunId(repoPath) ?? null;
  const params = new URLSearchParams({ repoPath });
  if (runId) params.set('runId', runId);

  const resourceUri = `compliance://dashboard?${params.toString()}`;

  return {
    resourceUri,
    repoPath,
    runId,
    message: `Dashboard ready. Render via resources/read with URI: ${resourceUri}`,
  };
}

// â”€â”€ MCP Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export function createComplianceServer() {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  // â”€â”€ Resource Handlers (MCP App Dashboard) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      {
        uri: 'compliance://dashboard',
        name: 'Compliance Navigator Dashboard',
        description: 'Interactive HTML dashboard for the compliance workflow. Pass repoPath and optional runId as query parameters.',
        mimeType: 'text/html',
      },
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;

    // Strict URI match: must be exactly "compliance://dashboard" or "compliance://dashboard?..."
    if (uri !== 'compliance://dashboard' && !uri.startsWith('compliance://dashboard?')) {
      throw new Error(`Unknown resource URI: ${uri}`);
    }

    // Parse query params from URI
    const questionMark = uri.indexOf('?');
    const params = questionMark >= 0
      ? new URLSearchParams(uri.slice(questionMark + 1))
      : new URLSearchParams();

    const repoPath = params.get('repoPath') ?? process.cwd();

    // Validate repoPath â€” same checks as tool handlers
    const pathCheck = validateRepoPath(repoPath);
    if (!pathCheck.valid) {
      throw new Error(`Invalid repoPath in resource URI: ${pathCheck.reason}`);
    }

    // Validate runId from URI query params (defense-in-depth against path traversal)
    const rawRunId = params.get('runId');
    const SAFE_RUNID_RE = /^[a-zA-Z0-9._-]+$/;
    const runId = rawRunId
      ? (SAFE_RUNID_RE.test(rawRunId) ? rawRunId : undefined)
      : getLatestRunId(repoPath) ?? undefined;

    // Extract framework from scan result if available
    let framework: 'soc2' | 'hipaa' = 'soc2';
    if (runId) {
      const scanResult = loadScanResult(repoPath, runId);
      if (scanResult?.manifest?.framework === 'hipaa') {
        framework = 'hipaa';
      }
    }

    const html = generateDashboardHtml({
      repoPath,
      runId,
      hasGhToken: !!process.env.GH_TOKEN,
      hasJiraConfig: !!(process.env.JIRA_BASE_URL && process.env.JIRA_API_TOKEN),
      serverVersion: SERVER_VERSION,
      framework,
    });

    return {
      contents: [
        {
          uri,
          mimeType: 'text/html',
          text: html,
        },
      ],
    };
  });

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
        case 'compliance.verify_audit_chain':
          result = handleVerifyAuditChain(args);
          break;
        case 'compliance.open_dashboard':
          result = handleOpenDashboard(args);
          break;
        case 'compliance.create_demo_fixture':
          result = handleCreateDemoFixture(args);
          break;
        case 'compliance.export_audit_packet':
          result = await handleExportAuditPacket(args);
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

// â”€â”€ Main Entry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
