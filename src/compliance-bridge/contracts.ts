/**
 * Compliance Navigator - Type Contracts
 *
 * All TypeScript types for the compliance-bridge MCP server.
 * Zero runtime dependencies -- pure type definitions.
 */

// ── Enums & Literals ─────────────────────────────────────────────

export type Framework = 'soc2';

export type Mode = 'report-only' | 'generate-remediation';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScannerId = 'gitleaks' | 'npm_audit' | 'checkov';

export type RiskTier = 'low' | 'medium' | 'high';

// ── Findings ─────────────────────────────────────────────────────

export interface NormalizedFinding {
  id: string;                     // stable hash (first 16 chars of sha256)
  scanner: ScannerId;
  severity: Severity;
  title: string;
  description?: string;
  file?: string;
  line?: number;
  evidence: {
    kind: 'command_output' | 'file_snippet' | 'scanner_native';
    ref: string;                  // path to evidence artifact or embedded pointer
  };
  remediation?: string;
  tags?: string[];
  soc2?: {
    controls: string[];           // e.g. ["CC6.1", "CC6.6"]
    rationale: string;
    confidence: number;           // 0..1
  };
}

// ── Scanner Transcripts ──────────────────────────────────────────

export interface ToolRunTranscript {
  tool: ScannerId;
  command: string;
  cwd: string;
  startedAt: string;
  finishedAt: string;
  exitCode: number;
  durationMs: number;
  stdoutPath: string;
  stderrPath: string;
}

// ── SOC2 Mapping ─────────────────────────────────────────────────

export interface SOC2Control {
  id: string;                     // e.g. "CC6.1"
  name: string;                   // e.g. "Logical Access Controls"
  description: string;
  scannerMappings: Array<{
    scanner: ScannerId;
    rulePatterns?: RegExp[];      // optional fine-grained matching
    /** Heuristic relevance score (0..1). NOT empirically validated. See soc2-map.ts for methodology. */
    confidence: number;
  }>;
}

export interface SOC2Mapping {
  controlId: string;
  controlName: string;
  findings: NormalizedFinding[];
  confidence: number;
}

// ── Coverage ─────────────────────────────────────────────────────
//
// IMPORTANT: "Coverage" here means "scanner reach" -- the percentage of SOC2
// controls that at least one scanner produced findings for. It does NOT mean
// compliance status. A control marked "covered" means a scanner reported
// findings relevant to it, not that the control passes an audit.

export interface CoverageResult {
  coveredControls: string[];
  missingControls: string[];
  /** Scanner reach: controls where at least one finding was detected (NOT compliance status) */
  coveragePct: number;            // 0..100
  /** Potential reach: controls addressable by installed scanners (even with 0 findings) */
  coveragePctPotential: number;   // 0..100
  /** Full reach: controls addressable when all 3 scanners are installed */
  coveragePctFull: number;        // 0..100
  coveredControlsPotential: string[];
  controlDetails: Array<{
    controlId: string;
    controlName: string;
    /** 'covered' = scanner produced findings for this control (not compliance status) */
    status: 'covered' | 'gap';
    findingCount: number;
  }>;
}

// ── Scanner Status ────────────────────────────────────────────────

export type ScannerStatusCode = 'ok' | 'missing' | 'error' | 'skipped';

export interface ScannerStatus {
  scanner: ScannerId;
  status: ScannerStatusCode;
  version?: string;
  message?: string;
}

// ── Manifest ─────────────────────────────────────────────────────

export interface AuditManifest {
  generatedAt: string;
  runId: string;
  repoPath: string;
  repoCommitHash?: string;
  os: string;
  nodeVersion: string;
  scannerVersions: Record<ScannerId, string | null>;
  framework: Framework;
  complianceNavigatorVersion: string;
  /** Security execution policy -- makes audit packet self-contained */
  policy: {
    commandAllowlist: string[];
    shellExecution: string;
    pathPolicy: string;
  };
  /** Paths excluded from scanning (from .gitleaks.toml, etc.) */
  excludedPaths: string[];
}

// ── ROI ──────────────────────────────────────────────────────────
//
// ROI estimates use configurable defaults, NOT validated measurements.
// See roi.ts for full methodology documentation and real-world ranges.

export interface ROIResult {
  hoursSaved: number;
  hoursSavedConservative: number;
  hoursSavedLikely: number;
  /** Always contains a disclaimer about the estimation basis */
  basis: string;
  breakdown: Record<ScannerId, {
    count: number;
    hoursPerFinding: number;
    totalHours: number;
  }>;
}

// ── Tool Requests ────────────────────────────────────────────────

export interface ScanRepoRequest {
  framework: Framework;
  repoPath: string;
  mode?: Mode;
  includePaths?: string[];
  excludePaths?: string[];
  maxMinutes?: number;            // default 10
}

export interface GenerateAuditPacketRequest {
  repoPath: string;
  runId?: string;                 // if omitted, uses most recent run
  outputDir?: string;
}

export interface PlanRemediationRequest {
  repoPath: string;
  runId?: string;
  mode?: Mode;
  maxItems?: number;              // default 20
}

// ── Tool Responses ───────────────────────────────────────────────

export interface ScanRepoResponse {
  runId: string;
  framework: Framework;
  repoPath: string;
  startedAt: string;
  finishedAt: string;

  findings: NormalizedFinding[];
  /** Counts excluding scanner-missing meta-findings (actionable items only) */
  countsBySeverity: Record<Severity, number>;
  /** Counts including scanner-missing meta-findings (full picture) */
  countsBySeverityAll: Record<Severity, number>;
  countsByScanner: Record<ScannerId, number>;

  controlCoverage: CoverageResult;

  roiEstimate: ROIResult;

  scannerStatuses: ScannerStatus[];
  manifest: AuditManifest;

  transcripts: ToolRunTranscript[];
  evidenceDir: string;
}

export interface GenerateAuditPacketResponse {
  auditPacketPath: string;
  indexPath: string;
  findingsJsonPath: string;
  evidencePath: string;
  generatedAt: string;
  files: string[];
}

export interface RemediationStep {
  id: string;
  priority: number;
  title: string;
  description: string;
  severity: Severity;
  files?: string[];
  commands?: string[];            // recommended commands (not auto-run)
  soc2Controls?: string[];
  estimatedMinutes?: number;
}

export interface PlanRemediationResponse {
  planJsonPath?: string;
  planMdPath?: string;
  steps: RemediationStep[];
  totalEstimatedHours: number;
}

// ── Ticket Creation ──────────────────────────────────────────────

export type TicketTarget = 'github' | 'jira';

export type LabelPolicy = 'require-existing' | 'create-if-missing';

export interface TicketPlanItem {
  findingId: string;
  title: string;
  body: string;
  labels: string[];
  dedupeQuery: string;
}

export interface CreateTicketsRequest {
  repoPath: string;
  runId?: string;
  maxItems?: number;
  target?: TicketTarget;
  targetRepo?: string;
  dryRun?: boolean;
  approvedPlanId?: string;
  reopenClosed?: boolean;
  labelPolicy?: LabelPolicy;
}

export interface CreateTicketsResponse {
  target: TicketTarget;
  repo: { owner: string; name: string };
  runId: string;

  dryRun: boolean;
  planId: string;

  wouldCreate: TicketPlanItem[];
  skippedAsDuplicate: { findingId: string; existingUrl: string }[];
  reopened?: { findingId: string; url: string; number: number }[];

  created?: { findingId: string; url: string; number: number }[];
  summary: {
    requested: number;
    wouldCreate: number;
    duplicates: number;
    reopened: number;
    created: number;
  };
}

export interface ApproveTicketPlanRequest {
  repoPath: string;
  planId: string;
  approvedBy: string;
  reason?: string;
}

export interface ApproveTicketPlanResponse {
  planId: string;
  approvedAt: string;
  approvalPath: string;
}

// ── Audit Events ─────────────────────────────────────────────────

export interface AuditEvent {
  ts: string;
  kind: 'tool_start' | 'tool_end' | 'approval_requested' | 'approval_granted' | 'command_run' | 'file_written';
  tool?: string;
  data: Record<string, unknown>;
  prevHash: string;
  hash: string;
}
