/**
 * Ticket Writer - GitHub Issues Integration
 *
 * Creates GitHub Issues from compliance scan findings with:
 *   - Deterministic deduplication (CN-FINDING-ID markers)
 *   - Approval gate (file-based, tamper-evident)
 *   - Enterprise-grade ticket formatting
 *
 * Uses Node fetch (no shell) to keep the command allowlist small.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertCompliancePath } from '../shared/path-policy.js';
import type {
  NormalizedFinding,
  ScanRepoResponse,
  TicketPlanItem,
  CreateTicketsResponse,
  ApproveTicketPlanResponse,
  TicketTarget,
  Severity,
} from './contracts.js';

// ── Constants ────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const MARKER_PREFIX = 'CN-FINDING-ID';
const RUN_MARKER_PREFIX = 'CN-RUN-ID';

// ── Git Remote Parsing ───────────────────────────────────────────

export interface RepoIdentity {
  owner: string;
  name: string;
}

/**
 * Resolve owner/repo from .git/config remote "origin" URL.
 * Walks up from repoPath to find the nearest .git/config.
 * Supports HTTPS, SSH, and git:// URLs.
 */
export function resolveRepoIdentity(repoPath: string): RepoIdentity {
  // Walk up to find .git/config (handles subdirectories within a repo)
  let searchPath = resolve(repoPath);
  let configPath: string | undefined;
  for (let i = 0; i < 10; i++) {
    const candidate = resolve(searchPath, '.git', 'config');
    if (existsSync(candidate)) {
      configPath = candidate;
      break;
    }
    const parent = resolve(searchPath, '..');
    if (parent === searchPath) break; // reached filesystem root
    searchPath = parent;
  }

  if (!configPath) {
    throw new Error(`No .git/config found at or above ${repoPath}. Is this inside a git repository?`);
  }

  const config = readFileSync(configPath, 'utf-8');

  // Parse remote "origin" URL
  const remoteMatch = config.match(
    /\[remote\s+"origin"\]\s*\n(?:\s+\w+\s*=\s*[^\n]*\n)*?\s*url\s*=\s*(.+)/
  );
  if (!remoteMatch) {
    throw new Error('No remote "origin" found in .git/config');
  }

  const url = remoteMatch[1].trim();
  return parseGitUrl(url);
}

/**
 * Parse a git URL into owner/name.
 * Handles: https://github.com/owner/repo.git
 *          git@github.com:owner/repo.git
 *          git://github.com/owner/repo.git
 */
export function parseGitUrl(url: string): RepoIdentity {
  // SSH: git@github.com:owner/repo.git
  const sshMatch = url.match(/git@[^:]+:([^/]+)\/([^/.]+?)(?:\.git)?$/);
  if (sshMatch) {
    return { owner: sshMatch[1], name: sshMatch[2] };
  }

  // HTTPS/git: https://github.com/owner/repo.git
  const httpsMatch = url.match(/(?:https?|git):\/\/[^/]+\/([^/]+)\/([^/.]+?)(?:\.git)?$/);
  if (httpsMatch) {
    return { owner: httpsMatch[1], name: httpsMatch[2] };
  }

  throw new Error(`Cannot parse git remote URL: ${url}`);
}

// ── GitHub API Client ────────────────────────────────────────────

function getGitHubToken(): string {
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error(
      'GitHub token not found. Set GH_TOKEN or GITHUB_TOKEN environment variable.'
    );
  }
  return token;
}

function githubHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'compliance-navigator/0.1.0',
  };
}

/**
 * Search GitHub Issues for a deduplication marker.
 * Returns the matching issue URL if found, undefined otherwise.
 */
async function searchForDuplicate(
  owner: string,
  name: string,
  findingId: string,
  token: string,
): Promise<string | undefined> {
  const query = encodeURIComponent(`repo:${owner}/${name} "${MARKER_PREFIX}: ${findingId}" is:issue`);
  const url = `https://api.github.com/search/issues?q=${query}&per_page=1`;

  const res = await fetch(url, { headers: githubHeaders(token) });
  if (!res.ok) {
    console.error(`[ticket-writer] GitHub search failed: ${res.status} ${res.statusText}`);
    return undefined;
  }

  const data = (await res.json()) as { total_count: number; items: Array<{ html_url: string }> };
  if (data.total_count > 0 && data.items[0]) {
    return data.items[0].html_url;
  }
  return undefined;
}

/**
 * Ensure a label exists in the repository. Creates it if missing.
 */
async function ensureLabel(
  owner: string,
  name: string,
  label: string,
  color: string,
  token: string,
): Promise<void> {
  const url = `https://api.github.com/repos/${owner}/${name}/labels`;
  const res = await fetch(url, {
    method: 'POST',
    headers: githubHeaders(token),
    body: JSON.stringify({ name: label, color }),
  });
  // 422 = already exists (fine), anything else non-2xx is a warning
  if (!res.ok && res.status !== 422) {
    console.error(`[ticket-writer] Label create warning for "${label}": ${res.status}`);
  }
}

/**
 * Create a GitHub Issue.
 */
async function createGitHubIssue(
  owner: string,
  name: string,
  title: string,
  body: string,
  labels: string[],
  token: string,
): Promise<{ url: string; number: number }> {
  const url = `https://api.github.com/repos/${owner}/${name}/issues`;
  const res = await fetch(url, {
    method: 'POST',
    headers: githubHeaders(token),
    body: JSON.stringify({ title, body, labels }),
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`GitHub issue creation failed: ${res.status} ${errBody}`);
  }

  const data = (await res.json()) as { html_url: string; number: number };
  return { url: data.html_url, number: data.number };
}

// ── Label Definitions ────────────────────────────────────────────

const LABEL_COLORS: Record<string, string> = {
  'severity:critical': 'b60205',
  'severity:high': 'd93f0b',
  'severity:medium': 'fbca04',
  'severity:low': '0e8a16',
  'severity:info': 'c5def5',
  'scanner:gitleaks': '5319e7',
  'scanner:npm_audit': '0052cc',
  'scanner:checkov': '006b75',
  'compliance-navigator': '1d76db',
};

function getLabelColor(label: string): string {
  if (LABEL_COLORS[label]) return LABEL_COLORS[label];
  if (label.startsWith('soc2:')) return 'e4e669';
  return 'd4c5f9';
}

// ── Ticket Formatting ────────────────────────────────────────────

function formatTicketTitle(finding: NormalizedFinding): string {
  const framework = finding.soc2 ? 'SOC2' : 'SEC';
  const severity = finding.severity.toUpperCase();
  const scanner = finding.scanner;
  return `[${framework}][${severity}][${scanner}] ${finding.title}`;
}

function formatTicketBody(finding: NormalizedFinding, runId: string): string {
  const lines: string[] = [];

  // Summary
  lines.push('## Finding Summary');
  lines.push('');
  lines.push(`**Severity**: ${finding.severity.toUpperCase()}`);
  lines.push(`**Scanner**: ${finding.scanner}`);
  if (finding.file) {
    lines.push(`**File**: \`${finding.file}\`${finding.line ? `:${finding.line}` : ''}`);
  }
  lines.push('');

  if (finding.description) {
    lines.push(finding.description);
    lines.push('');
  }

  // Evidence
  lines.push('## Evidence');
  lines.push('');
  lines.push(`- **Kind**: ${finding.evidence.kind}`);
  lines.push(`- **Reference**: \`${finding.evidence.ref}\``);
  lines.push('');

  // SOC2 Controls
  if (finding.soc2) {
    lines.push('## SOC2 Controls');
    lines.push('');
    lines.push(`| Control | Confidence |`);
    lines.push(`|---------|------------|`);
    for (const control of finding.soc2.controls) {
      lines.push(`| ${control} | ${(finding.soc2.confidence * 100).toFixed(0)}% |`);
    }
    lines.push('');
    lines.push(`**Rationale**: ${finding.soc2.rationale}`);
    lines.push('');
  }

  // Remediation
  if (finding.remediation) {
    lines.push('## Remediation');
    lines.push('');
    lines.push(finding.remediation);
    lines.push('');
  }

  // Deduplication markers (must be at the bottom)
  lines.push('---');
  lines.push('');
  lines.push(`\`${MARKER_PREFIX}: ${finding.id}\``);
  lines.push(`\`${RUN_MARKER_PREFIX}: ${runId}\``);
  lines.push('');
  lines.push('_Created by [Compliance Navigator](https://github.com/rblake2320/claude-desktop-mcp-bridge)_');

  return lines.join('\n');
}

function buildLabels(finding: NormalizedFinding): string[] {
  const labels: string[] = [
    `severity:${finding.severity}`,
    `scanner:${finding.scanner}`,
    'compliance-navigator',
  ];

  if (finding.soc2) {
    // Use individual control labels (max 3 to avoid label spam)
    const controls = finding.soc2.controls.slice(0, 3);
    for (const control of controls) {
      labels.push(`soc2:${control}`);
    }
  }

  return labels;
}

// ── Plan Management ──────────────────────────────────────────────

function computePlanHash(items: TicketPlanItem[]): string {
  return createHash('sha256').update(JSON.stringify(items)).digest('hex');
}

interface PendingPlan {
  planId: string;
  createdAt: string;
  target: TicketTarget;
  repo: RepoIdentity;
  runId: string;
  planHash: string;
  items: TicketPlanItem[];
}

interface ApprovalRecord {
  planId: string;
  approvedAt: string;
  approvedBy: string;
  reason?: string;
  planHash: string;
}

function getApprovalsDir(repoPath: string): string {
  return resolve(repoPath, '.compliance', 'approvals');
}

function getPendingPath(repoPath: string, planId: string): string {
  return resolve(getApprovalsDir(repoPath), 'pending', `${planId}.json`);
}

function getApprovedPath(repoPath: string, planId: string): string {
  return resolve(getApprovalsDir(repoPath), 'approved', `${planId}.json`);
}

function savePendingPlan(repoPath: string, plan: PendingPlan): string {
  const dir = resolve(getApprovalsDir(repoPath), 'pending');
  mkdirSync(dir, { recursive: true });
  const filePath = getPendingPath(repoPath, plan.planId);
  assertCompliancePath(repoPath, filePath);
  writeFileSync(filePath, JSON.stringify(plan, null, 2), 'utf-8');
  return filePath;
}

function loadPendingPlan(repoPath: string, planId: string): PendingPlan | undefined {
  const filePath = getPendingPath(repoPath, planId);
  if (!existsSync(filePath)) return undefined;
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8')) as PendingPlan;
  } catch {
    return undefined;
  }
}

function loadApproval(repoPath: string, planId: string): ApprovalRecord | undefined {
  const filePath = getApprovedPath(repoPath, planId);
  if (!existsSync(filePath)) return undefined;
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8')) as ApprovalRecord;
  } catch {
    return undefined;
  }
}

// ── Core Logic ───────────────────────────────────────────────────

/**
 * Build ticket plan items from scan findings.
 * Sorted by severity (critical first), limited to maxItems.
 */
function buildPlanItems(
  findings: NormalizedFinding[],
  runId: string,
  maxItems: number,
): TicketPlanItem[] {
  // Filter out scanner-missing meta-findings
  const real = findings.filter(f => !f.tags?.includes('scanner-missing'));

  // Sort by severity
  const sorted = [...real].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return sorted.slice(0, maxItems).map(finding => ({
    findingId: finding.id,
    title: formatTicketTitle(finding),
    body: formatTicketBody(finding, runId),
    labels: buildLabels(finding),
    dedupeQuery: `${MARKER_PREFIX}: ${finding.id}`,
  }));
}

/**
 * Create tickets (dry-run or execute).
 *
 * Dry-run: builds plan, checks deduplication, saves pending plan.
 * Execute: requires approved plan, creates GitHub issues.
 */
export async function handleCreateTickets(
  repoPath: string,
  scanResult: ScanRepoResponse,
  runId: string,
  maxItems: number,
  target: TicketTarget,
  dryRun: boolean,
  approvedPlanId?: string,
): Promise<CreateTicketsResponse> {
  // Resolve repo identity
  const repo = resolveRepoIdentity(repoPath);
  const token = getGitHubToken();

  // Build plan items
  const planItems = buildPlanItems(scanResult.findings, runId, maxItems);
  const planId = approvedPlanId ?? randomUUID().slice(0, 12);

  // Deduplication check
  const wouldCreate: TicketPlanItem[] = [];
  const skippedAsDuplicate: { findingId: string; existingUrl: string }[] = [];

  for (const item of planItems) {
    const existingUrl = await searchForDuplicate(repo.owner, repo.name, item.findingId, token);
    if (existingUrl) {
      skippedAsDuplicate.push({ findingId: item.findingId, existingUrl });
    } else {
      wouldCreate.push(item);
    }
  }

  // If dryRun or no approved plan → save pending and return preview
  if (dryRun || !approvedPlanId) {
    const planHash = computePlanHash(wouldCreate);
    const pendingPlan: PendingPlan = {
      planId,
      createdAt: new Date().toISOString(),
      target,
      repo,
      runId,
      planHash,
      items: wouldCreate,
    };
    savePendingPlan(repoPath, pendingPlan);

    return {
      target,
      repo,
      runId,
      dryRun: true,
      planId,
      wouldCreate,
      skippedAsDuplicate,
      summary: {
        requested: planItems.length,
        wouldCreate: wouldCreate.length,
        duplicates: skippedAsDuplicate.length,
        created: 0,
      },
    };
  }

  // Execute mode: verify approval
  const pendingPlan = loadPendingPlan(repoPath, approvedPlanId);
  if (!pendingPlan) {
    throw new Error(`No pending plan found for planId: ${approvedPlanId}`);
  }

  const approval = loadApproval(repoPath, approvedPlanId);
  if (!approval) {
    throw new Error(
      `Plan ${approvedPlanId} has not been approved. Call compliance.approve_ticket_plan first.`
    );
  }

  // Verify plan hash matches (tamper prevention)
  if (approval.planHash !== pendingPlan.planHash) {
    throw new Error(
      `Plan hash mismatch: approval hash does not match pending plan. The plan may have been tampered with.`
    );
  }

  // Ensure labels exist
  const allLabels = new Set<string>();
  for (const item of pendingPlan.items) {
    for (const label of item.labels) {
      allLabels.add(label);
    }
  }
  for (const label of allLabels) {
    await ensureLabel(repo.owner, repo.name, label, getLabelColor(label), token);
  }

  // Create issues
  const created: { findingId: string; url: string; number: number }[] = [];
  for (const item of pendingPlan.items) {
    try {
      const result = await createGitHubIssue(
        repo.owner, repo.name,
        item.title, item.body, item.labels,
        token,
      );
      created.push({ findingId: item.findingId, url: result.url, number: result.number });
    } catch (err) {
      console.error(`[ticket-writer] Failed to create issue for ${item.findingId}: ${(err as Error).message}`);
    }
  }

  return {
    target,
    repo,
    runId,
    dryRun: false,
    planId: approvedPlanId,
    wouldCreate: pendingPlan.items,
    skippedAsDuplicate,
    created,
    summary: {
      requested: planItems.length,
      wouldCreate: pendingPlan.items.length,
      duplicates: skippedAsDuplicate.length,
      created: created.length,
    },
  };
}

/**
 * Approve a pending ticket plan.
 * Writes approval artifact with matching plan hash.
 */
export function handleApproveTicketPlan(
  repoPath: string,
  planId: string,
  approvedBy: string,
  reason?: string,
): ApproveTicketPlanResponse {
  const pendingPlan = loadPendingPlan(repoPath, planId);
  if (!pendingPlan) {
    throw new Error(`No pending plan found for planId: ${planId}`);
  }

  const approvalRecord: ApprovalRecord = {
    planId,
    approvedAt: new Date().toISOString(),
    approvedBy,
    reason,
    planHash: pendingPlan.planHash,
  };

  const approvedDir = resolve(getApprovalsDir(repoPath), 'approved');
  mkdirSync(approvedDir, { recursive: true });
  const approvalPath = getApprovedPath(repoPath, planId);
  assertCompliancePath(repoPath, approvalPath);
  writeFileSync(approvalPath, JSON.stringify(approvalRecord, null, 2), 'utf-8');

  return {
    planId,
    approvedAt: approvalRecord.approvedAt,
    approvalPath,
  };
}
