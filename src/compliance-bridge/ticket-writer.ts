/**
 * Ticket Writer - GitHub Issues Integration
 *
 * Creates GitHub Issues from compliance scan findings with:
 *   - Deterministic deduplication (CN-FINDING-ID markers)
 *   - Approval gate (file-based, tamper-evident)
 *   - Enterprise-grade ticket formatting
 *   - Rate limiting + backoff for GitHub API
 *   - Label policy (require-existing vs create-if-missing)
 *   - Repo targeting defense (repoFullName in plan hash)
 *   - Reopen-closed dedup handling
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
  LabelPolicy,
  Severity,
} from './contracts.js';

// ── Constants ────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const MARKER_PREFIX = 'CN-FINDING-ID';
const RUN_MARKER_PREFIX = 'CN-RUN-ID';

// Rate limit: max concurrent requests and delay between batches
const MAX_CONCURRENT = 2;
const BATCH_DELAY_MS = 500;
const RATE_LIMIT_BACKOFF_MS = 5000;

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
 * Rate-limit aware fetch wrapper.
 * Checks X-RateLimit-Remaining and backs off on 403/429.
 */
async function githubFetch(
  url: string,
  options: RequestInit & { headers: Record<string, string> },
): Promise<Response> {
  const res = await fetch(url, options);

  // Check for secondary rate limit (403 with retry-after or rate limit message)
  if (res.status === 403 || res.status === 429) {
    const retryAfter = res.headers.get('retry-after');
    const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : RATE_LIMIT_BACKOFF_MS;
    console.error(`[ticket-writer] Rate limited (${res.status}). Backing off ${waitMs}ms.`);
    await sleep(waitMs);
    // Retry once
    return fetch(url, options);
  }

  // Check remaining rate limit and log warning
  const remaining = res.headers.get('x-ratelimit-remaining');
  if (remaining !== null && parseInt(remaining, 10) < 10) {
    console.error(`[ticket-writer] GitHub rate limit low: ${remaining} remaining`);
  }

  return res;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Deduplication Search ─────────────────────────────────────────

interface DedupeResult {
  found: boolean;
  url?: string;
  number?: number;
  state?: 'open' | 'closed';
}

/**
 * Search GitHub Issues for a deduplication marker.
 * Returns match info including state (open/closed) for reopen handling.
 */
async function searchForDuplicate(
  owner: string,
  name: string,
  findingId: string,
  token: string,
): Promise<DedupeResult> {
  const query = encodeURIComponent(
    `repo:${owner}/${name} "${MARKER_PREFIX}: ${findingId}" is:issue`
  );
  const url = `https://api.github.com/search/issues?q=${query}&per_page=1`;

  const res = await githubFetch(url, { headers: githubHeaders(token) });
  if (!res.ok) {
    console.error(`[ticket-writer] GitHub search failed: ${res.status} ${res.statusText}`);
    return { found: false };
  }

  const data = (await res.json()) as {
    total_count: number;
    items: Array<{ html_url: string; number: number; state: string }>;
  };
  if (data.total_count > 0 && data.items[0]) {
    return {
      found: true,
      url: data.items[0].html_url,
      number: data.items[0].number,
      state: data.items[0].state as 'open' | 'closed',
    };
  }
  return { found: false };
}

/**
 * Reopen a closed GitHub issue.
 */
async function reopenIssue(
  owner: string,
  name: string,
  issueNumber: number,
  token: string,
): Promise<void> {
  const url = `https://api.github.com/repos/${owner}/${name}/issues/${issueNumber}`;
  const res = await githubFetch(url, {
    method: 'PATCH',
    headers: githubHeaders(token),
    body: JSON.stringify({ state: 'open' }),
  });
  if (!res.ok) {
    console.error(`[ticket-writer] Failed to reopen issue #${issueNumber}: ${res.status}`);
  }
}

// ── Label Management ─────────────────────────────────────────────

/**
 * Ensure labels exist based on label policy.
 * - 'create-if-missing': creates labels that don't exist
 * - 'require-existing': skips creation, logs warning for missing labels
 */
async function ensureLabels(
  owner: string,
  name: string,
  labels: Set<string>,
  policy: LabelPolicy,
  token: string,
): Promise<void> {
  if (policy === 'require-existing') {
    // Just verify labels exist, warn about missing ones
    const url = `https://api.github.com/repos/${owner}/${name}/labels?per_page=100`;
    const res = await githubFetch(url, { headers: githubHeaders(token) });
    if (res.ok) {
      const existing = (await res.json()) as Array<{ name: string }>;
      const existingNames = new Set(existing.map(l => l.name));
      for (const label of labels) {
        if (!existingNames.has(label)) {
          console.error(
            `[ticket-writer] Label "${label}" does not exist in repo. ` +
            `Use labelPolicy: "create-if-missing" to auto-create, or create it manually.`
          );
        }
      }
    }
    return;
  }

  // create-if-missing: create each label
  for (const label of labels) {
    const color = getLabelColor(label);
    const url = `https://api.github.com/repos/${owner}/${name}/labels`;
    const res = await githubFetch(url, {
      method: 'POST',
      headers: githubHeaders(token),
      body: JSON.stringify({ name: label, color }),
    });
    // 422 = already exists (fine)
    if (!res.ok && res.status !== 422) {
      console.error(`[ticket-writer] Label create warning for "${label}": ${res.status}`);
    }
    await sleep(100); // gentle pacing for label creation
  }
}

/**
 * Create a GitHub Issue with rate limiting.
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
  const res = await githubFetch(url, {
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

/**
 * Compute plan hash including repoFullName for cross-repo tamper prevention.
 * Including the repo in the hash means an approval for repo A
 * cannot be replayed against repo B.
 */
function computePlanHash(items: TicketPlanItem[], repoFullName: string, runId: string): string {
  const payload = { repoFullName, runId, items };
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

interface PendingPlan {
  planId: string;
  createdAt: string;
  target: TicketTarget;
  repo: RepoIdentity;
  repoFullName: string;
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
  repoFullName: string;
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
  targetRepo?: string,
  reopenClosed?: boolean,
  labelPolicy?: LabelPolicy,
): Promise<CreateTicketsResponse> {
  // Resolve repo identity
  let repo: RepoIdentity;
  if (targetRepo) {
    const [owner, name] = targetRepo.split('/');
    repo = { owner, name };
  } else {
    repo = resolveRepoIdentity(repoPath);
  }
  const repoFullName = `${repo.owner}/${repo.name}`;
  const token = getGitHubToken();
  const policy = labelPolicy ?? 'require-existing';

  // Build plan items
  const planItems = buildPlanItems(scanResult.findings, runId, maxItems);
  const planId = approvedPlanId ?? randomUUID().slice(0, 12);

  // Deduplication check with reopen-closed support
  const wouldCreate: TicketPlanItem[] = [];
  const skippedAsDuplicate: { findingId: string; existingUrl: string }[] = [];
  const reopenedItems: { findingId: string; url: string; number: number }[] = [];

  for (const item of planItems) {
    const dup = await searchForDuplicate(repo.owner, repo.name, item.findingId, token);
    if (dup.found && dup.url) {
      if (dup.state === 'closed' && reopenClosed && dup.number) {
        // Mark for reopening (or reopen immediately in execute mode)
        reopenedItems.push({ findingId: item.findingId, url: dup.url, number: dup.number });
      } else {
        skippedAsDuplicate.push({ findingId: item.findingId, existingUrl: dup.url });
      }
    } else {
      wouldCreate.push(item);
    }
    // Gentle pacing for search API
    await sleep(200);
  }

  // If dryRun or no approved plan -> save pending and return preview
  if (dryRun || !approvedPlanId) {
    const planHash = computePlanHash(wouldCreate, repoFullName, runId);
    const pendingPlan: PendingPlan = {
      planId,
      createdAt: new Date().toISOString(),
      target,
      repo,
      repoFullName,
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
      reopened: reopenedItems.length > 0 ? reopenedItems : undefined,
      summary: {
        requested: planItems.length,
        wouldCreate: wouldCreate.length,
        duplicates: skippedAsDuplicate.length,
        reopened: reopenedItems.length,
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

  // Verify repo matches (cross-repo replay prevention)
  if (approval.repoFullName !== pendingPlan.repoFullName) {
    throw new Error(
      `Repo mismatch: approval is for ${approval.repoFullName} but plan targets ${pendingPlan.repoFullName}`
    );
  }

  // Ensure labels exist per policy
  const allLabels = new Set<string>();
  for (const item of pendingPlan.items) {
    for (const label of item.labels) {
      allLabels.add(label);
    }
  }
  await ensureLabels(repo.owner, repo.name, allLabels, policy, token);

  // Reopen closed issues if requested
  for (const item of reopenedItems) {
    await reopenIssue(repo.owner, repo.name, item.number, token);
    await sleep(BATCH_DELAY_MS);
  }

  // Create issues with rate-limited batching
  const created: { findingId: string; url: string; number: number }[] = [];
  for (let i = 0; i < pendingPlan.items.length; i++) {
    const item = pendingPlan.items[i];
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

    // Batch delay every MAX_CONCURRENT issues
    if ((i + 1) % MAX_CONCURRENT === 0 && i < pendingPlan.items.length - 1) {
      await sleep(BATCH_DELAY_MS);
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
    reopened: reopenedItems.length > 0 ? reopenedItems : undefined,
    created,
    summary: {
      requested: planItems.length,
      wouldCreate: pendingPlan.items.length,
      duplicates: skippedAsDuplicate.length,
      reopened: reopenedItems.length,
      created: created.length,
    },
  };
}

/**
 * Approve a pending ticket plan.
 * Writes approval artifact with matching plan hash and repo identity.
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
    repoFullName: pendingPlan.repoFullName,
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
