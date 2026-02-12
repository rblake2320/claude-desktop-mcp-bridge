#!/usr/bin/env node
/**
 * CI Runner for Compliance Navigator
 *
 * Runs a complete compliance scan workflow via JSON-RPC stdio:
 *   1. scan_repo
 *   2. generate_audit_packet
 *   3. export_audit_packet (ZIP)
 *   4. [optional] create_tickets (dry-run or execute with approved plan)
 *
 * Writes machine-readable summary to .compliance/ci/summary.json.
 * Prints human-readable report to stderr.
 *
 * Usage:
 *   node scripts/run-compliance.mjs --repo-path .
 *   node scripts/run-compliance.mjs --repo-path . --fail-on critical
 *   node scripts/run-compliance.mjs --repo-path . --create-tickets --dry-run
 *   node scripts/run-compliance.mjs --repo-path . --create-tickets --approved-plan-id <id>
 */

import { spawn } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdirSync, writeFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, "..");
const SERVER = join(PROJECT_ROOT, "dist", "compliance-bridge", "server.js");

// ── CLI Argument Parsing ────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    repoPath: ".",
    includeEvidence: true,
    createTickets: false,
    dryRun: true,
    approvedPlanId: null,
    target: "github",
    maxItems: 10,
    failOn: "none", // none | critical | high | medium
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--repo-path":
        opts.repoPath = args[++i];
        break;
      case "--include-evidence":
        opts.includeEvidence = true;
        break;
      case "--no-evidence":
        opts.includeEvidence = false;
        break;
      case "--create-tickets":
        opts.createTickets = true;
        break;
      case "--dry-run":
        opts.dryRun = true;
        break;
      case "--no-dry-run":
        opts.dryRun = false;
        break;
      case "--approved-plan-id":
        opts.approvedPlanId = args[++i];
        opts.createTickets = true;
        opts.dryRun = false;
        break;
      case "--target":
        opts.target = args[++i];
        break;
      case "--max-items":
        opts.maxItems = parseInt(args[++i], 10);
        break;
      case "--fail-on":
        opts.failOn = args[++i];
        if (!["none", "critical", "high", "medium"].includes(opts.failOn)) {
          console.error(`Invalid --fail-on value: ${opts.failOn}. Must be: none, critical, high, medium`);
          process.exit(2);
        }
        break;
      case "--help":
      case "-h":
        console.error(`Usage: node scripts/run-compliance.mjs [options]

Options:
  --repo-path <path>          Repository to scan (default: .)
  --include-evidence          Include raw scanner evidence in ZIP (default)
  --no-evidence               Exclude evidence from ZIP
  --create-tickets            Enable ticket creation step
  --dry-run                   Dry-run ticket creation (default when --create-tickets)
  --no-dry-run                Execute ticket creation (requires --approved-plan-id)
  --approved-plan-id <id>     Approved plan ID (implies --create-tickets --no-dry-run)
  --target <github|jira>      Ticket target system (default: github)
  --max-items <n>             Max tickets to create (default: 10)
  --fail-on <level>           Fail build if findings at this severity or above
                              Values: none (default), critical, high, medium
`);
        process.exit(0);
        break;
      default:
        console.error(`Unknown argument: ${args[i]}. Use --help for usage.`);
        process.exit(2);
    }
  }

  opts.repoPath = resolve(opts.repoPath);

  // Validate: --no-dry-run without --approved-plan-id is unsafe
  if (opts.createTickets && !opts.dryRun && !opts.approvedPlanId) {
    console.error("Error: --no-dry-run requires --approved-plan-id for ticket execution.");
    console.error("Use --dry-run first to generate a plan, then approve and pass the plan ID.");
    process.exit(2);
  }

  return opts;
}

// ── JSON-RPC over stdio ─────────────────────────────────────────

let nextId = 1;

function rpc(proc, method, params, timeoutMs = 120000) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString("utf8");
      for (const line of buf.split(/\r?\n/)) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id) {
            proc.stdout.off("data", onData);
            resolve(parsed);
            return;
          }
        } catch { /* incomplete JSON, keep buffering */ }
      }
    };
    proc.stdout.on("data", onData);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => {
      proc.stdout.off("data", onData);
      reject(new Error(`Timeout waiting for response: ${method} (id=${id})`));
    }, timeoutMs);
  });
}

function extractToolResult(resp) {
  if (resp.error) {
    throw new Error(`RPC error: ${JSON.stringify(resp.error)}`);
  }
  const content = resp.result?.content;
  if (!content || !content.length) {
    throw new Error("Empty response from tool");
  }
  const text = content[0].text;
  if (resp.result?.isError) {
    throw new Error(`Tool error: ${text}`);
  }
  return JSON.parse(text);
}

// ── Severity check ──────────────────────────────────────────────

const SEVERITY_LEVELS = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function shouldFail(findings, failOn) {
  if (failOn === "none") return false;
  const threshold = SEVERITY_LEVELS[failOn];
  if (threshold === undefined) return false;
  // Filter out scanner-missing meta-findings (identified by tags, not scanner name)
  const realFindings = findings.filter(f => !f.tags?.includes("scanner-missing"));
  return realFindings.some(f => (SEVERITY_LEVELS[f.severity] ?? 4) <= threshold);
}

function countBySeverity(findings) {
  const real = findings.filter(f => !f.tags?.includes("scanner-missing"));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of real) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  counts.total = real.length;
  return counts;
}

// ── Main workflow ───────────────────────────────────────────────

async function main() {
  const opts = parseArgs(process.argv);

  console.error("\n=== Compliance Navigator CI Runner ===\n");
  console.error(`Repo:     ${opts.repoPath}`);
  console.error(`Fail-on:  ${opts.failOn}`);
  if (opts.createTickets) {
    console.error(`Tickets:  ${opts.dryRun ? "dry-run" : "execute"} → ${opts.target}`);
    if (opts.approvedPlanId) console.error(`Plan ID:  ${opts.approvedPlanId}`);
  }
  console.error();

  // Spawn compliance-bridge server
  const proc = spawn("node", [SERVER], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: PROJECT_ROOT,
  });

  // Drain stderr to prevent buffer stall
  proc.stderr.on("data", () => {});

  let exitCode = 0;
  const summary = {};

  try {
    // Initialize MCP handshake
    await rpc(proc, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "compliance-ci-runner", version: "1.0.0" },
    });

    // Step 1: Scan
    console.error("Step 1/3: Scanning repository...");
    const scanResp = await rpc(proc, "tools/call", {
      name: "compliance.scan_repo",
      arguments: { repoPath: opts.repoPath },
    }, 600000); // 10 min timeout for scan

    const scanResult = extractToolResult(scanResp);
    const counts = countBySeverity(scanResult.findings || []);
    const coverage = scanResult.controlCoverage || {};

    summary.runId = scanResult.runId;
    summary.findings = counts;
    summary.coverage = {
      percent: coverage.coveragePct ?? 0,
      covered: coverage.coveredControls?.length ?? 0,
      total: (coverage.coveredControls?.length ?? 0) + (coverage.missingControls?.length ?? 20),
    };

    console.error(`  Findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low (${counts.total} total)`);
    console.error(`  Scanner Reach: ${summary.coverage.percent}% (${summary.coverage.covered}/${summary.coverage.total} SOC2 controls)`);

    // Step 2: Generate audit packet
    console.error("Step 2/3: Generating audit packet...");
    const packetResp = await rpc(proc, "tools/call", {
      name: "compliance.generate_audit_packet",
      arguments: { repoPath: opts.repoPath, runId: scanResult.runId },
    }, 60000);

    const packetResult = extractToolResult(packetResp);
    summary.auditPacketPath = packetResult.auditPacketPath;

    // Step 3: Export ZIP
    console.error("Step 3/3: Exporting ZIP archive...");
    const exportResp = await rpc(proc, "tools/call", {
      name: "compliance.export_audit_packet",
      arguments: {
        repoPath: opts.repoPath,
        runId: scanResult.runId,
        includeEvidence: opts.includeEvidence,
      },
    }, 60000);

    const exportResult = extractToolResult(exportResp);
    summary.zip = {
      path: exportResult.zipPath,
      bytes: exportResult.bytes,
      sha256: exportResult.sha256,
    };

    console.error(`  ZIP: ${exportResult.zipPath} (${exportResult.bytes} bytes)`);
    console.error(`  SHA-256: ${exportResult.sha256}`);

    // Optional: Create tickets
    if (opts.createTickets) {
      console.error("\nStep 4: Creating tickets...");
      const ticketArgs = {
        repoPath: opts.repoPath,
        runId: scanResult.runId,
        dryRun: opts.dryRun,
        target: opts.target,
        maxItems: opts.maxItems,
      };
      if (opts.approvedPlanId) {
        ticketArgs.approvedPlanId = opts.approvedPlanId;
      }

      const ticketResp = await rpc(proc, "tools/call", {
        name: "compliance.create_tickets",
        arguments: ticketArgs,
      }, 120000);

      const ticketResult = extractToolResult(ticketResp);
      summary.tickets = {
        planId: ticketResult.planId,
        dryRun: ticketResult.dryRun,
        wouldCreate: ticketResult.summary?.wouldCreate ?? 0,
        duplicates: ticketResult.summary?.duplicates ?? 0,
        created: ticketResult.summary?.created ?? 0,
      };

      if (ticketResult.dryRun) {
        console.error(`  Dry-run: ${summary.tickets.wouldCreate} would create, ${summary.tickets.duplicates} duplicates`);
        console.error(`  Plan ID: ${ticketResult.planId} (use with --approved-plan-id to execute)`);
      } else {
        console.error(`  Created: ${summary.tickets.created} tickets`);
      }
    }

    // Check fail-on threshold
    summary.failOn = opts.failOn;
    if (shouldFail(scanResult.findings || [], opts.failOn)) {
      console.error(`\n⛔ Build failed: findings at or above '${opts.failOn}' severity detected.`);
      exitCode = 1;
    }
    summary.exitCode = exitCode;

    // Write machine-readable summary
    const ciDir = resolve(opts.repoPath, ".compliance", "ci");
    mkdirSync(ciDir, { recursive: true });
    const summaryPath = resolve(ciDir, "summary.json");
    writeFileSync(summaryPath, JSON.stringify(summary, null, 2), "utf-8");
    console.error(`\nSummary written to: ${summaryPath}`);

  } catch (err) {
    console.error(`\nError: ${err.message}`);
    exitCode = 1;
    summary.error = err.message;
    summary.exitCode = 1;
  } finally {
    proc.kill();
  }

  console.error(`\nExit code: ${exitCode}`);
  process.exit(exitCode);
}

main();
