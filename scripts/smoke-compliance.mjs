import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const SERVER = process.argv[2] || "dist/compliance-bridge/server.js";
const REPO_PATH = process.env.SMOKE_REPO_PATH || process.cwd();

// Set SMOKE_TICKETS=1 to exercise dry-run ticket planning
const DO_TICKETS = process.env.SMOKE_TICKETS === "1";

// Set SMOKE_TICKETS_EXECUTE=1 to actually create issues (requires GH_TOKEN + approval)
const DO_TICKETS_EXECUTE = process.env.SMOKE_TICKETS_EXECUTE === "1";

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

function parseJsonLines(buffer) {
  const lines = buffer.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    try { return JSON.parse(line); } catch {}
  }
  return null;
}

async function rpc(proc, msg, timeoutMs = 15000) {
  return await new Promise((resolve, reject) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString("utf8");
      const parsed = parseJsonLines(buf);
      if (parsed && parsed.id === msg.id) {
        proc.stdout.off("data", onData);
        resolve(parsed);
      }
    };
    proc.stdout.on("data", onData);
    proc.stdin.write(JSON.stringify(msg) + "\n");

    setTimeout(() => {
      proc.stdout.off("data", onData);
      reject(new Error(`RPC timeout for id=${msg.id} method=${msg.method}`));
    }, timeoutMs);
  });
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function requireEnv(name) {
  const v = process.env[name];
  assert(v && v.length > 0, `Missing required env var: ${name}`);
  return v;
}

async function main() {
  console.log("Starting server:", SERVER);
  console.log("Repo path:", REPO_PATH);

  const proc = spawn("node", [SERVER], { stdio: ["pipe", "pipe", "inherit"] });

  // 1) tools/list
  const list = await rpc(proc, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, 10000);
  assert(!list.error, `tools/list error: ${JSON.stringify(list.error)}`);
  const tools = list.result?.tools || [];
  assert(Array.isArray(tools) && tools.length > 0, "tools/list returned no tools");

  const names = tools.map(t => t.name);
  const required = [
    "compliance.scan_repo",
    "compliance.generate_audit_packet",
    "compliance.plan_remediation",
    "compliance.create_tickets",
    "compliance.approve_ticket_plan",
  ];
  for (const r of required) assert(names.includes(r), `Missing tool: ${r}`);
  console.log("PASS tools/list (5 tools present)");

  // 2) scan_repo
  const scanResp = await rpc(proc, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "compliance.scan_repo",
      arguments: {
        framework: "soc2",
        repoPath: REPO_PATH,
        maxMinutes: 5
      }
    }
  }, 60000);

  assert(!scanResp.error, `scan_repo error: ${JSON.stringify(scanResp.error)}`);

  const scanText = scanResp.result?.content?.[0]?.text;
  assert(typeof scanText === "string" && scanText.length > 0, "scan_repo returned no text content");
  const scan = JSON.parse(scanText);

  assert(scan.runId, "scan_repo response missing runId");
  assert(scan.evidenceDir, "scan_repo response missing evidenceDir");
  console.log("PASS scan_repo runId:", scan.runId);

  // 3) generate_audit_packet
  const genResp = await rpc(proc, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "compliance.generate_audit_packet", arguments: { scan } }
  }, 30000);

  assert(!genResp.error, `generate_audit_packet error: ${JSON.stringify(genResp.error)}`);

  const genText = genResp.result?.content?.[0]?.text;
  assert(typeof genText === "string" && genText.length > 0, "generate_audit_packet returned no text content");
  const out = JSON.parse(genText);

  const indexPath = out.indexPath || out.index_path;
  const findingsJsonPath = out.findingsJsonPath || out.findings_json_path;
  const manifestPath = out.manifestPath || out.manifest_path;

  assert(indexPath && fs.existsSync(indexPath), `index.md not found at ${indexPath}`);
  assert(findingsJsonPath && fs.existsSync(findingsJsonPath), `findings.json not found at ${findingsJsonPath}`);
  if (manifestPath) assert(fs.existsSync(manifestPath), `manifest.json not found at ${manifestPath}`);

  console.log("PASS generate_audit_packet", indexPath);

  // 4) create_tickets dry-run (optional)
  if (DO_TICKETS) {
    // For dry-run, GH token is optional if your implementation allows "plan only" without API calls.
    // If you call GitHub Search API for dedupe even in dry-run, require GH_TOKEN here:
    requireEnv("GH_TOKEN");

    const ctResp = await rpc(proc, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "compliance.create_tickets",
        arguments: {
          repoPath: REPO_PATH,
          runId: scan.runId,
          maxItems: 3,
          target: "github",
          dryRun: true,
          labelPolicy: "require-existing"
        }
      }
    }, 30000);

    assert(!ctResp.error, `create_tickets(dryRun) error: ${JSON.stringify(ctResp.error)}`);
    const ctText = ctResp.result?.content?.[0]?.text;
    assert(typeof ctText === "string" && ctText.length > 0, "create_tickets returned no text content");
    const plan = JSON.parse(ctText);

    assert(plan.planId, "create_tickets missing planId");
    assert(plan.dryRun === true, "create_tickets dryRun not true");
    assert(Array.isArray(plan.wouldCreate), "create_tickets wouldCreate not array");

    // Confirm pending approval artifact exists (pinned to .compliance)
    const pendingPath =
      path.join(REPO_PATH, ".compliance", "approvals", "pending", `${plan.planId}.json`);
    assert(fs.existsSync(pendingPath), `Pending approval file missing: ${pendingPath}`);

    console.log("PASS create_tickets dry-run planId:", plan.planId);

    // 5) execute ticket creation (OFF by default)
    if (DO_TICKETS_EXECUTE) {
      // This will create real issues: only enable on a disposable repo.
      const approvedBy = process.env.SMOKE_APPROVED_BY || "smoke-test";
      const approveResp = await rpc(proc, {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "compliance.approve_ticket_plan",
          arguments: { repoPath: REPO_PATH, planId: plan.planId, approvedBy }
        }
      }, 15000);
      assert(!approveResp.error, `approve_ticket_plan error: ${JSON.stringify(approveResp.error)}`);

      const execResp = await rpc(proc, {
        jsonrpc: "2.0",
        id: 6,
        method: "tools/call",
        params: {
          name: "compliance.create_tickets",
          arguments: {
            repoPath: REPO_PATH,
            runId: scan.runId,
            maxItems: 3,
            target: "github",
            dryRun: false,
            approvedPlanId: plan.planId,
            labelPolicy: "require-existing"
          }
        }
      }, 60000);

      assert(!execResp.error, `create_tickets(execute) error: ${JSON.stringify(execResp.error)}`);
      const execText = execResp.result?.content?.[0]?.text;
      const exec = JSON.parse(execText);
      assert(Array.isArray(exec.created), "Expected created[] in execute response");
      console.log("PASS create_tickets execute created:", exec.created.length);
    }
  } else {
    console.log("SKIP create_tickets (set SMOKE_TICKETS=1)");
  }

  proc.kill();
  await wait(250);
}

main().catch((e) => {
  console.error("FAIL:", e.stack || e.message);
  process.exit(1);
});
