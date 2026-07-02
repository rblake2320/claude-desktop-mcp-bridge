/**
 * Failure injection: kill mid-scan, restart, concurrency, memory behavior.
 *
 * Real execution against the compiled server — no mocks.
 *   1. Kill the server process while compliance.scan_repo is in flight.
 *   2. Restart: audit chain must still verify, a fresh scan must succeed,
 *      and the orphaned partial run must fail loudly (not silently) when used.
 *   3. Two concurrent scans on the same repo → distinct runIds, both complete.
 *   4. 10 sequential PII scans of a 500-file tree → RSS must not grow unbounded.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(PROJECT_ROOT, "dist", "compliance-bridge", "server.js");
const FIXTURE_DIR = path.join(PROJECT_ROOT, "test-fixture-failinject");

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { console.log(`  PASS: ${msg}`); passed++; }
  else { console.error(`  FAIL: ${msg}`); failed++; }
}
const wait = (ms) => new Promise(r => setTimeout(r, ms));

let nextId = 1;
function startServer() {
  const proc = spawn("node", [SERVER], { stdio: ["pipe", "pipe", "pipe"], cwd: PROJECT_ROOT });
  proc.stderr.on("data", () => {});
  return proc;
}
function rpc(proc, method, params, timeoutMs = 120000) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString("utf8");
      for (const line of buf.split(/\r?\n/)) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id) { proc.stdout.off("data", onData); resolve(parsed); return; }
        } catch {}
      }
    };
    proc.stdout.on("data", onData);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => { proc.stdout.off("data", onData); reject(new Error(`Timeout: ${method}`)); }, timeoutMs);
  });
}
const init = (proc) => rpc(proc, "initialize", {
  protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "failinject", version: "1.0.0" },
});
const call = (proc, name, args, t) => rpc(proc, "tools/call", { name, arguments: args }, t);
const parseResult = (resp) => JSON.parse(resp.result.content[0].text);

async function main() {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });

  console.log("\n=== Failure Injection Suite ===\n");

  // ── 1. Kill mid-scan ──
  console.log("Test 1: kill server mid-scan");
  let proc = startServer();
  await init(proc);
  parseResult(await call(proc, "compliance.create_demo_fixture", { outputDir: FIXTURE_DIR }));

  // Fire scan, kill 300ms in (checkov alone takes seconds)
  const inflight = call(proc, "compliance.scan_repo", { repoPath: FIXTURE_DIR }).catch(() => null);
  await wait(300);
  proc.kill("SIGKILL");
  await inflight; // resolves null on timeout/kill
  await wait(300);

  const runsDir = path.join(FIXTURE_DIR, ".compliance", "runs");
  const runsAfterKill = fs.existsSync(runsDir) ? fs.readdirSync(runsDir) : [];
  console.log(`  (info) run dirs after kill: ${runsAfterKill.length}`);
  const orphaned = runsAfterKill.filter(r => !fs.existsSync(path.join(runsDir, r, "scan_result.json")));
  console.log(`  (info) killed mid-scan; ${orphaned.length} orphaned partial run dir(s) on disk`);

  // ── 2. Restart and verify state ──
  console.log("\nTest 2: restart — chain verifies, fresh scan succeeds, orphan fails loudly");
  proc = startServer();
  await init(proc);

  const verify1 = parseResult(await call(proc, "compliance.verify_audit_chain", {}));
  assert(verify1.valid === true, `audit chain valid after SIGKILL (entries: ${verify1.totalEntries})`);

  if (orphaned.length > 0) {
    const orphanResp = await call(proc, "compliance.generate_audit_packet", {
      repoPath: FIXTURE_DIR, runId: orphaned[0],
    });
    const text = orphanResp.result?.content?.[0]?.text || "";
    assert(orphanResp.result?.isError && text.includes("not found"),
      `orphaned partial run fails loudly: ${text.slice(0, 80)}`);
  } else {
    console.log("  (info) no orphaned run dir was left (scan may not have started writing) — skip orphan check");
  }

  const rescan = parseResult(await call(proc, "compliance.scan_repo", { repoPath: FIXTURE_DIR }));
  assert(typeof rescan.runId === "string" && Array.isArray(rescan.findings),
    `fresh scan after kill succeeds (runId ${rescan.runId}, ${rescan.findings.length} findings)`);
  assert(rescan.countsByScanner.pii === 6, `pii findings intact after restart (got ${rescan.countsByScanner.pii})`);

  const verify2 = parseResult(await call(proc, "compliance.verify_audit_chain", {}));
  assert(verify2.valid === true, `audit chain still valid after rescan (entries: ${verify2.totalEntries})`);

  // ── 3. Concurrent scans on the same repo ──
  console.log("\nTest 3: two concurrent scans, same repo");
  const [scanA, scanB] = await Promise.all([
    call(proc, "compliance.scan_repo", { repoPath: FIXTURE_DIR }),
    call(proc, "compliance.scan_repo", { repoPath: FIXTURE_DIR }),
  ]);
  const a = parseResult(scanA), b = parseResult(scanB);
  assert(a.runId !== b.runId, `distinct runIds: ${a.runId} vs ${b.runId}`);
  assert(a.countsByScanner.pii === 6 && b.countsByScanner.pii === 6, "both concurrent scans found 6 pii findings");
  assert(fs.existsSync(path.join(runsDir, a.runId, "scan_result.json"))
      && fs.existsSync(path.join(runsDir, b.runId, "scan_result.json")),
    "both scan_result.json files persisted");
  const verify3 = parseResult(await call(proc, "compliance.verify_audit_chain", {}));
  assert(verify3.valid === true, "audit chain valid after concurrent scans");

  proc.kill();
  await wait(200);

  // ── 4. Memory behavior: 10 sequential PII scans of a 500-file tree ──
  console.log("\nTest 4: PII scanner memory over 10 scans x 500 files");
  const bigDir = path.join(PROJECT_ROOT, "test-pii-mem");
  fs.rmSync(bigDir, { recursive: true, force: true });
  fs.mkdirSync(bigDir, { recursive: true });
  for (let i = 0; i < 500; i++) {
    fs.writeFileSync(path.join(bigDir, `f${i}.txt`),
      `record ${i}\nemail: person${i}@realcompany.org\nssn 078-05-1120\n`.repeat(20));
  }
  const { scanRepoForPII } = await import(
    new URL("file:///" + path.join(PROJECT_ROOT, "dist", "compliance-bridge", "pii-scanner.js").replace(/\\/g, "/")).href
  );
  if (typeof global.gc !== "function") {
    console.error("  FAIL: run with node --expose-gc for an honest heap measurement");
    failed++;
  }
  global.gc?.();
  const heapBefore = process.memoryUsage().heapUsed;
  let totalFindings = 0;
  for (let i = 0; i < 10; i++) {
    const { findings } = scanRepoForPII(bigDir, "mem-test-evidence.json");
    totalFindings += findings.length;
    global.gc?.();
  }
  const heapAfter = process.memoryUsage().heapUsed;
  const growthMb = (heapAfter - heapBefore) / (1024 * 1024);
  console.log(`  (info) findings total: ${totalFindings}, post-GC heap growth: ${growthMb.toFixed(1)} MB`);
  // Each file holds 20 email lines + 20 SSN lines (content is .repeat(20)),
  // both under the 25-per-rule-per-file cap => 40 findings/file.
  assert(totalFindings === 10 * 500 * 40, `deterministic finding count across 10 runs (got ${totalFindings})`);
  assert(growthMb < 20, `post-GC heap growth bounded (<20 MB): ${growthMb.toFixed(1)} MB`);
  fs.rmSync(bigDir, { recursive: true, force: true });

  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });

  console.log(`\n=== Failure injection: ${passed} passed, ${failed} failed ===\n`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => { console.error("FATAL:", e.stack || e.message); process.exit(1); });
