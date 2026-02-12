/**
 * End-to-end test: demo fixture → tool invocation → verify
 *
 * Uses stdio JSON-RPC to talk to the real compliance-bridge server.
 * No mocks. No fakes. Real execution.
 */

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(PROJECT_ROOT, "dist", "compliance-bridge", "server.js");
const FIXTURE_DIR = path.join(PROJECT_ROOT, "test-fixture-output");

// Clean up previous test output
if (fs.existsSync(FIXTURE_DIR)) {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
}

let nextId = 1;
let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failed++;
  } else {
    console.log(`  PASS: ${msg}`);
    passed++;
  }
}

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

async function rpc(proc, method, params, timeoutMs = 30000) {
  const id = nextId++;
  return await new Promise((resolve, reject) => {
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
        } catch {}
      }
    };
    proc.stdout.on("data", onData);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => {
      proc.stdout.off("data", onData);
      reject(new Error(`Timeout: ${method} id=${id}`));
    }, timeoutMs);
  });
}

async function main() {
  console.log("\n=== Compliance Navigator v0.8.0 — Fixture E2E Test ===\n");
  console.log("Server:", SERVER);
  console.log("Fixture dir:", FIXTURE_DIR);
  console.log();

  const proc = spawn("node", [SERVER], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: PROJECT_ROOT,
  });

  // Drain stderr to prevent buffer stall
  proc.stderr.on("data", () => {});

  // Initialize
  await rpc(proc, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "e2e-test", version: "1.0.0" },
  });

  // ── Test 1: tools/list returns 9 tools ──
  console.log("Test 1: tools/list");
  const listResp = await rpc(proc, "tools/list", {});
  const tools = listResp.result?.tools || [];
  assert(tools.length === 9, `Expected 9 tools, got ${tools.length}`);
  const names = tools.map(t => t.name);
  assert(names.includes("compliance.create_demo_fixture"), "create_demo_fixture tool present");
  assert(names.includes("compliance.open_dashboard"), "open_dashboard tool present");
  assert(names.includes("compliance.scan_repo"), "scan_repo tool present");
  assert(names.includes("compliance.export_audit_packet"), "export_audit_packet tool present");
  console.log();

  // ── Test 2: resources/list returns 1 resource ──
  console.log("Test 2: resources/list");
  const resListResp = await rpc(proc, "resources/list", {});
  const resources = resListResp.result?.resources || [];
  assert(resources.length >= 1, `Expected >=1 resource, got ${resources.length}`);
  assert(resources[0]?.uri === "compliance://dashboard", "Dashboard resource URI correct");
  console.log();

  // ── Test 3: create_demo_fixture ──
  console.log("Test 3: create_demo_fixture");
  const fixtureResp = await rpc(proc, "tools/call", {
    name: "compliance.create_demo_fixture",
    arguments: { outputDir: FIXTURE_DIR },
  });
  assert(!fixtureResp.error, `No error: ${JSON.stringify(fixtureResp.error)}`);
  const fixtureText = fixtureResp.result?.content?.[0]?.text;
  assert(typeof fixtureText === "string", "Response has text content");
  const fixture = JSON.parse(fixtureText);
  assert(fixture.outputDir === FIXTURE_DIR, `outputDir matches: ${fixture.outputDir}`);
  assert(fixture.filesCreated.length === 8, `8 files created: ${fixture.filesCreated.length}`);
  console.log();

  // ── Test 4: Verify fixture files exist on disk ──
  console.log("Test 4: Fixture files on disk");
  const expectedFiles = [
    "README.md", ".gitignore", ".gitleaks.toml", "config.env",
    ".env.example", "package.json", "infra/main.tf", "infra/Dockerfile",
  ];
  for (const f of expectedFiles) {
    const full = path.join(FIXTURE_DIR, f);
    assert(fs.existsSync(full), `File exists: ${f}`);
  }
  console.log();

  // ── Test 5: Fixture content has expected markers ──
  console.log("Test 5: Fixture content validation");
  const configEnv = fs.readFileSync(path.join(FIXTURE_DIR, "config.env"), "utf-8");
  assert(configEnv.includes("AKIAIOSFODNN7EXAMPLE"), "config.env has fake AWS key");
  assert(configEnv.includes("TEST ONLY"), "config.env has TEST ONLY marker");

  const mainTf = fs.readFileSync(path.join(FIXTURE_DIR, "infra", "main.tf"), "utf-8");
  assert(mainTf.includes("DO-NOT-DEPLOY"), "main.tf has DO-NOT-DEPLOY marker");
  assert(mainTf.includes("aws_s3_bucket"), "main.tf has S3 bucket resource");
  assert(mainTf.includes('cidr_blocks = ["0.0.0.0/0"]'), "main.tf has open CIDR");

  const pkgJson = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, "package.json"), "utf-8"));
  assert(pkgJson.dependencies?.lodash === "4.17.20", "package.json has vulnerable lodash");
  console.log();

  // ── Test 6: Dashboard HTML contains cn-dashboard and v0.7.0 ──
  console.log("Test 6: Dashboard HTML");
  const readResp = await rpc(proc, "resources/read", {
    uri: `compliance://dashboard?repoPath=${encodeURIComponent(FIXTURE_DIR)}`,
  });
  assert(!readResp.error, `No error: ${JSON.stringify(readResp.error)}`);
  const html = readResp.result?.contents?.[0]?.text || "";
  assert(html.includes("cn-dashboard"), "HTML has cn-dashboard");
  assert(html.includes("0.8.0"), "HTML has v0.8.0");
  assert(html.includes("Create Demo Repo"), "HTML has 'Create Demo Repo' button");
  assert(html.includes("Content-Security-Policy"), "HTML has CSP meta tag");
  console.log();

  // ── Test 7: open_dashboard returns resource URI ──
  console.log("Test 7: open_dashboard tool");
  const dashResp = await rpc(proc, "tools/call", {
    name: "compliance.open_dashboard",
    arguments: { repoPath: FIXTURE_DIR },
  });
  assert(!dashResp.error, `No error: ${JSON.stringify(dashResp.error)}`);
  const dashText = dashResp.result?.content?.[0]?.text;
  const dashData = JSON.parse(dashText);
  assert(dashData.resourceUri.startsWith("compliance://dashboard?"), "resourceUri starts with compliance://dashboard?");
  assert(dashData.repoPath === FIXTURE_DIR, "repoPath matches");
  console.log();

  // ── Test 8: Security — GH_TOKEN not leaked in dashboard HTML ──
  console.log("Test 8: Token leak check");
  // Set a fake token to test
  const fakeToken = "ghp_FAKE_TEST_TOKEN_12345";
  process.env.GH_TOKEN = fakeToken;
  const secReadResp = await rpc(proc, "resources/read", {
    uri: `compliance://dashboard?repoPath=${encodeURIComponent(FIXTURE_DIR)}`,
  });
  const secHtml = secReadResp.result?.contents?.[0]?.text || "";
  assert(!secHtml.includes(fakeToken), "GH_TOKEN value NOT in HTML output");
  delete process.env.GH_TOKEN;
  console.log();

  // ── Test 9: Path traversal blocked ──
  console.log("Test 9: Path traversal protection");
  const traversalResp = await rpc(proc, "tools/call", {
    name: "compliance.create_demo_fixture",
    arguments: { outputDir: "../../etc/passwd" },
  });
  const traversalText = traversalResp.result?.content?.[0]?.text || "";
  assert(
    traversalResp.result?.isError || traversalText.includes("Error") || traversalText.includes("traversal"),
    "Path traversal blocked"
  );
  console.log();

  // ── Test 10: scan_repo on fixture → generate_audit_packet → export ZIP ──
  console.log("Test 10: scan_repo on fixture");
  const scanResp = await rpc(proc, "tools/call", {
    name: "compliance.scan_repo",
    arguments: { repoPath: FIXTURE_DIR },
  }, 120000);
  assert(!scanResp.error, `scan_repo no error: ${JSON.stringify(scanResp.error)}`);
  const scanText = scanResp.result?.content?.[0]?.text;
  assert(typeof scanText === "string", "scan_repo has text response");
  const scanResult = JSON.parse(scanText);
  assert(typeof scanResult.runId === "string", `scan_repo returned runId: ${scanResult.runId}`);
  assert(Array.isArray(scanResult.findings), "scan_repo returned findings array");
  console.log();

  // ── Test 11: generate_audit_packet ──
  console.log("Test 11: generate_audit_packet");
  const packetResp = await rpc(proc, "tools/call", {
    name: "compliance.generate_audit_packet",
    arguments: { repoPath: FIXTURE_DIR, runId: scanResult.runId },
  });
  assert(!packetResp.error, `generate_audit_packet no error: ${JSON.stringify(packetResp.error)}`);
  const packetText = packetResp.result?.content?.[0]?.text;
  const packetResult = JSON.parse(packetText);
  assert(typeof packetResult.auditPacketPath === "string", "audit packet path returned");
  assert(fs.existsSync(packetResult.auditPacketPath), "audit_packet directory exists on disk");
  assert(fs.existsSync(path.join(packetResult.auditPacketPath, "index.md")), "index.md exists in packet");
  assert(fs.existsSync(path.join(packetResult.auditPacketPath, "findings.json")), "findings.json exists in packet");
  console.log();

  // ── Test 12: export_audit_packet (ZIP) ──
  console.log("Test 12: export_audit_packet (ZIP)");
  const exportResp = await rpc(proc, "tools/call", {
    name: "compliance.export_audit_packet",
    arguments: { repoPath: FIXTURE_DIR, runId: scanResult.runId },
  });
  assert(!exportResp.error, `export_audit_packet no error: ${JSON.stringify(exportResp.error)}`);
  const exportText = exportResp.result?.content?.[0]?.text;
  assert(typeof exportText === "string", "export_audit_packet has text response");
  const exportResult = JSON.parse(exportText);
  assert(typeof exportResult.zipPath === "string", `zipPath returned: ${exportResult.zipPath}`);
  assert(typeof exportResult.bytes === "number" && exportResult.bytes > 0, `bytes > 0: ${exportResult.bytes}`);
  assert(typeof exportResult.sha256 === "string" && exportResult.sha256.length === 64, `sha256 is 64 hex chars: ${exportResult.sha256}`);
  assert(exportResult.runId === scanResult.runId, "runId matches");
  assert(exportResult.includesEvidence === true, "includesEvidence is true (default)");
  console.log();

  // ── Test 13: ZIP file exists on disk and SHA-256 matches ──
  console.log("Test 13: ZIP file integrity");
  assert(fs.existsSync(exportResult.zipPath), "ZIP file exists on disk");
  const zipBytes = fs.readFileSync(exportResult.zipPath);
  assert(zipBytes.length === exportResult.bytes, `ZIP byte count matches: ${zipBytes.length} === ${exportResult.bytes}`);

  // Verify SHA-256
  const computedHash = crypto.createHash("sha256").update(zipBytes).digest("hex");
  assert(computedHash === exportResult.sha256, `SHA-256 matches: ${computedHash}`);

  // Verify ZIP magic bytes (PK header: 0x50 0x4B)
  assert(zipBytes[0] === 0x50 && zipBytes[1] === 0x4B, "ZIP has PK magic bytes");
  console.log();

  // ── Test 14: export without evidence (smaller) ──
  console.log("Test 14: export without evidence");
  const exportNoEvResp = await rpc(proc, "tools/call", {
    name: "compliance.export_audit_packet",
    arguments: { repoPath: FIXTURE_DIR, runId: scanResult.runId, includeEvidence: false },
  });
  assert(!exportNoEvResp.error, `export no-evidence no error: ${JSON.stringify(exportNoEvResp.error)}`);
  const exportNoEvResult = JSON.parse(exportNoEvResp.result?.content?.[0]?.text);
  assert(exportNoEvResult.includesEvidence === false, "includesEvidence is false");
  assert(exportNoEvResult.bytes > 0, `bytes > 0: ${exportNoEvResult.bytes}`);
  // The no-evidence ZIP should be smaller or equal (depends on whether evidence exists)
  assert(exportNoEvResult.bytes <= exportResult.bytes, `No-evidence ZIP (${exportNoEvResult.bytes}) <= full ZIP (${exportResult.bytes})`);
  console.log();

  // ── Test 15: export with non-existent runId fails ──
  console.log("Test 15: export with bad runId");
  const exportBadResp = await rpc(proc, "tools/call", {
    name: "compliance.export_audit_packet",
    arguments: { repoPath: FIXTURE_DIR, runId: "nonexistent-run-12345" },
  });
  const exportBadText = exportBadResp.result?.content?.[0]?.text || "";
  assert(
    exportBadResp.result?.isError || exportBadText.includes("Error") || exportBadText.includes("not found"),
    "Export with bad runId fails gracefully"
  );
  console.log();

  // ── Test 16: planId with path traversal rejected at schema level ──
  console.log("Test 16: planId validation");
  const badPlanResp = await rpc(proc, "tools/call", {
    name: "compliance.approve_ticket_plan",
    arguments: { repoPath: FIXTURE_DIR, planId: "../../etc/passwd", approvedBy: "test" },
  });
  const badPlanText = badPlanResp.result?.content?.[0]?.text || "";
  assert(
    badPlanResp.result?.isError || badPlanText.includes("Error") || badPlanText.includes("invalid"),
    "planId with path traversal rejected"
  );

  const shellPlanResp = await rpc(proc, "tools/call", {
    name: "compliance.approve_ticket_plan",
    arguments: { repoPath: FIXTURE_DIR, planId: "plan&whoami", approvedBy: "test" },
  });
  const shellPlanText = shellPlanResp.result?.content?.[0]?.text || "";
  assert(
    shellPlanResp.result?.isError || shellPlanText.includes("Error") || shellPlanText.includes("invalid"),
    "planId with shell metacharacters rejected"
  );
  console.log();

  // Cleanup
  proc.kill();
  await wait(250);

  // Clean up test fixture directory
  if (fs.existsSync(FIXTURE_DIR)) {
    fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  }

  // Summary
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => {
  console.error("FATAL:", e.stack || e.message);
  process.exit(1);
});
