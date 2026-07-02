/**
 * PII/PHI Detector — Adversarial Unit Tests
 *
 * Tests the compiled scanner (dist/compliance-bridge/pii-scanner.js) against
 * real files on disk. No mocks. Covers: validators, context gating, redaction,
 * binary/oversize/long-line/lock-file/symlink skipping, directory exclusions,
 * deadline exhaustion, per-file finding caps, determinism, and hostile input.
 *
 * Windows note: the symlink test requires symlink privilege (Developer Mode
 * or admin); the unreadable-file test uses icacls. Both report SKIPPED —
 * loudly — if the environment forbids them, rather than faking a pass.
 */

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const TMP = path.join(PROJECT_ROOT, "test-pii-tmp");

const {
  luhnValid, isValidSSN, matchesKnownIIN, scanRepoForPII, PII_RULES,
} = await import(
  new URL("file:///" + path.join(PROJECT_ROOT, "dist", "compliance-bridge", "pii-scanner.js").replace(/\\/g, "/")).href
);

let passed = 0, failed = 0, skipped = 0;
function assert(cond, msg) {
  if (cond) { console.log(`  PASS: ${msg}`); passed++; }
  else { console.error(`  FAIL: ${msg}`); failed++; }
}
function skip(msg) { console.warn(`  SKIP: ${msg}`); skipped++; }

function freshDir(name) {
  const dir = path.join(TMP, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Scan a dir and return findings for one rule id (by tag). */
function scanDir(dir, opts = {}) {
  return scanRepoForPII(dir, path.join(dir, "evidence.json"), opts);
}

// ── 1. Validators ─────────────────────────────────────────────────
console.log("\nTest 1: Luhn checksum");
assert(luhnValid("4111111111111111") === true, "Visa test number passes Luhn");
assert(luhnValid("4111111111111112") === false, "off-by-one digit fails Luhn");
assert(luhnValid("378282246310005") === true, "Amex test number passes Luhn");
assert(luhnValid("0000000000000000") === true, "all zeros passes Luhn (IIN check must reject it)");
assert(luhnValid("abc") === false, "non-digits fail Luhn");
assert(luhnValid("") === false, "empty string fails Luhn");

console.log("\nTest 2: IIN prefix + length");
assert(matchesKnownIIN("4111111111111111") === true, "Visa 16-digit accepted");
assert(matchesKnownIIN("0000000000000000") === false, "all zeros rejected (no issuer)");
assert(matchesKnownIIN("9111111111111111") === false, "unknown prefix 9 rejected");
assert(matchesKnownIIN("411111111111111") === false, "Visa 15-digit (wrong length) rejected");
assert(matchesKnownIIN("378282246310005") === true, "Amex 15-digit accepted");
assert(matchesKnownIIN("5555555555554444") === true, "Mastercard 16-digit accepted");
assert(matchesKnownIIN("2221000000000009") === true, "Mastercard 2-series accepted");

console.log("\nTest 3: SSN structural rules");
assert(isValidSSN("078", "05", "1120") === true, "Woolworth sample SSN structurally valid");
assert(isValidSSN("000", "12", "3456") === false, "area 000 rejected");
assert(isValidSSN("666", "12", "3456") === false, "area 666 rejected");
assert(isValidSSN("900", "12", "3456") === false, "area 900+ rejected");
assert(isValidSSN("123", "00", "4567") === false, "group 00 rejected");
assert(isValidSSN("123", "45", "0000") === false, "serial 0000 rejected");

// ── 2. Detection behavior on real files ───────────────────────────
console.log("\nTest 4: SSN detection + redaction");
{
  const dir = freshDir("ssn");
  fs.writeFileSync(path.join(dir, "a.txt"), "employee record 078-05-1120 end\n");
  fs.writeFileSync(path.join(dir, "b.txt"), "invalid ones 000-12-3456 666-12-3456 900-12-3456 123-00-4567 123-45-0000\n");
  const { findings } = scanDir(dir);
  const ssn = findings.filter(f => f.tags.includes("ssn"));
  assert(ssn.length === 1, `exactly 1 valid SSN found (got ${ssn.length})`);
  const json = JSON.stringify(findings);
  assert(!json.includes("078-05-1120"), "raw SSN absent from findings JSON (redaction)");
  assert(json.includes("***-**-1120"), "masked SSN present in findings JSON");
  assert(ssn[0].file === "a.txt" && ssn[0].line === 1, "file and line recorded");
}

console.log("\nTest 5: undashed SSN requires context");
{
  const dir = freshDir("ssn-ctx");
  fs.writeFileSync(path.join(dir, "no-ctx.txt"), "order id 078051120 shipped\n");
  fs.writeFileSync(path.join(dir, "ctx.txt"), "SSN: 078051120\n");
  const { findings } = scanDir(dir);
  const noCtx = findings.filter(f => f.file === "no-ctx.txt");
  const ctx = findings.filter(f => f.file === "ctx.txt" && f.tags.includes("ssn"));
  assert(noCtx.length === 0, "9-digit number without context NOT flagged");
  assert(ctx.length === 1, "9-digit number with SSN context flagged");
}

console.log("\nTest 6: payment card validators");
{
  const dir = freshDir("cards");
  fs.writeFileSync(path.join(dir, "c.txt"), [
    "valid: 4111111111111111",
    "luhn-fail: 4111111111111112",
    "no-issuer: 9111111111111129",
    "timestamp: 1751234567890",
    "long-run: 41111111111111112222",
    "spaced: 4111 1111 1111 1111",
  ].join("\n") + "\n");
  const { findings } = scanDir(dir);
  const cards = findings.filter(f => f.tags.includes("credit-card"));
  assert(cards.length === 2, `only valid card forms flagged (got ${cards.length}: plain + spaced)`);
  const json = JSON.stringify(cards);
  assert(!json.includes("4111111111111111"), "raw card number absent (redaction)");
  assert(json.includes("1111"), "masked card keeps last 4");
}

console.log("\nTest 7: email filtering");
{
  const dir = freshDir("emails");
  fs.writeFileSync(path.join(dir, "e.txt"), [
    "personal: jane.doe@realcompany.org",
    "role: noreply@realcompany.org",
    "reserved: user@example.com",
    "reserved2: dev@service.test",
  ].join("\n") + "\n");
  const { findings } = scanDir(dir);
  const emails = findings.filter(f => f.tags.includes("email"));
  assert(emails.length === 1, `only the personal email flagged (got ${emails.length})`);
  assert(JSON.stringify(emails).includes("j***@***.org"), "email masked to first char + TLD only");
  assert(!JSON.stringify(emails).includes("realcompany"), "domain NOT preserved in mask");
}

console.log("\nTest 8: phone/DOB/MRN context gating");
{
  const dir = freshDir("ctx-rules");
  fs.writeFileSync(path.join(dir, "gated.txt"), [
    "Phone: (555) 867-5309",
    "DOB: 1987-04-12",
    "MRN: 4587321",
  ].join("\n") + "\n");
  fs.writeFileSync(path.join(dir, "ungated.txt"), [
    "(555) 867-5309",
    "1987-04-12",
    "4587321",
    "DOB: 1987-13-12",
  ].join("\n") + "\n");
  const { findings } = scanDir(dir);
  const gated = findings.filter(f => f.file === "gated.txt");
  const ungated = findings.filter(f => f.file === "ungated.txt");
  assert(gated.some(f => f.tags.includes("phone")), "phone with context flagged");
  assert(gated.some(f => f.tags.includes("dob")), "DOB with context flagged");
  assert(gated.some(f => f.tags.includes("mrn")), "MRN with context flagged");
  assert(ungated.length === 0, `no context => no findings, and month 13 rejected (got ${ungated.length})`);
}

console.log("\nTest 9: hostile input — unicode, empty, huge line");
{
  const dir = freshDir("hostile");
  fs.writeFileSync(path.join(dir, "unicode.txt"), "名前 ☃ émoji 🎉 ssn 078-05-1120 中文\n");
  fs.writeFileSync(path.join(dir, "empty.txt"), "");
  fs.writeFileSync(path.join(dir, "longline.txt"), "x".repeat(11000) + " 078-05-1120\n");
  const { findings, stats } = scanDir(dir);
  assert(findings.some(f => f.file === "unicode.txt" && f.tags.includes("ssn")), "SSN found amid unicode");
  assert(stats.linesSkippedLong === 1, `over-long line skipped and counted (got ${stats.linesSkippedLong})`);
  assert(!findings.some(f => f.file === "longline.txt"), "SSN on over-long line not scanned (documented limit)");
  assert(stats.filesScanned === 3, `all 3 files scanned (got ${stats.filesScanned})`);
}

console.log("\nTest 10: binary, oversize, lock-file skipping");
{
  const dir = freshDir("skips");
  fs.writeFileSync(path.join(dir, "bin.dat"), Buffer.from([0x50, 0x4b, 0x00, 0x01, 0x02]));
  fs.writeFileSync(path.join(dir, "img.png"), "078-05-1120"); // binary ext, text content
  fs.writeFileSync(path.join(dir, "big.txt"), "078-05-1120 padding padding\n");
  fs.writeFileSync(path.join(dir, "package-lock.json"), '{"note":"078-05-1120"}');
  const { findings, stats } = scanDir(dir, { maxFileBytes: 10 });
  assert(findings.length === 0, "no findings from skipped files");
  assert(stats.filesSkippedBinary === 2, `null-byte + .png ext skipped (got ${stats.filesSkippedBinary})`);
  assert(stats.filesSkippedSize === 1, `oversize file skipped (got ${stats.filesSkippedSize})`);
  assert(stats.filesSkippedName === 1, `lock file skipped (got ${stats.filesSkippedName})`);
}

console.log("\nTest 11: excluded directories");
{
  const dir = freshDir("dirs");
  for (const d of ["node_modules", ".git", ".compliance", "dist"]) {
    fs.mkdirSync(path.join(dir, d), { recursive: true });
    fs.writeFileSync(path.join(dir, d, "leak.txt"), "078-05-1120\n");
  }
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src", "real.txt"), "078-05-1120\n");
  const { findings } = scanDir(dir);
  assert(findings.length === 1 && findings[0].file === "src/real.txt",
    `only src/real.txt flagged; vendored dirs excluded (got ${findings.map(f => f.file).join(", ")})`);
}

console.log("\nTest 12: symlinks not followed");
{
  const dir = freshDir("symlinks");
  const outside = freshDir("symlink-target");
  fs.writeFileSync(path.join(outside, "secret.txt"), "078-05-1120\n");
  try {
    fs.symlinkSync(outside, path.join(dir, "link"), "junction");
    const { findings, stats } = scanDir(dir);
    assert(findings.length === 0, "no findings through symlink/junction");
    assert(stats.filesSkippedSymlink >= 1, `symlink counted as skipped (got ${stats.filesSkippedSymlink})`);
  } catch (e) {
    skip(`symlink creation not permitted here (${e.code}) — symlink skip not verified in this run`);
  }
}

console.log("\nTest 13: deadline exhaustion is loud");
{
  const dir = freshDir("deadline");
  fs.writeFileSync(path.join(dir, "a.txt"), "078-05-1120\n");
  const { stats } = scanDir(dir, { deadlineMs: Date.now() - 1 });
  assert(stats.deadlineExceeded === true, "deadlineExceeded flag set");
}

console.log("\nTest 14: per-file per-rule cap is counted, not silent");
{
  const dir = freshDir("cap");
  const lines = [];
  for (let i = 0; i < 30; i++) lines.push(`row ${i}: 078-05-${String(1120 + i).padStart(4, "0")}`);
  fs.writeFileSync(path.join(dir, "many.txt"), lines.join("\n") + "\n");
  const { findings, stats } = scanDir(dir);
  const ssn = findings.filter(f => f.tags.includes("ssn"));
  assert(ssn.length === 25, `capped at 25 per rule per file (got ${ssn.length})`);
  assert(stats.findingsCapped === 5, `5 dropped matches counted (got ${stats.findingsCapped})`);
}

console.log("\nTest 15: file limit is loud");
{
  const dir = freshDir("filelimit");
  for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(dir, `f${i}.txt`), "hello\n");
  const { stats } = scanDir(dir, { maxFiles: 3 });
  assert(stats.fileLimitReached === true, "fileLimitReached flag set");
}

console.log("\nTest 16: determinism — identical findings across runs");
{
  const dir = freshDir("determinism");
  fs.writeFileSync(path.join(dir, "d.txt"), "078-05-1120 and jane@realcompany.org and 4111111111111111\n");
  const a = scanDir(dir).findings.map(f => f.id).sort();
  const b = scanDir(dir).findings.map(f => f.id).sort();
  assert(a.length > 0 && JSON.stringify(a) === JSON.stringify(b), "same finding ids on repeat runs");
}

console.log("\nTest 17: nonexistent path throws loudly");
{
  let threw = false;
  try { scanRepoForPII(path.join(TMP, "does-not-exist-xyz"), "ev.json"); }
  catch (e) { threw = /does not exist/.test(e.message); }
  assert(threw, "clear error for nonexistent repoPath");
}

console.log("\nTest 18: unreadable file counted as read error (icacls)");
{
  const dir = freshDir("unreadable");
  const locked = path.join(dir, "locked.txt");
  fs.writeFileSync(locked, "078-05-1120\n");
  fs.writeFileSync(path.join(dir, "ok.txt"), "no pii here\n");
  const deny = spawnSync("icacls", [locked, "/deny", "Everyone:(R)"], { stdio: "pipe" });
  if (deny.status !== 0) {
    skip("icacls deny failed — unreadable-file path not verified in this run");
  } else {
    try {
      const { findings, stats } = scanDir(dir);
      assert(stats.readErrors === 1, `read error counted (got ${stats.readErrors})`);
      assert(!findings.some(f => f.file === "locked.txt"), "no findings from unreadable file");
      assert(stats.filesScanned === 1, "readable sibling still scanned");
    } finally {
      spawnSync("icacls", [locked, "/remove:d", "Everyone"], { stdio: "pipe" });
    }
  }
}

console.log("\nTest 20: same-line distinct values sharing a mask are both counted");
{
  const dir = freshDir("same-line");
  // Two DIFFERENT valid SSNs with the same last 4 digits => same masked form
  fs.writeFileSync(path.join(dir, "s.txt"), "pair 078-05-1120 and 123-45-1120 end\n");
  const { findings } = scanDir(dir);
  const ssn = findings.filter(f => f.tags.includes("ssn"));
  assert(ssn.length === 2, `both same-mask SSNs counted (got ${ssn.length})`);
}

console.log("\nTest 21: short MRN is fully masked (no last-4 leak)");
{
  const dir = freshDir("mrn-mask");
  fs.writeFileSync(path.join(dir, "m.txt"), "MRN: 40021\n");
  const { findings } = scanDir(dir);
  const mrn = findings.filter(f => f.tags.includes("mrn"));
  assert(mrn.length === 1, `5-digit MRN flagged (got ${mrn.length})`);
  assert(mrn[0].title.includes("*****"), "all 5 digits masked");
  assert(!mrn[0].title.includes("0021"), "no digits of the MRN leak into the mask");
}

console.log("\nTest 22: CR-only (classic Mac) line endings get correct line numbers");
{
  const dir = freshDir("cr-only");
  fs.writeFileSync(path.join(dir, "cr.txt"), "first line\rssn 078-05-1120\rthird\r");
  const { findings } = scanDir(dir);
  const ssn = findings.filter(f => f.tags.includes("ssn"));
  assert(ssn.length === 1 && ssn[0].line === 2, `SSN on CR-only line 2 (got line ${ssn[0]?.line})`);
}

console.log("\nTest 23: deadline respected inside a directory of many small files");
{
  const dir = freshDir("deadline-dir");
  for (let i = 0; i < 200; i++) fs.writeFileSync(path.join(dir, `f${i}.txt`), "hello world\n");
  const { stats } = scanDir(dir, { deadlineMs: Date.now() });
  assert(stats.deadlineExceeded === true, "deadline stops the walk mid-directory");
  assert(stats.filesScanned < 200, `walk stopped early (scanned ${stats.filesScanned}/200)`);
}

console.log("\nTest 19: every rule has redacting mask and remediation");
{
  for (const rule of PII_RULES) {
    assert(typeof rule.mask === "function" && rule.remediation.length > 20,
      `rule ${rule.id} has mask + remediation`);
    assert(rule.pattern.flags.includes("g"), `rule ${rule.id} pattern has g flag`);
  }
}

// Cleanup
fs.rmSync(TMP, { recursive: true, force: true });

console.log(`\n=== PII unit tests: ${passed} passed, ${failed} failed, ${skipped} skipped ===\n`);
if (failed > 0) process.exit(1);
