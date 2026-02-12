# SYNC CONTEXT — DO NOT LOSE THIS (project is already far along)

Repo: claude-desktop-mcp-bridge (public), current releases include v0.8.0.

## WHAT IS ALREADY SHIPPED (do NOT re-implement; build on it)

Compliance Navigator is a standalone MCP server: `src/compliance-bridge/server.ts`, CI green Node 18/20/22.

## TOOL SURFACE (9 tools exist now)

1. **compliance.scan_repo** — Runs gitleaks + npm audit + checkov, normalizes findings, produces manifest, "SOC2 Scanner Reach" (NOT compliance)
2. **compliance.generate_audit_packet** — Writes structured audit-support packet (index.md + findings.json + coverage + roi + manifest + evidence/)
3. **compliance.plan_remediation** — Deterministic prioritized steps w/ effort estimates
4. **compliance.create_tickets** — Targets github + jira. Always dry-run first → planId → pending approval artifact. Execute requires approvedPlanId + planHash match, supports dedupe markers, reopenClosed, labelPolicy, rate limit backoff
5. **compliance.approve_ticket_plan** — Writes approved artifact under .compliance/approvals/approved/
6. **compliance.verify_audit_chain** — Recomputes SHA-256 chain, PASS/FAIL + first broken line
7. **compliance.open_dashboard** — Returns resource URI (compliance://dashboard?...), serves single-file HTML via resources/read
8. **compliance.create_demo_fixture** — Generates a safe demo repo with intentional findings for all scanners and is gitignored
9. **compliance.export_audit_packet** — ZIP export of audit packet with SHA-256 integrity hash, writes to .compliance/exports/<runId>/

## MCP APP DASHBOARD (already shipped)

- `resources/list` includes `compliance://dashboard`
- `resources/read` returns HTML with `id="cn-dashboard"`
- Dashboard shows workflow steps: Scan → Packet → Remediation → Tickets (dry-run) → Approve → Execute → Verify
- Dashboard disables ticket actions when GH_TOKEN/JIRA env missing
- Quick Start card with "Create Demo Repo" button
- Security: `safeJsonEmbed` escapes `</script>`, strict URI match, `validateRepoPath` enforced in resources/read, `esc()` for HTML fields, CSP meta tag

## SECURITY MODEL (must remain enforced)

- gitleaks/checkov spawn with `shell: false` on all platforms (.exe on Windows, direct exec on Unix); npm.cmd uses `shell: true` with cmd metachar hard-rejection + double-quote sanitization (scanner allowlist stays tight — 6 regex patterns only)
- GitHub/Jira integrations are fetch() APIs using env tokens
- All writes pinned under `<repo>/.compliance/` with safePath validation
- Ticket workflow has dry-run → approve → execute with planHash binding and repoFullName included to prevent cross-repo replay
- Hash-chained audit log is verifiable via `compliance.verify_audit_chain`
- Demo fixture secrets are fake and excluded by fixture .gitignore; never commit fixtures or .compliance artifacts
- All path-accepting schema fields use `safePath` (blocks `../` traversal and null bytes)
- All `runId` schema fields use `safeRunId` (alphanumeric, dots, underscores, hyphens; must contain at least one alphanumeric; max 64 chars)
- All `planId`/`approvedPlanId` schema fields use `safePlanId` (same character rules as safeRunId, min 6 chars; blocks path traversal via approval artifact filenames)
- ZIP export skips symlinks to prevent data exfiltration attacks

## PRODUCT LANGUAGE (use this wording — do not inflate)

- "SOC2 Scanner Reach" not "SOC2 Compliance"
- "Est. Hours Saved (NOT VALIDATED)" with documented ranges
- "hash-chained log + verifier" not "tamper-proof"
- "structured audit-support packet" not "audit-grade guarantee"
- Dashboard payload-copy is a design choice, not a protocol limitation

## BEST USE CASES READY TODAY (no new code required)

1. **Closed-loop remediation** — scan → packet → tickets → verify chain
2. **MSP/consultancy packaging** — deliver packet + ticket plan + verified chain
3. **CI/CD change-control evidence** — run in CI and attach packet artifacts

## REVIEW PROTOCOL (always run before commit)

Every code change must pass 3 parallel subagent reviews before commit:
1. **Peer Review** — correctness, edge cases, regressions
2. **Skeptic Review** — security vulnerabilities, attack vectors, bypasses
3. **Fact Checker** — verify all CLAUDE.md claims match actual source code

## KNOWN PRE-EXISTING SECURITY ITEMS (track for future hardening)

- ~~`planId` and `approvedPlanId` in schemas.ts lack character-class restriction~~ — FIXED in v0.8.0 (safePlanId)
- ~~`shell: true` on Windows with unsanitized repoPath~~ — FIXED in v0.8.0 (per-command shell decision + metachar rejection)
- `getLatestRunId` returns unsanitized directory names (mitigated by assertCompliancePath downstream)
- TOCTOU race in symlink check (requires local write access, can't fix without replacing archiver)

## BUILD QUEUE (next targets, in order)

1. ~~**ZIP export**~~ — SHIPPED in v0.7.0
2. ~~**GitHub Action wrapper**~~ — SHIPPED in v0.8.0 (`scripts/run-compliance.mjs` + `.github/workflows/compliance.yml`)
3. **HIPAA Security Rule mapping** — `framework: 'hipaa'` + 164.312 control map. Next target.
4. **PHI/PII detector** — new scanner (Presidio or similar) alongside gitleaks/npm-audit/checkov

## ARCHITECTURE

```
Claude Desktop → MCP Client → MCP Bridge Servers → Local System
                                    ↓
                            [filesystem-bridge]
                            [shell-bridge]
                            [skills-bridge]
                            [compliance-bridge]  ← 9 tools + MCP resource handlers
                            [task-bridge]
```

All bridges are standalone MCP servers using StdioServerTransport.

## KEY FILES

- `src/compliance-bridge/server.ts` — Main MCP server (9 tools + resource handlers)
- `src/compliance-bridge/contracts.ts` — All TypeScript types
- `src/compliance-bridge/schemas.ts` — Zod validation (9 tool schemas, all paths use safePath)
- `src/compliance-bridge/policy.ts` — Per-tool risk tiers
- `src/compliance-bridge/dashboard.ts` — Single-file HTML dashboard generator
- `src/compliance-bridge/demo-fixture.ts` — Demo repo generator
- `src/compliance-bridge/zip-export.ts` — ZIP export with SHA-256 integrity hash
- `src/compliance-bridge/ticket-writer.ts` — GitHub Issues + Jira integration
- `src/compliance-bridge/normalizers/` — Scanner output parsers (gitleaks, npm-audit, checkov)
- `src/compliance-bridge/soc2-map.ts` — 20-control SOC2 mapping
- `src/compliance-bridge/roi.ts` — ROI estimation model
- `src/compliance-bridge/audit-packet.ts` — Structured audit-support packet generator
- `src/shared/command-allowlist.ts` — Scanner command allowlist (6 regex patterns)
- `src/shared/path-policy.ts` — Path escape prevention
- `src/shared/audit-chain.ts` — SHA-256 hash-chained JSONL log
- `.github/workflows/ci.yml` — CI: build + smoke test (9 tools + resources)
- `.github/workflows/compliance.yml` — GitHub Action: scan + export + upload artifact + optional tickets
- `scripts/run-compliance.mjs` — CI runner script (JSON-RPC stdio, --fail-on, JSON summary output)
- `scripts/test-fixture-e2e.mjs` — 62-assertion E2E suite (real execution, no mocks)
