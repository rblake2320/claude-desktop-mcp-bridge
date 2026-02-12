# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-02-12

### Added
- **Compliance Dashboard (MCP App)**: `compliance.open_dashboard` tool + MCP resource handlers
- Interactive single-file HTML dashboard served via `resources/read` with `id="cn-dashboard"`
- Workflow UI: scan → audit packet → remediation → tickets (dry-run → approve → execute) → verify
- Findings table, evidence panel, coverage stats, ROI display, manifest viewer
- GH_TOKEN/Jira configuration detection with disabled state for unavailable actions
- CI smoke tests for `resources/list` and `resources/read` (validates HTML contains `cn-dashboard`)

### Changed
- Compliance Navigator now exposes 7 tools (was 6) plus MCP resource handlers

## [0.4.0] - 2026-02-12

### Added
- **Closed-loop ticket creation**: `compliance.create_tickets` and `compliance.approve_ticket_plan` tools
- Dry-run / approve / execute workflow with file-based approval gate
- Deterministic deduplication via `CN-FINDING-ID` markers in GitHub Issue body
- SHA-256 hash-bound approval plans with repo identity baked in (cross-repo replay prevention)
- `targetRepo` override for creating issues in a different repo than the scanned one
- `reopenClosed` flag to reopen closed duplicate issues instead of skipping
- `labelPolicy`: `require-existing` (safe default) vs `create-if-missing`
- Rate limiting with `X-RateLimit-Remaining` monitoring and 403/429 automatic backoff
- Batch pacing (2 concurrent issues, 500ms delay between batches)
- Approval artifacts stored in `<repo>/.compliance/approvals/{pending,approved}/`
- All ticket operations logged to hash-chained audit log
- `compliance.verify_audit_chain` tool: recomputes every SHA-256 hash and checks chain integrity (PASS/FAIL + first broken line)
- CI smoke test (GitHub Actions: build + tools/list assertion)

### Changed
- Compliance Navigator now exposes 6 tools (was 3)
- README updated with closed-loop workflow documentation and feature list
- Output structure diagram updated with `approvals/` directory

## [0.3.0] - 2026-02-11

### Added
- **Compliance Navigator**: SOC2-lite audit engine as a standalone MCP server
- 3 MCP tools: `compliance.scan_repo`, `compliance.generate_audit_packet`, `compliance.plan_remediation`
- Scanner integration: gitleaks (secrets), npm audit (dependencies), checkov (IaC)
- Normalizers for all 3 scanner output formats
- 20 SOC2 Trust Services control mappings with heuristic confidence scores (not auditor-validated)
- Scanner-reach metrics: observed, potential (installed scanners), and full (all scanners)
- ROI estimation model with configurable defaults (not validated against real remediation data)
- Structured audit-support packet: index.md, findings.json, coverage.json, roi.json, manifest.json
- Hash-chained audit log (SHA-256 JSONL)
- Command allowlist: only 6 regex patterns permitted (gitleaks, npm audit, checkov + version probes)
- Path policy: all writes pinned to `<repo>/.compliance/`
- Self-documenting manifest with security execution policy
- Graceful scanner degradation (missing scanners produce empty findings, scan continues)
- Windows compatibility (shell mode detection, .exe/.cmd suffix support)
- Demo repo with intentional findings for testing

## [0.2.0] - 2026-02-09

### Added
- Skills bridge with 22-skill library (master, elite, standard tiers)
- Dynamic skill loading with trust-based quarantine (SYSTEM/VERIFIED/UNTRUSTED)
- Skill marketplace infrastructure with approval workflow
- Remote SSE/HTTP server for VPS deployment

## [0.1.0] - 2026-02-08

### Added
- Initial project structure
- Filesystem bridge (read, write, edit, glob)
- Shell bridge (run command, background processes, navigation)
- Basic MCP server architecture

[0.5.0]: https://github.com/rblake2320/claude-desktop-mcp-bridge/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rblake2320/claude-desktop-mcp-bridge/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rblake2320/claude-desktop-mcp-bridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rblake2320/claude-desktop-mcp-bridge/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rblake2320/claude-desktop-mcp-bridge/releases/tag/v0.1.0
