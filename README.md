# Claude Desktop MCP Bridge

**Bringing Claude Code capabilities to Claude Desktop through Model Context Protocol (MCP)**

## Problem Statement

Claude Desktop and Claude Code offer different capabilities:
- **Claude Desktop**: General-purpose AI assistant with limited local system access
- **Claude Code**: Full development environment with filesystem access, shell commands, and extensive skills library

**Why should users be forced to choose?** If Claude Desktop can access Docker, there's no technical reason it can't access the same tools as Claude Code through MCP.

## Vision

Create MCP servers that expose Claude Code functionality to Claude Desktop, enabling:
- ✅ File operations (read, write, edit)
- ✅ Shell command execution
- ✅ Code search and navigation
- ✅ Skills library integration
- ✅ Task management system
- ✅ Persistent memory and learning

## Architecture

```
Claude Desktop → MCP Client → MCP Bridge Servers → Local System
                                    ↓
                            [filesystem-bridge]
                            [shell-bridge]
                            [skills-bridge]
                            [compliance-bridge]  ← SOC2-lite compliance scanner
                            [task-bridge]
```

## MCP Servers

### 1. 📁 `filesystem-bridge` ✅ **COMPLETE**
Exposes Claude Code's file operations:
- `read_file()` - Read any file with line numbers
- `write_file()` - Create new files
- `edit_file()` - Exact string replacements
- `glob_search()` - Pattern-based file finding

### 2. 🖥️ `shell-bridge` ✅ **COMPLETE**
Provides secure shell access:
- `run_command()` - Execute bash/cmd commands
- `run_background()` - Background process management
- `get_current_directory()`, `change_directory()` - Navigation
- Safety controls and timeouts

### 3. 🧠 `skills-bridge` ✅ **COMPLETE**
Exposes Claude Code's **entire 22-skill library**:
- `list_skills()` - Browse all available skills by category
- `find_skills()` - Search skills by keywords/triggers
- `apply_skill()` - Apply specific skill to your task
- `auto_skill_match()` - Auto-find and apply best skill

**Available Skills:**
- **⭐ Master Skills (4):** Ultra Frontend, Ultra Backend, Ultra Fullstack, Ultra CSS
- **🏆 Elite Skills (4):** Master Debugger, Ultra Architect, Clean Code, Self-Learning
- **💡 Standard Skills (14):** AI Agent Builder, LLM Trainer, Test Automation, DevOps CI/CD, Data Engineering, Web Scraping, API Development, Database Management, Security Testing, MLOps, Cloud Infrastructure, Monitoring & Observability, Knowledge Base Builder, MCP Builder

### 4. `compliance-bridge` (Compliance Navigator)

**Compliance Navigator turns MCP from tool plumbing into a structured compliance workflow engine.**

SOC2-lite scanning in 8 tools with an interactive dashboard -- scan a repo, generate an audit-support packet, get a prioritized fix plan, and create tracked work items (GitHub Issues or Jira). Runs gitleaks (secrets), npm audit (dependencies), and checkov (IaC) through a strict command allowlist, maps findings to 20 SOC2 Trust Services controls, and provides remediation ROI estimates.

> **Important**: This tool assists with compliance workflows but does not replace a SOC2 audit. Scanner findings indicate potential control gaps -- they do not prove controls are implemented. Coverage percentages reflect scanner reach, not auditor-verified compliance status. ROI estimates use configurable industry-informed defaults, not measured data. All outputs should be reviewed by qualified personnel before use in formal compliance processes.

#### Quickstart

```bash
npm install && npm run build
```

Add to Claude Desktop MCP config (`claude_desktop_config.json`):
```json
{
  "compliance-bridge": {
    "command": "node",
    "args": ["./dist/compliance-bridge/server.js"]
  }
}
```

Then ask Claude: *"Run a compliance scan on this repo"* -- or call the tools directly:

```jsonc
// 1. Scan
{"method":"tools/call","params":{"name":"compliance.scan_repo","arguments":{"repoPath":"/path/to/repo"}}}

// Response includes:
// findings[], countsBySeverity, countsByScanner, controlCoverage{coveragePct, coveragePctPotential, coveragePctFull},
// roiEstimate{hoursSavedConservative, hoursSavedLikely}, scannerStatuses[], manifest{policy, excludedPaths}

// 2. Generate audit packet
{"method":"tools/call","params":{"name":"compliance.generate_audit_packet","arguments":{"repoPath":"/path/to/repo"}}}

// 3. Get remediation plan
{"method":"tools/call","params":{"name":"compliance.plan_remediation","arguments":{"repoPath":"/path/to/repo"}}}
```

**Example output** (against the included demo-repo with intentional vulnerabilities): findings array with severity/scanner/SOC2 mappings, control coverage percentages, and ROI estimates. Real-world results depend on your codebase and which scanners are installed.

#### Closed-Loop Ticket Creation

Turn findings into tracked work items with a secure dry-run / approve / execute flow:

```jsonc
// Step 1: Dry-run -- preview what would be created (no side effects)
{"method":"tools/call","params":{"name":"compliance.create_tickets","arguments":{
  "repoPath":"/path/to/repo", "dryRun": true
}}}
// Response: planId, wouldCreate[], skippedAsDuplicate[]

// Step 2: Approve the plan (file-based, hash-verified)
{"method":"tools/call","params":{"name":"compliance.approve_ticket_plan","arguments":{
  "repoPath":"/path/to/repo", "planId":"<planId>", "approvedBy":"security-lead"
}}}

// Step 3: Execute -- creates real GitHub Issues
{"method":"tools/call","params":{"name":"compliance.create_tickets","arguments":{
  "repoPath":"/path/to/repo", "dryRun": false, "approvedPlanId":"<planId>"
}}}
// Response: created[{url, number}], summary{requested, created, duplicates, reopened}
```

**One-liner demo** (scan + packet + tickets dry-run):
```
scan_repo → generate_audit_packet → create_tickets(dryRun=true) → approve → create_tickets(dryRun=false)
```

**Safety and control features:**
- **Deduplication**: `CN-FINDING-ID` markers in issue body prevent duplicate issues across runs
- **Approval gate**: SHA-256 hash-bound plans with repo identity baked in (prevents cross-repo replay)
- **reopenClosed**: Optionally reopen closed duplicate issues instead of skipping
- **labelPolicy**: `require-existing` (safe default) only uses labels that already exist; `create-if-missing` auto-creates them
- **Rate limiting**: Automatic backoff on GitHub/Jira API 403/429 responses with `X-RateLimit-Remaining` monitoring
- **Audit trail**: Every dry-run, approval, and execution logged to the hash-chained audit log

#### Compliance Dashboard (MCP App)

Open an interactive dashboard inside Claude Desktop or any MCP client that supports resources:

```jsonc
// Open dashboard for a repo
{"method":"tools/call","params":{"name":"compliance.open_dashboard","arguments":{"repoPath":"/path/to/repo"}}}
// Response: { resourceUri: "compliance://dashboard?repoPath=..." }

// Render via resources/read
{"method":"resources/read","params":{"uri":"compliance://dashboard?repoPath=/path/to/repo"}}
// Response: HTML with id="cn-dashboard" containing the full workflow UI
```

The dashboard provides:
- **Workflow steps**: Scan → Audit Packet → Remediation Plan → Tickets (dry-run) → Approve → Execute
- **Findings table** with severity, scanner, file, and SOC2 control mappings
- **Evidence panel** with scanner statuses, coverage (scanner reach), ROI estimates, and manifest
- **Audit log viewer** with hash-chain verification

If `GH_TOKEN` is not set, ticket creation buttons are disabled with a clear message.

#### Demo Fixture Generator

Create a self-contained demo repo with intentional findings for all 3 scanners:

```bash
# Via MCP tool
compliance.create_demo_fixture({ outputDir: "/tmp/demo-repo" })

# Then scan it
compliance.scan_repo({ repoPath: "/tmp/demo-repo" })
```

Generates fake AWS keys (gitleaks), vulnerable npm deps (npm audit), insecure Terraform + Dockerfile (checkov). All secrets are clearly marked TEST ONLY.

#### Security Model

These invariants hold for every scan:

1. **Commands are argv-validated before execution.** Only 6 regex patterns pass the allowlist: `gitleaks detect`, `npm audit`, `checkov -d`, and their `--version` probes. Everything else throws.
2. **No arbitrary shell evaluation.** On Linux/macOS, scanners spawn with `shell: false` (direct exec). On Windows, `shell: true` is required for `.cmd` resolution but `windowsVerbatimArguments: true` prevents injection. The manifest records which mode was used.
3. **All writes are confined to `<repo>/.compliance/`.** The path policy validates every write target against the repo root. Directory traversal (`../`) is blocked.
4. **Hash-chained audit log with built-in verifier.** Every tool invocation (start, end, command run, file written) is logged to `logs/compliance-audit-chain.jsonl` with SHA-256 hash chaining. Each entry includes `prevHash` and `hash`. The `compliance.verify_audit_chain` tool recomputes every hash and reports PASS/FAIL with the first broken line.
5. **Self-documenting manifest.** Every audit packet includes `manifest.json` recording: allowed commands, shell execution mode, excluded scan paths, scanner versions, OS, Node version, and repo commit hash. The packet is reviewable without access to the server code.

#### Output Structure

```
<repo>/.compliance/
  runs/<runId>/
    scan_result.json          # Full scan data
    evidence/
      gitleaks.json           # Raw scanner output
      npm-audit.json
      checkov.json
    audit_packet/
      index.md                # Executive summary + scorecard
      findings.json           # Normalized findings
      coverage.json           # SOC2 control coverage
      roi.json                # ROI estimate
      manifest.json           # Deterministic export metadata + security policy
      evidence/               # Copies of raw outputs
  approvals/
    pending/<planId>.json     # Dry-run ticket plans awaiting approval
    approved/<planId>.json    # Approved plans (hash-verified at execution time)
```

### 5. `task-bridge` (Planned)
Task management system:
- `create_task()`, `update_task()`, `list_tasks()`
- Progress tracking and dependencies
- Background task monitoring

### 6. `search-bridge` (Planned)
Advanced code search:
- `grep_search()` - Content search with regex
- `code_analysis()` - Semantic code understanding
- Multi-file refactoring support

## Quick Start

### Prerequisites
- Claude Desktop with MCP support
- Node.js 18+ or Python 3.8+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/rblake2320/claude-desktop-mcp-bridge.git
cd claude-desktop-mcp-bridge

# Install dependencies
npm install  # or pip install -r requirements.txt

# Build MCP servers
npm run build

# Configure Claude Desktop
# Add to your Claude Desktop MCP settings:
{
  "mcpServers": {
    "filesystem-bridge": {
      "command": "node",
      "args": ["./dist/filesystem-bridge.js"],
      "env": {
        "ALLOWED_PATHS": "/path/to/your/projects"
      }
    },
    "shell-bridge": {
      "command": "node",
      "args": ["./dist/shell-bridge.js"]
    },
    "skills-bridge": {
      "command": "node",
      "args": ["./dist/skills-bridge.js"]
    }
  }
}
```

## Development

### Repository Structure
```
claude-desktop-mcp-bridge/
├── src/
│   ├── filesystem-bridge/    # File operations MCP server
│   ├── shell-bridge/         # Shell command MCP server
│   ├── skills-bridge/        # Skills library MCP server
│   ├── compliance-bridge/    # SOC2 audit engine (gitleaks + npm audit + checkov)
│   │   ├── server.ts         # MCP server with 8 tools
│   │   ├── contracts.ts      # All TypeScript types
│   │   ├── schemas.ts        # Zod validation schemas
│   │   ├── ticket-writer.ts  # GitHub Issues integration (dry-run/approve/execute)
│   │   ├── normalizers/      # Scanner output parsers (gitleaks, npm-audit, checkov)
│   │   ├── soc2-map.ts       # 20-control SOC2 mapping
│   │   ├── roi.ts            # ROI estimation model
│   │   └── audit-packet.ts   # Structured audit-support packet generator
│   ├── task-bridge/          # Task management MCP server
│   └── shared/               # Shared utilities (command-allowlist, path-policy, audit-chain)
├── .gitleaks.toml            # Gitleaks exclusion config (dist/, node_modules/)
├── .gitleaksignore           # Fingerprint-based false positive suppression
├── tests/                    # Test suites
├── docs/                     # Documentation
├── examples/                 # Example configurations
└── scripts/                  # Build and deployment scripts
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Commit: `git commit -m 'Add amazing feature'`
5. Push: `git push origin feature/amazing-feature`
6. Open a Pull Request

## Roadmap

- [ ] **Phase 1**: Basic filesystem and shell MCP servers
- [ ] **Phase 2**: Skills library integration
- [ ] **Phase 3**: Task management system
- [ ] **Phase 4**: Advanced search and code analysis
- [ ] **Phase 5**: Persistent memory and learning
- [ ] **Phase 6**: Docker and remote system support

## Security Considerations

- 🔒 **Principle of least privilege**: Configurable allowed paths and commands
- 🛡️ **Input validation**: All user inputs sanitized and validated
- ⏱️ **Timeouts**: Commands have configurable execution timeouts
- 📝 **Audit logging**: All operations logged for security review
- 🚫 **Safe defaults**: Read-only mode by default, write access requires explicit configuration

## 🏪 Skill Marketplace Ready

This bridge includes **dynamic skill loading infrastructure** designed for security-first skill marketplaces.

### Trust Levels & Security Model

Our security-first approach uses **trust-based quarantine** to safely integrate community skills:

| Trust Level | Description | Approval Required | Resource Limits | Example |
|-------------|-------------|-------------------|-----------------|---------|
| **🔒 SYSTEM** | Built-in core functionality | None | Unlimited | Ultra Frontend, Master Debugger |
| **✅ VERIFIED** | Digitally signed trusted skills | None | Standard (64MB, 30s) | json-formatter |
| **⚠️ UNTRUSTED** | Community contributions | **User approval** | Strict (128MB, 45s) | url-checker |

### Directory Structure

Skills live in a standardized directory structure with automatic discovery:

```
~/.claude/skills/
├── .approvals/           # Approval workflow state
├── .cache/              # Discovery and validation cache
├── built-in/            # Legacy 22-skill library (preserved)
├── verified/            # Signed, trusted skills
│   └── json-formatter/  # ✅ Example: loads immediately
│       ├── skill-manifest.json
│       └── skill.ts
├── untrusted/           # Community skills requiring approval
│   └── url-checker/     # ⚠️ Example: requires user approval
│       ├── skill-manifest.json
│       └── skill.ts
└── README.md           # Golden-path examples and documentation
```

### Approval Workflow

The trust system provides **safe community skill integration**:

1. **Discovery**: Skills auto-discovered from `verified/` and `untrusted/` directories
2. **Security Scan**: Code analyzed for dangerous patterns (eval, exec, file deletion)
3. **Trust Validation**: Signatures checked, resource limits applied
4. **Approval Gate**: UNTRUSTED skills prompt user before loading
5. **Runtime Isolation**: Each skill runs in controlled environment

**VERIFIED skills** load immediately, **UNTRUSTED skills** require one-time user approval.

### Quick Start: Create Your First Skill

```bash
# 1. Copy the golden-path example
mkdir -p ~/.claude/skills/verified/my-skill
cp ~/.claude/skills/verified/json-formatter/* ~/.claude/skills/verified/my-skill/

# 2. Edit the manifest
cat > ~/.claude/skills/verified/my-skill/skill-manifest.json << 'EOF'
{
  "name": "my-skill",
  "version": "1.0.0",
  "author": "Your Name",
  "trust_level": "verified",
  "capabilities": ["my-capability"],
  "required_permissions": ["read:text", "write:text"],
  "resource_limits": {
    "max_memory_mb": 64,
    "timeout_seconds": 30,
    "max_network_requests": 0
  },
  "description": "My awesome skill",
  "triggers": ["my skill", "help me"]
}
EOF

# 3. Write the implementation
cat > ~/.claude/skills/verified/my-skill/skill.ts << 'EOF'
export default function mySkill(action: string, ...args: string[]) {
  if (action === 'greet') {
    return `Hello ${args.join(' ')}! This is my custom skill.`;
  }
  return 'Available actions: greet <name>';
}
EOF

# 4. Update integrity hash
cd ~/.claude/skills
node -e "
  const crypto = require('crypto');
  const fs = require('fs');
  const manifest = JSON.parse(fs.readFileSync('verified/my-skill/skill-manifest.json'));
  const skillCode = fs.readFileSync('verified/my-skill/skill.ts');
  manifest.integrity_hash = crypto.createHash('sha256').update(skillCode).digest('hex');
  fs.writeFileSync('verified/my-skill/skill-manifest.json', JSON.stringify(manifest, null, 2));
  console.log('✅ Skill ready!');
"

# 5. Test with skill doctor
./verify-examples.sh  # Validates your new skill
```

### Security Model Rationale

**Why trust-based quarantine?**

- **🔒 Low-Friction Trusted Skills**: SYSTEM and VERIFIED skills never prompt users
- **🚀 Innovation Friendly**: Community can contribute UNTRUSTED skills freely
- **🛡️ User Control**: Clear approval workflow for risky operations
- **📈 Scalable**: Router pattern enables unlimited skills without context bloat
- **🏪 Marketplace Ready**: Foundation for skill publishers and monetization

### Infrastructure

**Backwards Compatible**: All 22 legacy skills preserved and enhanced
**Router Pattern**: Skills loaded on-demand, preventing context overflow
**Cache System**: Fast discovery with SQLite + FTS5 memory engine
**Audit Trail**: All skill operations logged for compliance
**Resource Management**: Configurable limits per trust level

### Integration Points

Ready for skill marketplace publishers:

```javascript
// Skill discovery API
const skills = await discoverSkills(['verified', 'untrusted']);

// Trust validation
const trustStatus = await validateSkillTrust(skillPath);

// Runtime isolation
const result = await executeSkill(skillName, args, {
  memoryLimit: '64MB',
  timeout: 30000,
  networkAccess: false
});
```

**Learn More**:
- [Skill Examples Guide](~/.claude/skills/SKILL_EXAMPLES_GUIDE.md)
- [Skill Doctor CLI](~/.claude/skills/verify-examples.sh)
- [Dynamic Loading Tests](~/.claude/skills/test-skill-loading.js)

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/rblake2320/claude-desktop-mcp-bridge/issues)
- 💬 [Discussions](https://github.com/rblake2320/claude-desktop-mcp-bridge/discussions)

## Inspiration

This project was inspired by the realization that if Claude Desktop can access Docker, there's no technical reason it can't have the same capabilities as Claude Code through MCP. Let's bridge that gap!

---

⭐ **Star this repository if you want Claude Desktop to have Claude Code capabilities!**