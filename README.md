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

### 4. 📋 `task-bridge` (Planned)
Task management system:
- `create_task()`, `update_task()`, `list_tasks()`
- Progress tracking and dependencies
- Background task monitoring

### 5. 🔍 `search-bridge` (Planned)
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
│   ├── task-bridge/          # Task management MCP server
│   └── shared/               # Shared utilities
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

This bridge includes production-ready **dynamic skill loading infrastructure** designed for security-first skill marketplaces and enterprise deployment.

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

- **🔒 Enterprise Safe**: SYSTEM and VERIFIED skills never prompt users
- **🚀 Innovation Friendly**: Community can contribute UNTRUSTED skills freely
- **🛡️ User Control**: Clear approval workflow for risky operations
- **📈 Scalable**: Router pattern enables unlimited skills without context bloat
- **🏪 Marketplace Ready**: Foundation for skill publishers and monetization

### Production Infrastructure

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