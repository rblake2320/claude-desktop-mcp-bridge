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

### 1. 📁 `filesystem-bridge`
Exposes Claude Code's file operations:
- `read_file()` - Read any file with line numbers
- `write_file()` - Create new files
- `edit_file()` - Exact string replacements
- `glob_search()` - Pattern-based file finding

### 2. 🖥️ `shell-bridge`
Provides secure shell access:
- `run_command()` - Execute bash/cmd commands
- `run_background()` - Background process management
- Safety controls and timeouts

### 3. 🧠 `skills-bridge`
Exposes Claude Code's 22-skill library:
- Ultra Frontend/Backend/CSS/Fullstack
- Master Debugger, Ultra Architect
- AI Agent Builder, LLM Trainer
- All specialized development skills

### 4. 📋 `task-bridge`
Task management system:
- `create_task()`, `update_task()`, `list_tasks()`
- Progress tracking and dependencies
- Background task monitoring

### 5. 🔍 `search-bridge`
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