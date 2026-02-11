# Claude Desktop Version Compatibility

## Overview

Claude Desktop has undergone significant changes in how it manages MCP servers across versions. This document covers the key differences and how `claude-desktop-mcp-bridge` handles them.

## Version Differences

### Claude Desktop "Classic" (pre-Cowork)
**Versions**: 1.x through early 2025 builds
**MCP Protocol**: `2024-11-05`
**Client Name**: `claude-ai`

| Behavior | Detail |
|----------|--------|
| **MCP Server CWD** | Project directory or user home directory |
| **Log creation** | `process.cwd()/logs/` works normally |
| **Config location** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **UI Tabs** | Chat only |
| **MCP startup** | Spawns `node` processes from a standard working directory |

### Claude Desktop with Cowork (2025+)
**Versions**: 1.2512+ (Windows), varies by platform
**MCP Protocol**: `2025-06-18`
**Client Name**: `claude-ai` version `0.1.0`

| Behavior | Detail |
|----------|--------|
| **MCP Server CWD** | `C:\WINDOWS\system32` (Windows) |
| **Log creation** | `process.cwd()/logs/` fails with `EPERM` |
| **Config location** | `%APPDATA%\Claude\claude_desktop_config.json` (unchanged) |
| **UI Tabs** | Chat, Code, Cowork (plan dependent) |
| **MCP startup** | Spawns `node` processes from the system directory |
| **New log files** | `cowork_vm_node.log` appears in Claude logs directory |

## Breaking Change: Working Directory

The most impactful change is the **MCP server working directory**.

**Before (Classic)**:
```
MCP Server CWD → C:\Users\you\claude-desktop-mcp-bridge\
                  └── logs/  ← created successfully
```

**After (Cowork)**:
```
MCP Server CWD → C:\WINDOWS\system32\
                  └── logs/  ← EPERM: operation not permitted
```

### Root Cause

Claude Desktop with Cowork runs MCP server processes from the system application directory rather than the project directory. Any code using `process.cwd()` to create files or directories will fail because the system directory is not writable by normal user processes.

### How We Fixed It

All 3 bridges use `import.meta.url` to resolve the script's actual filesystem location instead of relying on `process.cwd()`:

```typescript
// Before (broken on Cowork):
private static logDir = join(process.cwd(), 'logs');

// After (works on both versions):
private static logDir = join(
  new URL('.', import.meta.url).pathname.replace(/^\/([A-Z]:)/i, '$1'),
  '..', '..', 'logs'
);
```

With a fallback to the system temp directory if the project directory is not writable:

```typescript
static init() {
  try {
    mkdirSync(logDir, { recursive: true });
  } catch {
    // Fallback to %TEMP%/claude-mcp-bridge-logs/
    logDir = join(process.env.TEMP || '/tmp', 'claude-mcp-bridge-logs');
    mkdirSync(logDir, { recursive: true });
  }
}
```

## Configuration

The `claude_desktop_config.json` format is the same across both versions. Use **absolute paths** for the `args` field to avoid CWD-dependent resolution:

```json
{
  "mcpServers": {
    "filesystem-bridge": {
      "command": "node",
      "args": [
        "C:/Users/you/claude-desktop-mcp-bridge/dist/filesystem-bridge/server.js"
      ],
      "env": {
        "ALLOWED_PATHS": "C:/Users/you",
        "READ_ONLY": "false",
        "MAX_FILE_SIZE": "10485760"
      }
    },
    "shell-bridge": {
      "command": "node",
      "args": [
        "C:/Users/you/claude-desktop-mcp-bridge/dist/shell-bridge/server.js"
      ],
      "env": {
        "TIMEOUT": "30000",
        "BLOCKED_COMMANDS": "rm,rmdir,del,format,fdisk,mkfs,dd,shutdown,reboot,taskkill,net"
      }
    },
    "skills-bridge": {
      "command": "node",
      "args": [
        "C:/Users/you/claude-desktop-mcp-bridge/dist/skills-bridge/server.js"
      ],
      "env": {
        "SKILLS_PATH": "~/.claude/skills/",
        "TIMEOUT": "60000"
      }
    }
  }
}
```

**Key rule**: Always use absolute paths in `args`. Relative paths resolve from the MCP server's CWD, which differs between Claude Desktop versions.

## Diagnosing Issues

### Check MCP server logs

Logs are stored at:
```
%APPDATA%\Claude\logs\
├── mcp-server-filesystem-bridge.log
├── mcp-server-shell-bridge.log
├── mcp-server-skills-bridge.log
└── cowork_vm_node.log           ← Only present on Cowork version
```

### Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `EPERM: operation not permitted, mkdir 'C:\WINDOWS\system32\logs'` | CWD is system32 (Cowork version) | Update to latest bridge version (v0.2.0+) |
| `Server disconnected` in Claude Desktop UI | Bridge crashed on startup | Check MCP logs above for the specific error |
| `Cannot find module` | Relative path in config resolved from wrong CWD | Use absolute paths in `claude_desktop_config.json` |

### Verify your Claude Desktop version

1. Open Claude Desktop
2. Check for the presence of a **Cowork** tab alongside Chat and Code
3. Check `%APPDATA%\Claude\logs\` for `cowork_vm_node.log` — its presence indicates the Cowork version
4. Check MCP logs for `protocolVersion` — `2025-06-18` indicates Cowork, `2024-11-05` indicates Classic

### Test bridges manually

You can verify bridges work from any working directory:

```bash
# Simulate Cowork's CWD by running from system32
cd C:\WINDOWS\system32
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | node "C:/Users/you/claude-desktop-mcp-bridge/dist/skills-bridge/server.js"
```

If you see a JSON response with `serverInfo`, the bridge is working correctly.

## Minimum Supported Versions

| Component | Minimum Version |
|-----------|----------------|
| Node.js | 18.0+ (ESM with `import.meta.url` support) |
| Claude Desktop (Classic) | Any version with MCP support |
| Claude Desktop (Cowork) | 1.2512+ (tested) |
| Windows | 10/11 |
| macOS | Catalina+ (untested, should work) |
| Linux | Any with Node.js 18+ (untested) |

## Bridge Version History

| Version | Claude Desktop Support | Key Changes |
|---------|----------------------|-------------|
| 0.1.0 | Classic only | Initial release, `process.cwd()` for logs |
| 0.2.0 | Classic + Cowork | `import.meta.url` path resolution, TEMP fallback, security hardening |
