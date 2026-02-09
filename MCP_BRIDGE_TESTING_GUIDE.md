# MCP Bridge Testing Guide for Claude Desktop

## Current Status
✅ **Configuration Added**: MCP bridge servers added to Claude Desktop config at:
`C:\Users\techai\AppData\Roaming\Claude\claude_desktop_config.json`

✅ **Backup Created**: Original config backed up to:
`C:\Users\techai\AppData\Roaming\Claude\claude_desktop_config_backup.json`

✅ **Test Files Created**: Test files available in:
`C:\Users\techai\claude-desktop-mcp-bridge\test-files\`

## Configuration Details

### filesystem-bridge
- **Server Path**: `C:/Users/techai/claude-desktop-mcp-bridge/dist/filesystem-bridge/server.js`
- **Allowed Paths**: `C:/Users/techai,C:/Users/techai/claude-desktop-mcp-bridge`
- **Read Only**: `false` (read/write enabled)
- **Max File Size**: `10MB`

### shell-bridge
- **Server Path**: `C:/Users/techai/claude-desktop-mcp-bridge/dist/shell-bridge/server.js`
- **Timeout**: `30 seconds`
- **Blocked Commands**: `rm,rmdir,del,format,fdisk,mkfs,dd,shutdown,reboot,taskkill,net`

## Testing Steps

### Step 1: Restart Claude Desktop
1. Close all Claude Desktop windows
2. Wait 5 seconds for processes to fully terminate
3. Launch Claude Desktop fresh
4. Check that no errors appear in the interface

### Step 2: Verify MCP Tools Are Available
In Claude Desktop, the following tools should now be available:

#### filesystem-bridge tools:
- `read_file` - Read file contents
- `write_file` - Write new files
- `edit_file` - Edit existing files with find/replace
- `glob_search` - Search files by patterns

#### shell-bridge tools:
- `run_command` - Execute shell commands
- `get_current_directory` - Get current working directory
- `change_directory` - Change working directory

### Step 3: Test filesystem-bridge Tools

#### Test 1: read_file
**Prompt**:
```
Use the read_file tool to read the contents of:
C:/Users/techai/claude-desktop-mcp-bridge/test-files/test-read.txt
```

**Expected Result**: File contents should be displayed

#### Test 2: write_file
**Prompt**:
```
Use the write_file tool to create a new file at:
C:/Users/techai/claude-desktop-mcp-bridge/test-files/new-test.txt

Content: "This file was created by Claude Desktop using the filesystem-bridge MCP server!"
```

**Expected Result**: New file should be created

#### Test 3: edit_file
**Prompt**:
```
Use the edit_file tool to modify:
C:/Users/techai/claude-desktop-mcp-bridge/test-files/test-edit.txt

Find: "Replace this line with something else."
Replace with: "This line was replaced by Claude Desktop!"
```

**Expected Result**: File should be modified with the replacement

#### Test 4: glob_search
**Prompt**:
```
Use the glob_search tool to find all JavaScript files in:
C:/Users/techai/claude-desktop-mcp-bridge/test-files/

Pattern: *.js
```

**Expected Result**: Should find glob-test-1.js and glob-test-2.js

### Step 4: Test shell-bridge Tools

#### Test 1: get_current_directory
**Prompt**:
```
Use the get_current_directory tool to show the current working directory.
```

**Expected Result**: Should display current directory path

#### Test 2: run_command (safe command)
**Prompt**:
```
Use the run_command tool to list files in the test directory:
dir C:\Users\techai\claude-desktop-mcp-bridge\test-files
```

**Expected Result**: Should list the test files we created

#### Test 3: change_directory
**Prompt**:
```
Use the change_directory tool to change to:
C:/Users/techai/claude-desktop-mcp-bridge

Then use get_current_directory to confirm the change.
```

**Expected Result**: Directory should change and be confirmed

#### Test 4: run_command (blocked command test)
**Prompt**:
```
Use the run_command tool to run: del test.txt
```

**Expected Result**: Should be blocked due to security restrictions

## Comparison with Claude Code

### Equivalent Functionality Check
Test that these MCP bridge tools work like Claude Code's equivalents:

1. **read_file** → Should work like Claude Code's `Read` tool
2. **write_file** → Should work like Claude Code's `Write` tool
3. **edit_file** → Should work like Claude Code's `Edit` tool
4. **glob_search** → Should work like Claude Code's `Glob` tool
5. **run_command** → Should work like Claude Code's `Bash` tool
6. **get_current_directory** → Should work like `pwd` in Claude Code
7. **change_directory** → Should work like `cd` in Claude Code

## Troubleshooting

### If Tools Don't Appear
1. **Check config syntax**:
   ```bash
   python C:/Users/techai/validate_config.py
   ```

2. **Check server files exist**:
   ```bash
   ls -la C:/Users/techai/claude-desktop-mcp-bridge/dist/*/server.js
   ```

3. **Test server startup manually**:
   ```bash
   node C:/Users/techai/claude-desktop-mcp-bridge/dist/filesystem-bridge/server.js
   ```

### If Permission Errors
1. Check `ALLOWED_PATHS` environment variable
2. Ensure paths use forward slashes in config
3. Verify Node.js can access the file paths

### If Commands Are Blocked
1. Check `BLOCKED_COMMANDS` in shell-bridge config
2. Verify command isn't in the blocked list
3. Check command timeout settings

## Cleanup Instructions

To remove the MCP bridge servers:
1. Restore backup config:
   ```bash
   cp /c/Users/techai/AppData/Roaming/Claude/claude_desktop_config_backup.json /c/Users/techai/AppData/Roaming/Claude/claude_desktop_config.json
   ```
2. Restart Claude Desktop

## Success Criteria

✅ **Configuration loads without errors**
✅ **All 7 tools are available in Claude Desktop**
✅ **filesystem tools can read, write, edit, and search files**
✅ **shell tools can execute commands and manage directories**
✅ **Security restrictions work (blocked commands fail)**
✅ **Performance is comparable to Claude Code tools**
✅ **No crashes or unexpected errors**

## Next Steps After Testing

1. Document any issues found
2. Compare performance with Claude Code equivalents
3. Test edge cases (large files, special characters, etc.)
4. Consider implementing skills-bridge server
5. Create user documentation for deployment