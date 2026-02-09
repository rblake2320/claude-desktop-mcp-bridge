#!/bin/bash

# Claude Desktop MCP Bridge Setup Script

set -e

echo "🚀 Setting up Claude Desktop MCP Bridge..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed. Please install Node.js 18+ first."
    exit 1
fi

echo "✅ Node.js found: $(node --version)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build the project
echo "🔨 Building TypeScript..."
npm run build

# Create example config directory
mkdir -p examples/configs

# Detect OS and provide appropriate config path
if [[ "$OSTYPE" == "darwin"* ]]; then
    CONFIG_PATH="~/Library/Application Support/Claude/claude_desktop_config.json"
    echo "🍎 macOS detected"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    CONFIG_PATH="%APPDATA%\\Claude\\claude_desktop_config.json"
    echo "🪟 Windows detected"
else
    CONFIG_PATH="~/.config/Claude/claude_desktop_config.json"
    echo "🐧 Linux detected"
fi

# Get absolute path to project
PROJECT_PATH=$(pwd)

echo ""
echo "✅ Build complete!"
echo ""
echo "📝 Next steps:"
echo "1. Copy the example configuration to your Claude Desktop config:"
echo "   Config file location: $CONFIG_PATH"
echo ""
echo "2. Update the paths in the config to point to this project:"
echo "   Replace './dist/filesystem-bridge/server.js' with:"
echo "   '$PROJECT_PATH/dist/filesystem-bridge/server.js'"
echo ""
echo "3. Update ALLOWED_PATHS to your project directories"
echo ""
echo "4. Restart Claude Desktop"
echo ""
echo "🎉 You should then see the new tools available in Claude Desktop:"
echo "   - read_file, write_file, edit_file, glob_search"
echo "   - run_command, run_background, get_current_directory, change_directory"
echo ""

# Optionally copy config template with updated paths
cat > examples/configs/claude-desktop-config-$(hostname).json << EOF
{
  "mcpServers": {
    "filesystem-bridge": {
      "command": "node",
      "args": ["$PROJECT_PATH/dist/filesystem-bridge/server.js"],
      "env": {
        "ALLOWED_PATHS": "$HOME/projects,$HOME/Documents",
        "READ_ONLY": "false",
        "MAX_FILE_SIZE": "10485760"
      }
    },
    "shell-bridge": {
      "command": "node",
      "args": ["$PROJECT_PATH/dist/shell-bridge/server.js"],
      "env": {
        "TIMEOUT": "120000",
        "BLOCKED_COMMANDS": "rm,rmdir,del,format,fdisk,sudo"
      }
    }
  }
}
EOF

echo "📁 Created personalized config at: examples/configs/claude-desktop-config-$(hostname).json"
echo "   You can copy this directly to your Claude Desktop config file."