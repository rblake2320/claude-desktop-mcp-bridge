@echo off
setlocal EnableDelayedExpansion

echo 🚀 Setting up Claude Desktop MCP Bridge...

REM Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Node.js is required but not installed. Please install Node.js 18+ first.
    pause
    exit /b 1
)

for /f %%i in ('node --version') do set NODE_VERSION=%%i
echo ✅ Node.js found: %NODE_VERSION%

REM Install dependencies
echo 📦 Installing dependencies...
call npm install
if %errorlevel% neq 0 (
    echo ❌ npm install failed
    pause
    exit /b 1
)

REM Build the project
echo 🔨 Building TypeScript...
call npm run build
if %errorlevel% neq 0 (
    echo ❌ Build failed
    pause
    exit /b 1
)

REM Create example config directory
if not exist examples\configs mkdir examples\configs

REM Get absolute path to project
set PROJECT_PATH=%CD%

echo.
echo ✅ Build complete!
echo.
echo 📝 Next steps:
echo 1. Copy the example configuration to your Claude Desktop config:
echo    Config file location: %%APPDATA%%\Claude\claude_desktop_config.json
echo.
echo 2. Use this configuration (already updated with correct paths):
echo.

REM Create personalized config
(
echo {
echo   "mcpServers": {
echo     "filesystem-bridge": {
echo       "command": "node",
echo       "args": ["%PROJECT_PATH%\dist\filesystem-bridge\server.js"],
echo       "env": {
echo         "ALLOWED_PATHS": "%USERPROFILE%\Documents,%USERPROFILE%\Desktop\projects",
echo         "READ_ONLY": "false",
echo         "MAX_FILE_SIZE": "10485760"
echo       }
echo     },
echo     "shell-bridge": {
echo       "command": "node",
echo       "args": ["%PROJECT_PATH%\dist\shell-bridge\server.js"],
echo       "env": {
echo         "TIMEOUT": "120000",
echo         "BLOCKED_COMMANDS": "del,format,fdisk"
echo       }
echo     }
echo   }
echo }
) > examples\configs\claude-desktop-config-%COMPUTERNAME%.json

echo 📁 Created personalized config at: examples\configs\claude-desktop-config-%COMPUTERNAME%.json
echo.
echo 3. Update ALLOWED_PATHS to your actual project directories
echo 4. Restart Claude Desktop
echo.
echo 🎉 You should then see the new tools available in Claude Desktop:
echo    - read_file, write_file, edit_file, glob_search
echo    - run_command, run_background, get_current_directory, change_directory
echo.
pause