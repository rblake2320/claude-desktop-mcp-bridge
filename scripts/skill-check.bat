@echo off
REM Skill Doctor Windows Batch Wrapper
REM Usage: skill-check.bat "C:\path\to\skill"

if "%~1"=="" (
    echo Usage: %~nx0 "path\to\skill"
    echo.
    echo Examples:
    echo   %~nx0 "%USERPROFILE%\.claude\skills\verified\json-formatter"
    echo   %~nx0 "%USERPROFILE%\.claude\skills\untrusted"
    exit /b 1
)

node "%~dp0skill-doctor.js" %*