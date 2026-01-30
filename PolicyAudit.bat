@echo off
REM Windows Policy Audit Tool
REM Scans GPO, Intune, MECM, and local policies on Windows machines
REM
REM Usage:
REM   PolicyAudit.bat [/comprehensive] [/output "path"] [/verbose]
REM
REM Options:
REM   /comprehensive - Scan all registry policies (recommended for complete audit)
REM   /output "path" - Save report to specific folder
REM   /verbose       - Show detailed output

setlocal

set "MODE=full"
set "EXPORT=true"
set "VERBOSE=false"
set "OUTPUT_PATH="

:parse_args
if "%~1"=="" goto :end_parse
if /i "%~1"=="/comprehensive" set "MODE=comprehensive"
if /i "%~1"=="/output" (
    set "OUTPUT_PATH=%~2"
    shift
)
if /i "%~1"=="/verbose" set "VERBOSE=true"
shift
goto :parse_args
:end_parse

echo.
echo Windows Policy Audit Tool
echo ========================
echo Scanning policies...
echo.

where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PowerShell not found. This script requires PowerShell 5.1+
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"

if not exist "%SCRIPT_DIR%PolicyAuditModule.ps1" (
    echo ERROR: PolicyAuditModule.ps1 not found. Keep both files together.
    pause
    exit /b 1
)


powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%PolicyAuditModule.ps1" -Mode "%MODE%" -Export "%EXPORT%" -OutputPath "%OUTPUT_PATH%" -Verbose "%VERBOSE%"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Audit failed.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Done! Report saved.
if "%EXPORT%"=="true" echo Check your output location for the HTML report.
echo.
pause

endlocal
exit /b 0
