@echo off
REM ============================================================================
REM Windows Policy Audit Tool
REM ============================================================================
REM 
REM SYNOPSIS:
REM     Comprehensive policy audit script that identifies ALL policies applied
REM     to a Windows machine from GPO, MECM, Intune, and other sources.
REM
REM DESCRIPTION:
REM     This script performs a deep audit of:
REM     - Group Policy Objects (GPO) from Active Directory
REM     - Microsoft Endpoint Configuration Manager (MECM/SCCM) policies
REM     - Microsoft Intune (MDM) policies
REM     - Local Group Policy
REM     - Registry-based policies
REM     
REM     For each policy found, it reports:
REM     - Policy source (GPO/MECM/Intune/Local)
REM     - Policy name and category
REM     - Current value/state
REM     - What features are enabled/disabled by the policy
REM     - Registry path where policy is stored
REM
REM REQUIREMENTS:
REM     - Windows 10/11 or Windows Server 2016+
REM     - PowerShell 5.1 or higher
REM     - Standard domain user account (no admin required for most checks)
REM
REM USAGE:
REM     PolicyAudit.bat [options]
REM     
REM     Options:
REM       /full     - Include all policy categories (default)
REM       /export   - Export report to Desktop
REM       /verbose  - Show detailed output
REM
REM ============================================================================

setlocal enabledelayedexpansion

REM Check for parameters
set "MODE=full"
set "EXPORT=true"
set "VERBOSE=false"

:parse_args
if "%~1"=="" goto :end_parse
if /i "%~1"=="/full" set "MODE=full"
if /i "%~1"=="/export" set "EXPORT=true"
if /i "%~1"=="/verbose" set "VERBOSE=true"
shift
goto :parse_args
:end_parse

echo.
echo ============================================================================
echo                    WINDOWS POLICY AUDIT TOOL
echo ============================================================================
echo.
echo Analyzing all policies applied to this machine...
echo This may take a few minutes...
echo.

REM Check if PowerShell is available
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PowerShell is not available on this system.
    echo This script requires PowerShell 5.1 or higher.
    pause
    exit /b 1
)

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Check if the PowerShell module exists
if not exist "%SCRIPT_DIR%PolicyAuditModule.ps1" (
    echo ERROR: PolicyAuditModule.ps1 not found in script directory.
    echo Please ensure all files are in the same directory.
    pause
    exit /b 1
)

REM Run the PowerShell audit script
echo Starting comprehensive policy audit...
echo.

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%PolicyAuditModule.ps1" -Mode "%MODE%" -Export "%EXPORT%" -Verbose "%VERBOSE%"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ============================================================================
    echo ERROR: Policy audit encountered an error.
    echo ============================================================================
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo                        AUDIT COMPLETE
echo ============================================================================
echo.
if "%EXPORT%"=="true" (
    echo Report has been exported to your Desktop.
    echo.
)
echo Press any key to exit...
pause >nul

endlocal
exit /b 0
