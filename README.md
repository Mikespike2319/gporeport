# Windows Policy Audit Tool

A comprehensive Windows policy audit script that identifies **ALL** policies applied to a machine from **GPO**, **MECM**, **Intune**, and other sources, with detailed reporting on what features each policy controls.

## Overview

This tool performs an in-depth audit of Windows policies and configurations, identifying:
- **Policy Source**: Whether policies come from Group Policy (GPO), Microsoft Endpoint Configuration Manager (MECM/SCCM), Microsoft Intune (MDM), or local settings
- **Policy Details**: Name, category, current value, and registry location
- **Impact Analysis**: What features are being enabled/disabled by each policy
- **Comprehensive Coverage**: Audits 11 major policy categories

## Features

### Policy Sources Detected
- ✅ **Group Policy Objects (GPO)** - Active Directory domain policies
- ✅ **Microsoft Intune / MDM** - Cloud-based mobile device management
- ✅ **MECM / SCCM** - Configuration Manager policies
- ✅ **Local Group Policy** - Machine-specific policies

### Policy Categories Audited

1. **Windows Update Policies**
   - Defer feature/quality updates
   - Target release version pinning
   - Auto-update configuration
   - WSUS server settings

2. **Device Control Policies**
   - USB storage restrictions
   - Removable media access control (read/write/execute)
   - Device installation restrictions
   - USBSTOR service status

3. **Security Policies**
   - Credential Guard / Virtualization-based Security
   - Windows Defender configuration
   - SmartScreen filter
   - Windows Hello for Business
   - Lock screen settings

4. **Network Policies**
   - Network connectivity probes
   - Multiple connection settings
   - DNS client configuration
   - Network isolation

5. **Application Control**
   - Software Restriction Policies (SRP)
   - AppLocker rules and enforcement
   - Executable/DLL/Script restrictions

6. **BitLocker Policies**
   - TPM requirements
   - Encryption methods
   - Recovery password requirements

7. **Firewall Policies**
   - Firewall state per profile (Domain/Private/Public)
   - Default inbound/outbound actions
   - Profile-specific configurations

8. **User Experience Policies**
   - Action Center settings
   - Consumer features
   - Telemetry levels
   - Drive visibility

9. **Power Management**
   - AC/Battery power settings
   - Sleep/hibernate configurations

10. **System Policies**
    - Script execution
    - App privacy (camera, microphone, etc.)
    - Disk quotas

11. **Other Policies**
    - Additional system configurations

## Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Standard domain user account (no admin required for most checks)
- **Execution Policy**: Script will bypass execution policy automatically

## Installation

1. Download all files to a directory on your Windows machine
2. Ensure both `PolicyAudit.bat` and `PolicyAuditModule.ps1` are in the same folder
3. No additional installation required

## Usage

### Basic Usage

Simply double-click `PolicyAudit.bat` or run from command line:

```batch
PolicyAudit.bat
```

This will:
- Scan all policy categories
- Display results in the console
- Export a detailed report to your Desktop

### Command-Line Options

```batch
PolicyAudit.bat [options]

Options:
  /full     - Include all policy categories (default)
  /export   - Export report to Desktop (default: enabled)
  /verbose  - Show detailed output during scan
```

### Examples

```batch
# Full audit with export (default)
PolicyAudit.bat

# Full audit with verbose output
PolicyAudit.bat /verbose

# Full audit only
PolicyAudit.bat /full
```

## Output

### Console Output

The script provides color-coded output showing:
- **Cyan**: Group Policy (GPO) policies
- **Magenta**: Intune/MDM policies  
- **Yellow**: MECM/SCCM policies
- **Gray**: Local policies

For each policy, you'll see:
```
Policy: DeferFeatureUpdates
Source: GROUP POLICY (GPO)
Value: 1
Impact: Feature updates are deferred by 365 days
Description: Controls whether feature updates are deferred
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
```

### Exported Report

A text file is automatically exported to your Desktop:
```
PolicyAudit_Report_YYYYMMDD_HHMMSS.txt
```

The report includes:
- **Executive Summary**: Policy counts by source and category
- **Detailed Inventory**: Complete listing of all policies with full details
- **Impact Analysis**: Clear explanations of what each policy does

## Example Use Cases

### 1. Troubleshooting USB Blocks
**Problem**: USB drives not working on corporate laptop

**Solution**: Run the audit tool to identify:
- Which management system is blocking USB (GPO/Intune/MECM)
- Specific policies affecting USB storage
- Registry paths for verification

### 2. Auditing Update Policies
**Problem**: Machine not receiving Windows updates

**Solution**: Check the Windows Update section to see:
- If updates are deferred
- Target version pinning
- WSUS server configuration
- Which system applied the policy

### 3. Security Compliance Review
**Problem**: Need to verify security configurations

**Solution**: Review Security, BitLocker, and Firewall sections to confirm:
- Encryption requirements
- Defender status
- Firewall configurations
- Policy sources for audit trail

### 4. Intune vs GPO Conflict Resolution
**Problem**: Unclear which policy source is winning

**Solution**: The tool shows policy priority and source, helping identify:
- Duplicate policies from different sources
- Which source takes precedence
- ConfigSource IDs for Intune policies

## Understanding Policy Sources

### Group Policy (GPO)
- Applied via Active Directory
- Registry path contains `\Policies\`
- Typically managed by domain admins
- Highest traditional priority

### Intune / MDM
- Cloud-based management
- Registry path contains `PolicyManager`
- Includes `ConfigSource` identifier for policy assignment tracking
- Modern management approach

### MECM / SCCM
- On-premises Configuration Manager
- Registry paths contain `CCM`, `ConfigMgr`, or `SCCM`
- Enterprise systems management
- Comprehensive client management

### Local Policy
- Machine-specific settings
- May be set by local admin or other tools
- Lowest priority in conflict resolution

## Advanced Features

### Registry Path Inspection
Each policy shows its exact registry location, allowing:
- Manual verification via `regedit`
- Scripted queries for automation
- Troubleshooting policy application

### Impact Analysis
The tool explains what each policy actually does:
- ❌ "USB storage drivers DISABLED - USB storage completely blocked"
- ✅ "Firewall is ENABLED for Domain profile"
- ⚠️ "System is pinned to Windows version 22H2"

### ConfigSource Tracking (Intune)
For Intune policies, the tool captures ConfigSource values:
- Unique identifiers for policy assignments
- Helps Intune admins identify which profile applied the setting
- Useful for policy troubleshooting

## Limitations

- Some policies may require administrator privileges to read
- Event log analysis (if implemented) limited to last 7 days
- Script focuses on registry-based policies
- WMI-based policies not currently covered

## Troubleshooting

### Script Won't Run
**Issue**: "Execution policy" error

**Solution**: The batch file uses `-ExecutionPolicy Bypass` automatically. If still blocked, run PowerShell as admin:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### No Policies Found
**Issue**: Report shows 0 policies

**Possible Causes**:
- Machine not domain-joined (no GPO)
- Not enrolled in Intune or MECM
- Running on non-enterprise Windows edition
- Insufficient permissions to read registry

### Module Not Found Error
**Issue**: "PolicyAuditModule.ps1 not found"

**Solution**: Ensure both `.bat` and `.ps1` files are in the same directory

## File Structure

```
windows-policy-audit-tool/
├── PolicyAudit.bat           # Main launcher script
├── PolicyAuditModule.ps1     # PowerShell audit engine
├── README.md                 # This file
└── EXAMPLES.md               # Example output samples
```

## Contributing

This tool can be extended to cover:
- Additional policy categories
- Event log correlation
- WMI policy queries
- PowerShell DSC configurations
- Custom reporting formats (CSV, JSON, HTML)

## Version History

**v1.0** (Initial Release)
- Comprehensive policy audit across 11 categories
- Multi-source detection (GPO/Intune/MECM/Local)
- Color-coded console output
- Detailed text report export
- Impact analysis for each policy

## License

This tool is provided as-is for educational and administrative purposes.

## Related Documentation

- [Microsoft Group Policy Documentation](https://docs.microsoft.com/en-us/windows/client-management/group-policies)
- [Intune Configuration Policies](https://docs.microsoft.com/en-us/mem/intune/)
- [Configuration Manager Documentation](https://docs.microsoft.com/en-us/mem/configmgr/)

---

**Note**: This tool performs read-only operations and does not modify any policies or settings.
