# Example Output

This document shows examples of what the Windows Policy Audit Tool reports for various policy scenarios.

## Table of Contents
- [Example 1: USB Blocking via Intune](#example-1-usb-blocking-via-intune)
- [Example 2: Windows Update Pinning via GPO](#example-2-windows-update-pinning-via-gpo)
- [Example 3: Mixed Policy Sources](#example-3-mixed-policy-sources)
- [Example 4: Full Report Sample](#example-4-full-report-sample)

---

## Example 1: USB Blocking via Intune

### Scenario
Corporate laptop with USB storage blocked by Intune MDM policy.

### Console Output
```
================================================================================
                    WINDOWS POLICY AUDIT TOOL
================================================================================
Computer: LAPTOP-ABC123
User: CONTOSO\jsmith
Date: 2026-01-30 15:30:00
Mode: full

[*] Starting policy audit...
[*] This may take a few minutes...

[*] Auditing Device Control Policies...

================================================================================
                        POLICY AUDIT SUMMARY
================================================================================

Total Policies Found: 8

Policies by Source:
  Intune: 5
  GPO: 2
  Local: 1

Policies by Category:
  Device Control: 5
  Security: 2
  Windows Update: 1

================================================================================
                     DETAILED POLICY ANALYSIS
================================================================================

>>> DEVICE CONTROL POLICIES (5) <<<
--------------------------------------------------------------------------------

Policy: Deny_Read_{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Source: INTUNE/MDM
Value: 1
Impact: READ access DENIED for device class: {53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Description: Controls read access to removable storage
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}

Policy: Deny_Write_{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Source: INTUNE/MDM
Value: 1
Impact: WRITE access DENIED for device class: {53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Description: Controls write access to removable storage
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}

Policy: Deny_Execute_{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Source: INTUNE/MDM
Value: 1
Impact: EXECUTE access DENIED for device class: {53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Description: Controls execute access to removable storage
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}

Policy: USBSTOR_Start
Source: INTUNE/MDM
Value: 4
Impact: USB storage drivers DISABLED - USB storage completely blocked
Description: Controls USB storage driver
Registry: HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR

Policy: DenyDeviceClasses
Source: INTUNE/MDM
Value: 1
Impact: Device installation restricted for specified classes
Description: Prevents installation of specific device classes
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage

[*] Audit complete!

Report exported to: C:\Users\jsmith\Desktop\PolicyAudit_Report_20260130_153045.txt
```

### Key Insights
- **All 5 USB-blocking policies** come from **Intune/MDM**
- No GPO or MECM involvement in USB blocking
- USBSTOR driver completely disabled (Value: 4)
- Both read and write access denied
- Contact **Intune admin** to modify policy

---

## Example 2: Windows Update Pinning via GPO

### Scenario
Desktop workstation pinned to Windows 10 22H2 via Group Policy.

### Console Output
```
>>> WINDOWS UPDATE POLICIES (7) <<<
--------------------------------------------------------------------------------

Policy: TargetReleaseVersion
Source: GROUP POLICY (GPO)
Value: 1
Impact: System is pinned to Windows version 22H2
Description: Pins Windows to a specific version
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Policy: TargetReleaseVersionInfo
Source: GROUP POLICY (GPO)
Value: 22H2
Impact: System is pinned to Windows version 22H2
Description: Specifies target Windows version
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Policy: DeferFeatureUpdates
Source: GROUP POLICY (GPO)
Value: 1
Impact: Feature updates are deferred by 365 days
Description: Controls whether feature updates are deferred
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Policy: DeferFeatureUpdatesPeriodInDays
Source: GROUP POLICY (GPO)
Value: 365
Impact: Feature updates are deferred by 365 days
Description: Number of days to defer feature updates
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Policy: DeferQualityUpdates
Source: GROUP POLICY (GPO)
Value: 1
Impact: Quality updates are deferred by 7 days
Description: Controls whether quality updates are deferred
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

Policy: AUOptions
Source: GROUP POLICY (GPO)
Value: 4
Impact: Auto download and schedule install
Description: Configures automatic update behavior
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU

Policy: WUServer
Source: GROUP POLICY (GPO)
Value: http://wsus.contoso.com:8530
Impact: Updates are managed through WSUS server: http://wsus.contoso.com:8530
Description: WSUS server for updates
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
```

### Key Insights
- **All Windows Update policies** enforced by **Group Policy (GPO)**
- System locked to **Windows 10 22H2**
- Updates managed through **internal WSUS server**
- Feature updates deferred for **365 days**
- Quality updates deferred for **7 days**
- Contact **AD Group Policy admin** to change version target

---

## Example 3: Mixed Policy Sources

### Scenario
Enterprise environment with overlapping policies from multiple sources.

### Console Output
```
================================================================================
                        POLICY AUDIT SUMMARY
================================================================================

Total Policies Found: 42

Policies by Source:
  Intune: 18
  GPO: 15
  MECM: 6
  Local: 3

Policies by Category:
  Security: 12
  Windows Update: 7
  Device Control: 8
  Network: 5
  Firewall: 6
  User Experience: 4

>>> SECURITY POLICIES (12) <<<
--------------------------------------------------------------------------------

Policy: EnableVirtualizationBasedSecurity
Source: GROUP POLICY (GPO)
Value: 1
Impact: Virtualization-based security is ENABLED (Credential Guard active)
Description: Enables Credential Guard and other VBS features
Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\System

Policy: DisableAntiSpyware
Source: INTUNE/MDM
Value: 0
Impact: Windows Defender is ENABLED
Description: Controls Windows Defender
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions

Policy: EnableSmartScreen
Source: INTUNE/MDM
Value: 1
Impact: SmartScreen filter is ENABLED
Description: Controls SmartScreen filter
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions

Policy: UsePassportForWork
Source: MECM/SCCM
Value: 1
Impact: Windows Hello for Business is ENABLED
Description: Controls Windows Hello for Business
Registry: HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\ActualConfig\UsePassportForWork

>>> FIREWALL POLICIES (6) <<<
--------------------------------------------------------------------------------

Policy: EnableFirewall_Domain
Source: GROUP POLICY (GPO)
Value: 1
Impact: Firewall is ENABLED for Domain profile
Description: Windows Firewall state for Domain profile
Registry: HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile

Policy: DefaultInboundAction_Domain
Source: GROUP POLICY (GPO)
Value: 1
Impact: Default BLOCK inbound connections for Domain profile
Description: Default inbound firewall action for Domain profile
Registry: HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile

Policy: EnableFirewall_Public
Source: INTUNE/MDM
Value: 1
Impact: Firewall is ENABLED for Public profile
Description: Windows Firewall state for Public profile
Registry: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall
```

### Key Insights
- **Three different management systems** active
- **GPO** manages VBS/Credential Guard and domain firewall
- **Intune** manages Defender, SmartScreen, and public firewall
- **MECM** manages Windows Hello for Business
- Policies are **complementary** (no conflicts detected)
- Enterprise has **hybrid management** approach

---

## Example 4: Full Report Sample

### Exported Text Report Excerpt

```
================================================================================
                    WINDOWS POLICY AUDIT REPORT
================================================================================
Generated: 2026-01-30 15:45:23
Computer: DESKTOP-XYZ789
User: CONTOSO\aadmin
Domain: CONTOSO

================================================================================
                            EXECUTIVE SUMMARY
================================================================================

Total Policies Found: 38

Policies by Source:
  - GPO: 22 policies
  - Intune: 11 policies
  - MECM: 3 policies
  - Local: 2 policies

Policies by Category:
  - Application Control: 2 policies
  - BitLocker: 3 policies
  - Device Control: 4 policies
  - Firewall: 6 policies
  - Network: 3 policies
  - Power Management: 2 policies
  - Security: 8 policies
  - System: 3 policies
  - User Experience: 2 policies
  - Windows Update: 5 policies

================================================================================
                     DETAILED POLICY INVENTORY
================================================================================

--------------------------------------------------------------------------------
WINDOWS UPDATE POLICIES (5)
--------------------------------------------------------------------------------

Policy Name: DeferFeatureUpdates
Source: GROUP POLICY (GPO)
Value: 1
Impact: Feature updates are deferred by 180 days
Description: Controls whether feature updates are deferred
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
Source Details: Active Directory Group Policy

Policy Name: TargetReleaseVersion
Source: GROUP POLICY (GPO)
Value: 1
Impact: System is pinned to Windows version 23H2
Description: Pins Windows to a specific version
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
Source Details: Active Directory Group Policy

Policy Name: AUOptions
Source: GROUP POLICY (GPO)
Value: 4
Impact: Auto download and schedule install
Description: Configures automatic update behavior
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
Source Details: Active Directory Group Policy

Policy Name: WUServer
Source: GROUP POLICY (GPO)
Value: https://wsus.contoso.local
Impact: Updates are managed through WSUS server: https://wsus.contoso.local
Description: WSUS server for updates
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
Source Details: Active Directory Group Policy

Policy Name: DeferQualityUpdates
Source: GROUP POLICY (GPO)
Value: 1
Impact: Quality updates are deferred by 14 days
Description: Controls whether quality updates are deferred
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
Source Details: Active Directory Group Policy

--------------------------------------------------------------------------------
DEVICE CONTROL POLICIES (4)
--------------------------------------------------------------------------------

Policy Name: Deny_Write_{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
Source: INTUNE/MDM
Value: 1
Impact: WRITE access DENIED for device class: {53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
Description: Controls write access to removable storage
Registry Path: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
Source Details: ConfigSource: {A7B3E2F9-1234-5678-ABCD-EF1234567890}

Policy Name: USBSTOR_Start
Source: INTUNE/MDM
Value: 3
Impact: USB storage drivers load manually (ENABLED)
Description: Controls USB storage driver
Registry Path: HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR
Source Details: PolicyManager CSP

--------------------------------------------------------------------------------
BITLOCKER POLICIES (3)
--------------------------------------------------------------------------------

Policy Name: EnableBDEWithNoTPM
Source: GROUP POLICY (GPO)
Value: 0
Impact: BitLocker requires TPM
Description: Controls BitLocker TPM requirement
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\FVE
Source Details: Active Directory Group Policy

Policy Name: EncryptionMethod
Source: GROUP POLICY (GPO)
Value: 4
Impact: Using AES-256-XTS encryption (recommended)
Description: BitLocker encryption algorithm
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\FVE
Source Details: Active Directory Group Policy

Policy Name: UseRecoveryPassword
Source: GROUP POLICY (GPO)
Value: 1
Impact: Recovery password is REQUIRED
Description: BitLocker recovery password requirement
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\FVE
Source Details: Active Directory Group Policy

================================================================================
END OF REPORT
================================================================================
```

---

## Understanding the Output

### Color Coding (Console Only)
- **Cyan**: Group Policy (GPO) - Traditional AD policies
- **Magenta**: Intune/MDM - Cloud-based management
- **Yellow**: MECM/SCCM - Configuration Manager
- **Gray**: Local policies

### Policy Value Interpretation

#### Common Values
- **0**: Disabled, No, False
- **1**: Enabled, Yes, True
- **2-9**: Specific configuration options
- **String**: Server URLs, version numbers, paths

#### USBSTOR Start Values
- **0**: Boot - Drivers load at boot
- **1**: System - Drivers load at system start
- **2**: Automatic - Standard automatic loading
- **3**: Manual - User/system can load drivers (USB works)
- **4**: Disabled - USB storage completely blocked

#### AUOptions Values
- **1**: Notify for download and install
- **2**: Notify before installation
- **3**: Auto download, notify for install
- **4**: Auto download and schedule install
- **5**: Local admin chooses

### ConfigSource Tracking

For Intune policies, you may see:
```
Source Details: ConfigSource: {A7B3E2F9-1234-5678-ABCD-EF1234567890}
```

This GUID helps Intune administrators identify:
- Which configuration profile applied the setting
- The assignment group
- Troubleshoot policy conflicts

To find the profile in Intune:
1. Go to Microsoft Endpoint Manager
2. Navigate to Device Configuration
3. Search for the ConfigSource GUID
4. Review the profile and assignment

---

## Common Scenarios Summary

| Scenario | Policy Source | Key Indicator |
|----------|---------------|---------------|
| USB Blocked at Work | Intune/GPO | `USBSTOR_Start = 4` or `Deny_Write = 1` |
| Update Version Locked | GPO | `TargetReleaseVersion = 1` |
| BitLocker Required | GPO | `UseRecoveryPassword = 1` |
| Defender Disabled | Intune/Local | `DisableAntiSpyware = 1` |
| Firewall Blocking | GPO | `DefaultInboundAction = 1` |
| WSUS Updates | GPO | `WUServer = <server_url>` |

---

## Next Steps After Running the Tool

1. **Identify the Source**: Check which system applied the policy
2. **Contact the Right Admin**:
   - GPO → Active Directory / Group Policy admin
   - Intune → Endpoint Manager / Cloud admin
   - MECM → Configuration Manager admin
3. **Provide Registry Path**: Include the exact path for verification
4. **Include ConfigSource**: For Intune policies, provide the GUID
5. **Reference the Report**: Attach the exported report file

---

**Tip**: Save the exported report as documentation for compliance audits, troubleshooting tickets, or change requests.
