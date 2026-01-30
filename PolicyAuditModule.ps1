<#
.SYNOPSIS
    Comprehensive Windows Policy Audit Module
.DESCRIPTION
    This PowerShell module performs deep analysis of all policies applied to
    a Windows machine, including GPO, MECM, Intune, and local policies.
    
    For each policy, it identifies:
    - The source (GPO/MECM/Intune/Local)
    - The policy name and category
    - Current value/state
    - What features are being controlled
    - Registry path
    
.PARAMETER Mode
    Audit mode: 'full' (default) or 'quick'
.PARAMETER Export
    Whether to export report to Desktop
.PARAMETER Verbose
    Show detailed output
#>

param(
    [string]$Mode = "full",
    [string]$Export = "true",
    [string]$Verbose = "false"
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

$script:AllPolicies = @()
$script:PolicyCategories = @{
    "Security" = @()
    "Windows Update" = @()
    "Device Control" = @()
    "Network" = @()
    "User Experience" = @()
    "Application Control" = @()
    "Power Management" = @()
    "System" = @()
    "BitLocker" = @()
    "Firewall" = @()
    "Other" = @()
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-SectionHeader {
    param([string]$Title)
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host $Title.ToUpper() -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

function Get-SafeRegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                return $value.$Name
            }
        }
    }
    catch {
        return $null
    }
    return $null
}

function Get-PolicySource {
    param(
        [string]$RegistryPath
    )
    
    # Intune/MDM PolicyManager paths
    if ($RegistryPath -match "PolicyManager") {
        $configSource = Get-SafeRegistryValue -Path $RegistryPath -Name "ConfigSource"
        return [PSCustomObject]@{
            Source = "INTUNE/MDM"
            SourceType = "Intune"
            Details = if ($configSource) { "ConfigSource: $configSource" } else { "PolicyManager CSP" }
            Color = "Magenta"
            Priority = 1
        }
    }
    
    # MECM/ConfigMgr paths
    if ($RegistryPath -match "CCM|ConfigMgr|SCCM") {
        return [PSCustomObject]@{
            Source = "MECM/SCCM"
            SourceType = "MECM"
            Details = "Configuration Manager Policy"
            Color = "Yellow"
            Priority = 2
        }
    }
    
    # Traditional Group Policy
    if ($RegistryPath -match "\\Policies\\") {
        return [PSCustomObject]@{
            Source = "GROUP POLICY (GPO)"
            SourceType = "GPO"
            Details = "Active Directory Group Policy"
            Color = "Cyan"
            Priority = 3
        }
    }
    
    # Local machine settings
    if ($RegistryPath -match "HKLM:\\SOFTWARE\\Microsoft\\Windows") {
        return [PSCustomObject]@{
            Source = "LOCAL POLICY"
            SourceType = "Local"
            Details = "Local Machine Policy"
            Color = "Gray"
            Priority = 4
        }
    }
    
    return [PSCustomObject]@{
        Source = "UNKNOWN"
        SourceType = "Unknown"
        Details = "Source not determined"
        Color = "DarkGray"
        Priority = 5
    }
}

function Add-PolicyToCollection {
    param(
        [string]$Category,
        [string]$PolicyName,
        [object]$Value,
        [string]$RegistryPath,
        [string]$Description,
        [string]$Impact
    )
    
    $sourceInfo = Get-PolicySource -RegistryPath $RegistryPath
    
    $policy = [PSCustomObject]@{
        Category = $Category
        PolicyName = $PolicyName
        Value = $Value
        RegistryPath = $RegistryPath
        Source = $sourceInfo.Source
        SourceType = $sourceInfo.SourceType
        SourceDetails = $sourceInfo.Details
        Description = $Description
        Impact = $Impact
        Color = $sourceInfo.Color
        Priority = $sourceInfo.Priority
    }
    
    $script:AllPolicies += $policy
    $script:PolicyCategories[$Category] += $policy
}

# ============================================================================
# POLICY AUDIT FUNCTIONS
# ============================================================================

function Get-WindowsUpdatePolicies {
    Write-ColorOutput "`n[*] Auditing Windows Update Policies..." -Color Yellow
    
    $wuPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
    )
    
    foreach ($path in $wuPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Defer Feature Updates
                if ($null -ne $props.DeferFeatureUpdates) {
                    $impact = if ($props.DeferFeatureUpdates -eq 1) {
                        "Feature updates are deferred by $($props.DeferFeatureUpdatesPeriodInDays) days"
                    } else {
                        "Feature updates are not deferred"
                    }
                    Add-PolicyToCollection -Category "Windows Update" -PolicyName "DeferFeatureUpdates" `
                        -Value $props.DeferFeatureUpdates -RegistryPath $path `
                        -Description "Controls whether feature updates are deferred" `
                        -Impact $impact
                }
                
                # Target Release Version
                if ($null -ne $props.TargetReleaseVersion) {
                    $impact = if ($props.TargetReleaseVersion -eq 1) {
                        "System is pinned to Windows version $($props.TargetReleaseVersionInfo)"
                    } else {
                        "System will receive latest feature updates"
                    }
                    Add-PolicyToCollection -Category "Windows Update" -PolicyName "TargetReleaseVersion" `
                        -Value $props.TargetReleaseVersion -RegistryPath $path `
                        -Description "Pins Windows to a specific version" `
                        -Impact $impact
                }
                
                # Auto Update Options
                if ($null -ne $props.AUOptions) {
                    $impact = switch ($props.AUOptions) {
                        1 { "Notify for download and install" }
                        2 { "Notify before installation" }
                        3 { "Auto download and notify for install" }
                        4 { "Auto download and schedule install" }
                        5 { "Allow local admin to choose setting" }
                        default { "Unknown configuration: $($props.AUOptions)" }
                    }
                    Add-PolicyToCollection -Category "Windows Update" -PolicyName "AUOptions" `
                        -Value $props.AUOptions -RegistryPath $path `
                        -Description "Configures automatic update behavior" `
                        -Impact $impact
                }
                
                # WSUS Server
                if ($null -ne $props.WUServer) {
                    Add-PolicyToCollection -Category "Windows Update" -PolicyName "WUServer" `
                        -Value $props.WUServer -RegistryPath $path `
                        -Description "WSUS server for updates" `
                        -Impact "Updates are managed through WSUS server: $($props.WUServer)"
                }
                
                # Defer Quality Updates
                if ($null -ne $props.DeferQualityUpdates) {
                    $impact = if ($props.DeferQualityUpdates -eq 1) {
                        "Quality updates are deferred by $($props.DeferQualityUpdatesPeriodInDays) days"
                    } else {
                        "Quality updates are not deferred"
                    }
                    Add-PolicyToCollection -Category "Windows Update" -PolicyName "DeferQualityUpdates" `
                        -Value $props.DeferQualityUpdates -RegistryPath $path `
                        -Description "Controls whether quality updates are deferred" `
                        -Impact $impact
                }
            }
        }
    }
}

function Get-DeviceControlPolicies {
    Write-ColorOutput "`n[*] Auditing Device Control Policies..." -Color Yellow
    
    # USB/Removable Storage
    $devicePaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemovableStorage",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
        "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
    )
    
    foreach ($path in $devicePaths) {
        if (Test-Path $path) {
            # Check for removable storage restrictions
            if ($path -match "RemovableStorage") {
                # Check all device classes
                Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $deviceClass = $_.PSChildName
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    
                    if ($null -ne $props.Deny_Read) {
                        $impact = if ($props.Deny_Read -eq 1) {
                            "READ access DENIED for device class: $deviceClass"
                        } else {
                            "READ access ALLOWED for device class: $deviceClass"
                        }
                        Add-PolicyToCollection -Category "Device Control" -PolicyName "Deny_Read_$deviceClass" `
                            -Value $props.Deny_Read -RegistryPath $_.PSPath `
                            -Description "Controls read access to removable storage" `
                            -Impact $impact
                    }
                    
                    if ($null -ne $props.Deny_Write) {
                        $impact = if ($props.Deny_Write -eq 1) {
                            "WRITE access DENIED for device class: $deviceClass"
                        } else {
                            "WRITE access ALLOWED for device class: $deviceClass"
                        }
                        Add-PolicyToCollection -Category "Device Control" -PolicyName "Deny_Write_$deviceClass" `
                            -Value $props.Deny_Write -RegistryPath $_.PSPath `
                            -Description "Controls write access to removable storage" `
                            -Impact $impact
                    }
                    
                    if ($null -ne $props.Deny_Execute) {
                        $impact = if ($props.Deny_Execute -eq 1) {
                            "EXECUTE access DENIED for device class: $deviceClass"
                        } else {
                            "EXECUTE access ALLOWED for device class: $deviceClass"
                        }
                        Add-PolicyToCollection -Category "Device Control" -PolicyName "Deny_Execute_$deviceClass" `
                            -Value $props.Deny_Execute -RegistryPath $_.PSPath `
                            -Description "Controls execute access to removable storage" `
                            -Impact $impact
                    }
                }
            }
            
            # USBSTOR service status
            if ($path -match "USBSTOR") {
                $startValue = Get-SafeRegistryValue -Path $path -Name "Start"
                if ($null -ne $startValue) {
                    $impact = switch ($startValue) {
                        0 { "USB storage drivers load at boot" }
                        1 { "USB storage drivers load at system start" }
                        2 { "USB storage drivers load automatically" }
                        3 { "USB storage drivers load manually (ENABLED)" }
                        4 { "USB storage drivers DISABLED - USB storage completely blocked" }
                        default { "Unknown configuration: $startValue" }
                    }
                    Add-PolicyToCollection -Category "Device Control" -PolicyName "USBSTOR_Start" `
                        -Value $startValue -RegistryPath $path `
                        -Description "Controls USB storage driver" `
                        -Impact $impact
                }
            }
            
            # Device Installation Restrictions
            if ($path -match "DeviceInstall") {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($null -ne $props.DenyDeviceClasses) {
                    Add-PolicyToCollection -Category "Device Control" -PolicyName "DenyDeviceClasses" `
                        -Value $props.DenyDeviceClasses -RegistryPath $path `
                        -Description "Prevents installation of specific device classes" `
                        -Impact "Device installation restricted for specified classes"
                }
                
                if ($null -ne $props.DenyDeviceIDs) {
                    Add-PolicyToCollection -Category "Device Control" -PolicyName "DenyDeviceIDs" `
                        -Value $props.DenyDeviceIDs -RegistryPath $path `
                        -Description "Prevents installation of specific devices" `
                        -Impact "Device installation restricted for specified hardware IDs"
                }
            }
        }
    }
}

function Get-SecurityPolicies {
    Write-ColorOutput "`n[*] Auditing Security Policies..." -Color Yellow
    
    $securityPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    )
    
    foreach ($path in $securityPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Credential Guard
                if ($null -ne $props.EnableVirtualizationBasedSecurity) {
                    $impact = if ($props.EnableVirtualizationBasedSecurity -eq 1) {
                        "Virtualization-based security is ENABLED (Credential Guard active)"
                    } else {
                        "Virtualization-based security is DISABLED"
                    }
                    Add-PolicyToCollection -Category "Security" -PolicyName "EnableVirtualizationBasedSecurity" `
                        -Value $props.EnableVirtualizationBasedSecurity -RegistryPath $path `
                        -Description "Enables Credential Guard and other VBS features" `
                        -Impact $impact
                }
                
                # Windows Defender
                if ($null -ne $props.DisableAntiSpyware) {
                    $impact = if ($props.DisableAntiSpyware -eq 1) {
                        "Windows Defender is DISABLED"
                    } else {
                        "Windows Defender is ENABLED"
                    }
                    Add-PolicyToCollection -Category "Security" -PolicyName "DisableAntiSpyware" `
                        -Value $props.DisableAntiSpyware -RegistryPath $path `
                        -Description "Controls Windows Defender" `
                        -Impact $impact
                }
                
                # Smart Screen
                if ($null -ne $props.EnableSmartScreen) {
                    $impact = if ($props.EnableSmartScreen -eq 1) {
                        "SmartScreen filter is ENABLED"
                    } else {
                        "SmartScreen filter is DISABLED"
                    }
                    Add-PolicyToCollection -Category "Security" -PolicyName "EnableSmartScreen" `
                        -Value $props.EnableSmartScreen -RegistryPath $path `
                        -Description "Controls SmartScreen filter" `
                        -Impact $impact
                }
                
                # Windows Hello
                if ($null -ne $props.UsePassportForWork) {
                    $impact = if ($props.UsePassportForWork -eq 1) {
                        "Windows Hello for Business is ENABLED"
                    } else {
                        "Windows Hello for Business is DISABLED"
                    }
                    Add-PolicyToCollection -Category "Security" -PolicyName "UsePassportForWork" `
                        -Value $props.UsePassportForWork -RegistryPath $path `
                        -Description "Controls Windows Hello for Business" `
                        -Impact $impact
                }
                
                # Lock Screen
                if ($null -ne $props.NoLockScreen) {
                    $impact = if ($props.NoLockScreen -eq 1) {
                        "Lock screen is DISABLED"
                    } else {
                        "Lock screen is ENABLED"
                    }
                    Add-PolicyToCollection -Category "Security" -PolicyName "NoLockScreen" `
                        -Value $props.NoLockScreen -RegistryPath $path `
                        -Description "Controls lock screen" `
                        -Impact $impact
                }
            }
        }
    }
}

function Get-NetworkPolicies {
    Write-ColorOutput "`n[*] Auditing Network Policies..." -Color Yellow
    
    $networkPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\NetworkIsolation"
    )
    
    foreach ($path in $networkPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Network Location Awareness
                if ($null -ne $props.NoActiveProbe) {
                    $impact = if ($props.NoActiveProbe -eq 1) {
                        "Network connectivity probes are DISABLED"
                    } else {
                        "Network connectivity probes are ENABLED"
                    }
                    Add-PolicyToCollection -Category "Network" -PolicyName "NoActiveProbe" `
                        -Value $props.NoActiveProbe -RegistryPath $path `
                        -Description "Controls active network connectivity probes" `
                        -Impact $impact
                }
                
                # WiFi Sense
                if ($null -ne $props.fMinimizeConnections) {
                    $impact = if ($props.fMinimizeConnections -eq 1) {
                        "Minimize simultaneous connections is ENABLED"
                    } else {
                        "Multiple network connections allowed"
                    }
                    Add-PolicyToCollection -Category "Network" -PolicyName "MinimizeConnections" `
                        -Value $props.fMinimizeConnections -RegistryPath $path `
                        -Description "Controls multiple network connections" `
                        -Impact $impact
                }
                
                # DNS Client
                if ($null -ne $props.EnableMulticast) {
                    $impact = if ($props.EnableMulticast -eq 0) {
                        "Multicast name resolution is DISABLED"
                    } else {
                        "Multicast name resolution is ENABLED"
                    }
                    Add-PolicyToCollection -Category "Network" -PolicyName "EnableMulticast" `
                        -Value $props.EnableMulticast -RegistryPath $path `
                        -Description "Controls multicast DNS" `
                        -Impact $impact
                }
            }
        }
    }
}

function Get-ApplicationControlPolicies {
    Write-ColorOutput "`n[*] Auditing Application Control Policies..." -Color Yellow
    
    $appPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppLocker",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AppLocker"
    )
    
    foreach ($path in $appPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Software Restriction Policies
                if ($null -ne $props.DefaultLevel) {
                    $impact = switch ($props.DefaultLevel) {
                        0x00000 { "Disallowed - Only explicitly allowed programs can run" }
                        0x10000 { "Basic User - Programs run with basic user rights" }
                        0x20000 { "Unrestricted - All programs can run" }
                        default { "Custom level: $($props.DefaultLevel)" }
                    }
                    Add-PolicyToCollection -Category "Application Control" -PolicyName "SRP_DefaultLevel" `
                        -Value $props.DefaultLevel -RegistryPath $path `
                        -Description "Software Restriction Policies default level" `
                        -Impact $impact
                }
                
                # AppLocker enforcement
                if ($null -ne $props.EnforcementMode) {
                    $impact = switch ($props.EnforcementMode) {
                        0 { "AppLocker is in audit mode only" }
                        1 { "AppLocker is ENFORCING rules" }
                        default { "Unknown mode: $($props.EnforcementMode)" }
                    }
                    Add-PolicyToCollection -Category "Application Control" -PolicyName "AppLocker_EnforcementMode" `
                        -Value $props.EnforcementMode -RegistryPath $path `
                        -Description "AppLocker enforcement mode" `
                        -Impact $impact
                }
            }
            
            # Check AppLocker rule collections
            $ruleTypes = @("Exe", "Dll", "Script", "Msi", "Appx")
            foreach ($ruleType in $ruleTypes) {
                $rulePath = Join-Path $path $ruleType
                if (Test-Path $rulePath) {
                    $ruleProps = Get-ItemProperty -Path $rulePath -ErrorAction SilentlyContinue
                    if ($ruleProps) {
                        Add-PolicyToCollection -Category "Application Control" -PolicyName "AppLocker_${ruleType}Rules" `
                            -Value "Configured" -RegistryPath $rulePath `
                            -Description "AppLocker rules for $ruleType" `
                            -Impact "AppLocker rules are configured for $ruleType files"
                    }
                }
            }
        }
    }
}

function Get-BitLockerPolicies {
    Write-ColorOutput "`n[*] Auditing BitLocker Policies..." -Color Yellow
    
    $bitlockerPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\FVE",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker"
    )
    
    foreach ($path in $bitlockerPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Require BitLocker
                if ($null -ne $props.EnableBDEWithNoTPM) {
                    $impact = if ($props.EnableBDEWithNoTPM -eq 1) {
                        "BitLocker can be enabled without TPM"
                    } else {
                        "BitLocker requires TPM"
                    }
                    Add-PolicyToCollection -Category "BitLocker" -PolicyName "EnableBDEWithNoTPM" `
                        -Value $props.EnableBDEWithNoTPM -RegistryPath $path `
                        -Description "Controls BitLocker TPM requirement" `
                        -Impact $impact
                }
                
                # Encryption method
                if ($null -ne $props.EncryptionMethod) {
                    $impact = switch ($props.EncryptionMethod) {
                        1 { "Using AES-128-CBC encryption" }
                        2 { "Using AES-256-CBC encryption" }
                        3 { "Using AES-128-XTS encryption" }
                        4 { "Using AES-256-XTS encryption (recommended)" }
                        6 { "Using XTS-AES 128-bit encryption" }
                        7 { "Using XTS-AES 256-bit encryption" }
                        default { "Unknown encryption method: $($props.EncryptionMethod)" }
                    }
                    Add-PolicyToCollection -Category "BitLocker" -PolicyName "EncryptionMethod" `
                        -Value $props.EncryptionMethod -RegistryPath $path `
                        -Description "BitLocker encryption algorithm" `
                        -Impact $impact
                }
                
                # Recovery options
                if ($null -ne $props.UseRecoveryPassword) {
                    $impact = if ($props.UseRecoveryPassword -eq 1) {
                        "Recovery password is REQUIRED"
                    } else {
                        "Recovery password is optional"
                    }
                    Add-PolicyToCollection -Category "BitLocker" -PolicyName "UseRecoveryPassword" `
                        -Value $props.UseRecoveryPassword -RegistryPath $path `
                        -Description "BitLocker recovery password requirement" `
                        -Impact $impact
                }
            }
        }
    }
}

function Get-FirewallPolicies {
    Write-ColorOutput "`n[*] Auditing Firewall Policies..." -Color Yellow
    
    $firewallPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
        "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall"
    )
    
    foreach ($path in $firewallPaths) {
        if (Test-Path $path) {
            $profile = if ($path -match "Domain") { "Domain" } elseif ($path -match "Private") { "Private" } else { "Public" }
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Firewall enabled
                if ($null -ne $props.EnableFirewall) {
                    $impact = if ($props.EnableFirewall -eq 1) {
                        "Firewall is ENABLED for $profile profile"
                    } else {
                        "Firewall is DISABLED for $profile profile"
                    }
                    Add-PolicyToCollection -Category "Firewall" -PolicyName "EnableFirewall_$profile" `
                        -Value $props.EnableFirewall -RegistryPath $path `
                        -Description "Windows Firewall state for $profile profile" `
                        -Impact $impact
                }
                
                # Default inbound action
                if ($null -ne $props.DefaultInboundAction) {
                    $impact = if ($props.DefaultInboundAction -eq 1) {
                        "Default BLOCK inbound connections for $profile profile"
                    } else {
                        "Default ALLOW inbound connections for $profile profile"
                    }
                    Add-PolicyToCollection -Category "Firewall" -PolicyName "DefaultInboundAction_$profile" `
                        -Value $props.DefaultInboundAction -RegistryPath $path `
                        -Description "Default inbound firewall action for $profile profile" `
                        -Impact $impact
                }
                
                # Default outbound action
                if ($null -ne $props.DefaultOutboundAction) {
                    $impact = if ($props.DefaultOutboundAction -eq 1) {
                        "Default BLOCK outbound connections for $profile profile"
                    } else {
                        "Default ALLOW outbound connections for $profile profile"
                    }
                    Add-PolicyToCollection -Category "Firewall" -PolicyName "DefaultOutboundAction_$profile" `
                        -Value $props.DefaultOutboundAction -RegistryPath $path `
                        -Description "Default outbound firewall action for $profile profile" `
                        -Impact $impact
                }
            }
        }
    }
}

function Get-UserExperiencePolicies {
    Write-ColorOutput "`n[*] Auditing User Experience Policies..." -Color Yellow
    
    $uxPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    )
    
    foreach ($path in $uxPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Disable notification center
                if ($null -ne $props.DisableNotificationCenter) {
                    $impact = if ($props.DisableNotificationCenter -eq 1) {
                        "Action Center/Notification Center is DISABLED"
                    } else {
                        "Action Center/Notification Center is ENABLED"
                    }
                    Add-PolicyToCollection -Category "User Experience" -PolicyName "DisableNotificationCenter" `
                        -Value $props.DisableNotificationCenter -RegistryPath $path `
                        -Description "Controls Action Center" `
                        -Impact $impact
                }
                
                # Disable consumer experiences
                if ($null -ne $props.DisableWindowsConsumerFeatures) {
                    $impact = if ($props.DisableWindowsConsumerFeatures -eq 1) {
                        "Consumer features (app suggestions, tips) are DISABLED"
                    } else {
                        "Consumer features are ENABLED"
                    }
                    Add-PolicyToCollection -Category "User Experience" -PolicyName "DisableWindowsConsumerFeatures" `
                        -Value $props.DisableWindowsConsumerFeatures -RegistryPath $path `
                        -Description "Controls consumer features and app suggestions" `
                        -Impact $impact
                }
                
                # Telemetry
                if ($null -ne $props.AllowTelemetry) {
                    $impact = switch ($props.AllowTelemetry) {
                        0 { "Telemetry is set to Security (Enterprise only)" }
                        1 { "Telemetry is set to Basic" }
                        2 { "Telemetry is set to Enhanced" }
                        3 { "Telemetry is set to Full" }
                        default { "Unknown telemetry setting: $($props.AllowTelemetry)" }
                    }
                    Add-PolicyToCollection -Category "User Experience" -PolicyName "AllowTelemetry" `
                        -Value $props.AllowTelemetry -RegistryPath $path `
                        -Description "Controls diagnostic data collection" `
                        -Impact $impact
                }
                
                # Hide specific drives
                if ($null -ne $props.NoDrives) {
                    Add-PolicyToCollection -Category "User Experience" -PolicyName "NoDrives" `
                        -Value $props.NoDrives -RegistryPath $path `
                        -Description "Hides specific drives in Explorer" `
                        -Impact "Specific drives are hidden from Explorer (bitmask: $($props.NoDrives))"
                }
            }
        }
    }
}

function Get-PowerManagementPolicies {
    Write-ColorOutput "`n[*] Auditing Power Management Policies..." -Color Yellow
    
    $powerPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Power"
    )
    
    foreach ($path in $powerPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $settingPath = $_.PSPath
                $settingName = $_.PSChildName
                $props = Get-ItemProperty -Path $settingPath -ErrorAction SilentlyContinue
                
                if ($null -ne $props.ACSettingIndex) {
                    Add-PolicyToCollection -Category "Power Management" -PolicyName "$settingName`_AC" `
                        -Value $props.ACSettingIndex -RegistryPath $settingPath `
                        -Description "Power setting when plugged in" `
                        -Impact "AC power setting configured"
                }
                
                if ($null -ne $props.DCSettingIndex) {
                    Add-PolicyToCollection -Category "Power Management" -PolicyName "$settingName`_DC" `
                        -Value $props.DCSettingIndex -RegistryPath $settingPath `
                        -Description "Power setting when on battery" `
                        -Impact "Battery power setting configured"
                }
            }
        }
    }
}

function Get-SystemPolicies {
    Write-ColorOutput "`n[*] Auditing System Policies..." -Color Yellow
    
    $systemPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    )
    
    foreach ($path in $systemPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props) {
                # Script execution
                if ($null -ne $props.EnableScripts) {
                    $impact = if ($props.EnableScripts -eq 1) {
                        "Logon/logoff scripts are ENABLED"
                    } else {
                        "Logon/logoff scripts are DISABLED"
                    }
                    Add-PolicyToCollection -Category "System" -PolicyName "EnableScripts" `
                        -Value $props.EnableScripts -RegistryPath $path `
                        -Description "Controls logon/logoff script execution" `
                        -Impact $impact
                }
                
                # App privacy
                if ($null -ne $props.LetAppsAccessCamera) {
                    $impact = switch ($props.LetAppsAccessCamera) {
                        0 { "User can control camera access" }
                        1 { "Camera access is FORCED ON" }
                        2 { "Camera access is FORCED OFF" }
                        default { "Unknown setting: $($props.LetAppsAccessCamera)" }
                    }
                    Add-PolicyToCollection -Category "System" -PolicyName "LetAppsAccessCamera" `
                        -Value $props.LetAppsAccessCamera -RegistryPath $path `
                        -Description "Controls app access to camera" `
                        -Impact $impact
                }
                
                # Disk quotas
                if ($null -ne $props.EnableDiskQuota) {
                    $impact = if ($props.EnableDiskQuota -eq 1) {
                        "Disk quotas are ENABLED"
                    } else {
                        "Disk quotas are DISABLED"
                    }
                    Add-PolicyToCollection -Category "System" -PolicyName "EnableDiskQuota" `
                        -Value $props.EnableDiskQuota -RegistryPath $path `
                        -Description "Controls disk quota management" `
                        -Impact $impact
                }
            }
        }
    }
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

function Show-PolicyReport {
    Write-SectionHeader "POLICY AUDIT SUMMARY"
    
    Write-ColorOutput "`nTotal Policies Found: $($script:AllPolicies.Count)" -Color White
    
    # Group by source
    $bySource = $script:AllPolicies | Group-Object SourceType
    Write-ColorOutput "`nPolicies by Source:" -Color Yellow
    foreach ($group in $bySource) {
        $color = switch ($group.Name) {
            "Intune" { "Magenta" }
            "MECM" { "Yellow" }
            "GPO" { "Cyan" }
            "Local" { "Gray" }
            default { "White" }
        }
        Write-ColorOutput "  $($group.Name): $($group.Count)" -Color $color
    }
    
    # Group by category
    Write-ColorOutput "`nPolicies by Category:" -Color Yellow
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $count = $script:PolicyCategories[$category].Count
        if ($count -gt 0) {
            Write-ColorOutput "  $category`: $count" -Color Cyan
        }
    }
    
    # Show detailed policies by category
    Write-SectionHeader "DETAILED POLICY ANALYSIS"
    
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $policies = $script:PolicyCategories[$category] | Sort-Object Priority, PolicyName
        if ($policies.Count -gt 0) {
            Write-Host "`n" -NoNewline
            Write-ColorOutput ">>> $category POLICIES ($($policies.Count)) <<<" -Color White
            Write-Host ("-" * 80) -ForegroundColor DarkGray
            
            foreach ($policy in $policies) {
                Write-Host "`n" -NoNewline
                Write-ColorOutput "Policy: " -Color Yellow -NoNewline
                Write-ColorOutput $policy.PolicyName -Color White
                
                Write-ColorOutput "Source: " -Color Yellow -NoNewline
                Write-ColorOutput $policy.Source -Color $policy.Color
                
                Write-ColorOutput "Value: " -Color Yellow -NoNewline
                $valueColor = if ($policy.Value -eq 1 -or $policy.Value -eq $true) { "Green" } elseif ($policy.Value -eq 0 -or $policy.Value -eq $false) { "Red" } else { "White" }
                Write-ColorOutput $policy.Value -Color $valueColor
                
                Write-ColorOutput "Impact: " -Color Yellow -NoNewline
                Write-ColorOutput $policy.Impact -Color White
                
                Write-ColorOutput "Description: " -Color Yellow -NoNewline
                Write-ColorOutput $policy.Description -Color Gray
                
                Write-ColorOutput "Registry: " -Color Yellow -NoNewline
                Write-ColorOutput $policy.RegistryPath -Color DarkGray
            }
        }
    }
}

function Export-PolicyReport {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = "$env:USERPROFILE\Desktop\PolicyAudit_Report_$timestamp.txt"
    
    $report = @"
================================================================================
                    WINDOWS POLICY AUDIT REPORT
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
User: $env:USERDOMAIN\$env:USERNAME
Domain: $env:USERDOMAIN

================================================================================
                            EXECUTIVE SUMMARY
================================================================================

Total Policies Found: $($script:AllPolicies.Count)

Policies by Source:
"@

    $bySource = $script:AllPolicies | Group-Object SourceType
    foreach ($group in $bySource) {
        $report += "`n  - $($group.Name): $($group.Count) policies"
    }
    
    $report += "`n`nPolicies by Category:"
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $count = $script:PolicyCategories[$category].Count
        if ($count -gt 0) {
            $report += "`n  - $category`: $count policies"
        }
    }
    
    $report += "`n`n"
    $report += "=" * 80
    $report += "`n                     DETAILED POLICY INVENTORY"
    $report += "`n" + "=" * 80
    
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $policies = $script:PolicyCategories[$category] | Sort-Object Priority, PolicyName
        if ($policies.Count -gt 0) {
            $report += "`n`n"
            $report += "-" * 80
            $report += "`n$category POLICIES ($($policies.Count))"
            $report += "`n" + "-" * 80
            
            foreach ($policy in $policies) {
                $report += "`n`n"
                $report += "Policy Name: $($policy.PolicyName)`n"
                $report += "Source: $($policy.Source)`n"
                $report += "Value: $($policy.Value)`n"
                $report += "Impact: $($policy.Impact)`n"
                $report += "Description: $($policy.Description)`n"
                $report += "Registry Path: $($policy.RegistryPath)`n"
                $report += "Source Details: $($policy.SourceDetails)`n"
            }
        }
    }
    
    $report += "`n`n"
    $report += "=" * 80
    $report += "`nEND OF REPORT"
    $report += "`n" + "=" * 80
    
    $report | Out-File -FilePath $exportPath -Encoding UTF8 -Force
    
    Write-ColorOutput "`nReport exported to: $exportPath" -Color Green
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-SectionHeader "Windows Policy Audit Tool"
Write-ColorOutput "Computer: $env:COMPUTERNAME" -Color Gray
Write-ColorOutput "User: $env:USERDOMAIN\$env:USERNAME" -Color Gray
Write-ColorOutput "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Gray
Write-ColorOutput "Mode: $Mode" -Color Gray

Write-ColorOutput "`n[*] Starting policy audit..." -Color Yellow
Write-ColorOutput "[*] This may take a few minutes...`n" -Color Yellow

# Run all audit functions
try {
    Get-WindowsUpdatePolicies
    Get-DeviceControlPolicies
    Get-SecurityPolicies
    Get-NetworkPolicies
    Get-ApplicationControlPolicies
    Get-BitLockerPolicies
    Get-FirewallPolicies
    Get-UserExperiencePolicies
    Get-PowerManagementPolicies
    Get-SystemPolicies
    
    # Display report
    Show-PolicyReport
    
    # Export if requested
    if ($Export -eq "true") {
        Write-ColorOutput "`n[*] Exporting report..." -Color Yellow
        Export-PolicyReport
    }
    
    Write-ColorOutput "`n[*] Audit complete!" -Color Green
    exit 0
}
catch {
    Write-ColorOutput "`nERROR: $($_.Exception.Message)" -Color Red
    Write-ColorOutput $_.ScriptStackTrace -Color Red
    exit 1
}
