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

function Get-PolicyIdentifier {
    param(
        [string]$RegistryPath
    )
    
    $identifier = @{}
    
    # Try to get GPO name from registry
    $gpoPath = $RegistryPath -replace "(HKLM:\\SOFTWARE\\Policies.*?)\\[^\\]+$", '$1'
    $gpoName = Get-SafeRegistryValue -Path $gpoPath -Name "GPOName"
    if ($gpoName) {
        $identifier.GPOName = $gpoName
    }
    
    # Try to get Intune ConfigSource
    $configSource = Get-SafeRegistryValue -Path $RegistryPath -Name "ConfigSource"
    if ($configSource) {
        $identifier.ConfigSource = $configSource
    }
    
    # Try to get Intune PolicyID
    $policyID = Get-SafeRegistryValue -Path $RegistryPath -Name "PolicyID"
    if ($policyID) {
        $identifier.PolicyID = $policyID
    }
    
    # Try to get MECM Policy GUID from path
    if ($RegistryPath -match "\{([0-9A-F\-]+)\}") {
        $identifier.MECMGUID = $Matches[1]
    }
    
    return $identifier
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
    $identifier = Get-PolicyIdentifier -RegistryPath $RegistryPath
    
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
        GPOName = $identifier.GPOName
        ConfigSource = $identifier.ConfigSource
        PolicyID = $identifier.PolicyID
        MECMGUID = $identifier.MECMGUID
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

function Get-MECMPolicies {
    Write-ColorOutput "`n[*] Auditing MECM/SCCM Policies..." -Color Yellow
    
    # Check if MECM client is installed
    $ccmPath = "HKLM:\SOFTWARE\Microsoft\CCM"
    if (-not (Test-Path $ccmPath)) {
        Write-ColorOutput "  MECM client not detected on this machine" -Color Gray
        return
    }
    
    # MECM Policy paths
    $mecmPaths = @(
        "HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\ActualConfig",
        "HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\RequestedConfig",
        "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution",
        "HKLM:\SOFTWARE\Policies\Microsoft\CCM"
    )
    
    foreach ($basePath in $mecmPaths) {
        if (Test-Path $basePath) {
            # Get all subkeys (policy GUIDs)
            Get-ChildItem -Path $basePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $policyPath = $_.PSPath
                $policyGUID = $_.PSChildName
                
                $props = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
                if ($props) {
                    # Process each property as a potential policy
                    foreach ($prop in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" })) {
                        $propName = $prop.Name
                        $propValue = $prop.Value
                        
                        # Skip empty or null values
                        if ($null -eq $propValue -or $propValue -eq "") {
                            continue
                        }
                        
                        # Determine category based on property name
                        $category = "Other"
                        if ($propName -match "Update|Patch|WSUS") {
                            $category = "Windows Update"
                        } elseif ($propName -match "Security|Defender|Firewall") {
                            $category = "Security"
                        } elseif ($propName -match "Power") {
                            $category = "Power Management"
                        } elseif ($propName -match "Device|USB|Storage") {
                            $category = "Device Control"
                        } elseif ($propName -match "BitLocker|Encryption") {
                            $category = "BitLocker"
                        } elseif ($propName -match "Network") {
                            $category = "Network"
                        }
                        
                        Add-PolicyToCollection -Category $category -PolicyName "MECM_$propName" `
                            -Value $propValue -RegistryPath $policyPath `
                            -Description "MECM/SCCM policy setting (GUID: $policyGUID)" `
                            -Impact "MECM is managing this setting"
                    }
                }
            }
        }
    }
    
    # Check MECM client settings
    $clientSettingsPath = "HKLM:\SOFTWARE\Microsoft\CCM\ClientSDK"
    if (Test-Path $clientSettingsPath) {
        $clientProps = Get-ItemProperty -Path $clientSettingsPath -ErrorAction SilentlyContinue
        if ($clientProps) {
            foreach ($prop in ($clientProps.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" })) {
                if ($null -ne $prop.Value -and $prop.Value -ne "") {
                    Add-PolicyToCollection -Category "System" -PolicyName "MECM_ClientSDK_$($prop.Name)" `
                        -Value $prop.Value -RegistryPath $clientSettingsPath `
                        -Description "MECM client SDK setting" `
                        -Impact "MECM client configuration"
                }
            }
        }
    }
}

function Get-AllDeployedPolicies {
    Write-ColorOutput "`n[*] Discovering ALL deployed policies from registry..." -Color Yellow
    
    # Root registry paths where policies can exist
    $policyRoots = @(
        "HKLM:\SOFTWARE\Policies",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKCU:\SOFTWARE\Policies",
        "HKCU:\SOFTWARE\Microsoft\PolicyManager"
    )
    
    foreach ($rootPath in $policyRoots) {
        if (Test-Path $rootPath) {
            Write-ColorOutput "  Scanning $rootPath..." -Color Gray
            
            # Recursively scan for all policies
            Get-ChildItem -Path $rootPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $policyPath = $_.PSPath
                
                # Get all properties at this path
                $props = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
                if ($props) {
                    foreach ($prop in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" })) {
                        $propName = $prop.Name
                        $propValue = $prop.Value
                        
                        # Skip empty, null, or system values
                        if ($null -eq $propValue -or $propValue -eq "" -or $propName -eq "(default)") {
                            continue
                        }
                        
                        # Auto-categorize based on path and property name
                        $category = "Other"
                        $pathLower = $policyPath.ToLower()
                        
                        if ($pathLower -match "windowsupdate|update|wsus") {
                            $category = "Windows Update"
                        } elseif ($pathLower -match "removablestorage|device|usb|deviceinstall") {
                            $category = "Device Control"
                        } elseif ($pathLower -match "security|defender|credential|smartscreen|passport") {
                            $category = "Security"
                        } elseif ($pathLower -match "network|dns|wifi|wcm") {
                            $category = "Network"
                        } elseif ($pathLower -match "applocker|safer|restrictions") {
                            $category = "Application Control"
                        } elseif ($pathLower -match "bitlocker|fve|encryption") {
                            $category = "BitLocker"
                        } elseif ($pathLower -match "firewall|mpssvc") {
                            $category = "Firewall"
                        } elseif ($pathLower -match "explorer|cloudcontent|datacollection|notification") {
                            $category = "User Experience"
                        } elseif ($pathLower -match "power|energy") {
                            $category = "Power Management"
                        } elseif ($pathLower -match "system|privacy|scripts") {
                            $category = "System"
                        }
                        
                        # Generate friendly policy name from path
                        $pathParts = $policyPath -split "\\"
                        $contextName = if ($pathParts.Count -gt 2) { $pathParts[-2] } else { "Policy" }
                        $fullPolicyName = "$contextName\$propName"
                        
                        # Determine impact based on common patterns
                        $impact = "Policy is configured"
                        if ($propValue -eq 1 -or $propValue -eq $true) {
                            if ($propName -match "Deny|Disable|Block|Prevent|NoAllow") {
                                $impact = "Feature/Access is BLOCKED or DISABLED"
                            } else {
                                $impact = "Feature/Access is ENABLED or ALLOWED"
                            }
                        } elseif ($propValue -eq 0 -or $propValue -eq $false) {
                            if ($propName -match "Deny|Disable|Block|Prevent|NoAllow") {
                                $impact = "Feature/Access is ALLOWED or ENABLED"
                            } else {
                                $impact = "Feature/Access is DISABLED or BLOCKED"
                            }
                        } elseif ($propValue -is [int] -and $propValue -gt 1) {
                            $impact = "Configured with value: $propValue"
                        } else {
                            $impact = "Configured as: $propValue"
                        }
                        
                        Add-PolicyToCollection -Category $category -PolicyName $fullPolicyName `
                            -Value $propValue -RegistryPath $policyPath `
                            -Description "Deployed policy setting" `
                            -Impact $impact
                    }
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
                
                # Show policy identifiers if available
                if ($policy.GPOName) {
                    Write-ColorOutput "GPO Name: " -Color Yellow -NoNewline
                    Write-ColorOutput $policy.GPOName -Color Cyan
                }
                if ($policy.ConfigSource) {
                    Write-ColorOutput "ConfigSource (Intune): " -Color Yellow -NoNewline
                    Write-ColorOutput $policy.ConfigSource -Color Magenta
                }
                if ($policy.PolicyID) {
                    Write-ColorOutput "Policy ID: " -Color Yellow -NoNewline
                    Write-ColorOutput $policy.PolicyID -Color Magenta
                }
                if ($policy.MECMGUID) {
                    Write-ColorOutput "MECM Policy GUID: " -Color Yellow -NoNewline
                    Write-ColorOutput $policy.MECMGUID -Color Yellow
                }
                
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
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $exportPath = "$desktopPath\PolicyAudit_Report_$timestamp.html"
    
    # Get summary data
    $bySource = $script:AllPolicies | Group-Object SourceType
    $sourceTable = ""
    foreach ($group in $bySource) {
        $sourceColor = switch ($group.Name) {
            "Intune" { "#9C27B0" }
            "MECM" { "#FF9800" }
            "GPO" { "#2196F3" }
            "Local" { "#757575" }
            default { "#424242" }
        }
        $sourceTable += "<tr><td><span class='badge' style='background-color: $sourceColor;'>$($group.Name)</span></td><td><strong>$($group.Count)</strong> policies</td></tr>"
    }
    
    $categoryTable = ""
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $count = $script:PolicyCategories[$category].Count
        if ($count -gt 0) {
            $categoryTable += "<tr><td>$category</td><td><strong>$count</strong> policies</td></tr>"
        }
    }
    
    # Build policy details HTML
    $policyDetailsHTML = ""
    foreach ($category in $script:PolicyCategories.Keys | Sort-Object) {
        $policies = $script:PolicyCategories[$category] | Sort-Object Priority, PolicyName
        if ($policies.Count -gt 0) {
            $policyDetailsHTML += "<h2 class='category-header'>$category ($($policies.Count) Policies)</h2>"
            
            foreach ($policy in $policies) {
                $sourceColor = switch ($policy.SourceType) {
                    "Intune" { "#9C27B0" }
                    "MECM" { "#FF9800" }
                    "GPO" { "#2196F3" }
                    "Local" { "#757575" }
                    default { "#424242" }
                }
                
                $valueClass = ""
                if ($policy.Value -eq 1 -or $policy.Value -eq $true) {
                    $valueClass = "value-enabled"
                } elseif ($policy.Value -eq 0 -or $policy.Value -eq $false) {
                    $valueClass = "value-disabled"
                }
                
                $policyDetailsHTML += @"
<div class='policy-card'>
    <div class='policy-header'>
        <h3>$([System.Security.SecurityElement]::Escape($policy.PolicyName))</h3>
        <span class='badge' style='background-color: $sourceColor;'>$([System.Security.SecurityElement]::Escape($policy.Source))</span>
    </div>
    <div class='policy-body'>
"@
                
                # Add identifiers if available
                if ($policy.GPOName) {
                    $policyDetailsHTML += "<p><strong>GPO Name:</strong> $([System.Security.SecurityElement]::Escape($policy.GPOName))</p>"
                }
                if ($policy.ConfigSource) {
                    $policyDetailsHTML += "<p><strong>ConfigSource (Intune):</strong> <code>$([System.Security.SecurityElement]::Escape($policy.ConfigSource))</code></p>"
                }
                if ($policy.PolicyID) {
                    $policyDetailsHTML += "<p><strong>Policy ID:</strong> <code>$([System.Security.SecurityElement]::Escape($policy.PolicyID))</code></p>"
                }
                if ($policy.MECMGUID) {
                    $policyDetailsHTML += "<p><strong>MECM Policy GUID:</strong> <code>$([System.Security.SecurityElement]::Escape($policy.MECMGUID))</code></p>"
                }
                
                $policyDetailsHTML += @"
        <p><strong>Value:</strong> <span class='$valueClass'>$([System.Security.SecurityElement]::Escape($policy.Value))</span></p>
        <p><strong>Impact:</strong> $([System.Security.SecurityElement]::Escape($policy.Impact))</p>
        <p><strong>Description:</strong> $([System.Security.SecurityElement]::Escape($policy.Description))</p>
        <p class='registry-path'><strong>Registry:</strong> <code>$([System.Security.SecurityElement]::Escape($policy.RegistryPath))</code></p>
    </div>
</div>
"@
            }
        }
    }
    
    # Build complete HTML report
    $report = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Windows Policy Audit Report - $env:COMPUTERNAME</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .meta-info {
            background: #eceff1;
            padding: 20px 40px;
            border-bottom: 1px solid #ddd;
        }
        .meta-info p {
            margin: 5px 0;
            font-size: 0.95em;
        }
        .meta-info strong {
            color: #1e3c72;
        }
        .content {
            padding: 40px;
        }
        .summary {
            background: #f8f9fa;
            border-left: 4px solid #2196F3;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 4px;
        }
        .summary h2 {
            color: #1e3c72;
            margin-bottom: 15px;
            font-size: 1.8em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .stat-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
        }
        .stat-card h3 {
            color: #1e3c72;
            margin-bottom: 15px;
            font-size: 1.2em;
            border-bottom: 2px solid #2196F3;
            padding-bottom: 10px;
        }
        .stat-card table {
            width: 100%;
            border-collapse: collapse;
        }
        .stat-card td {
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .stat-card td:last-child {
            text-align: right;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
        }
        .category-header {
            background: #1e3c72;
            color: white;
            padding: 15px 20px;
            margin: 30px 0 20px 0;
            border-radius: 4px;
            font-size: 1.4em;
            font-weight: 400;
        }
        .policy-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.3s;
        }
        .policy-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .policy-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .policy-header h3 {
            color: #1e3c72;
            font-size: 1.1em;
            font-weight: 600;
        }
        .policy-body {
            padding: 20px;
        }
        .policy-body p {
            margin: 10px 0;
            font-size: 0.95em;
        }
        .policy-body strong {
            color: #1e3c72;
            font-weight: 600;
        }
        .value-enabled {
            color: #4CAF50;
            font-weight: 600;
        }
        .value-disabled {
            color: #F44336;
            font-weight: 600;
        }
        code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            color: #d32f2f;
        }
        .registry-path code {
            display: block;
            margin-top: 5px;
            padding: 10px;
            background: #263238;
            color: #aed581;
            word-break: break-all;
            border-radius: 4px;
        }
        .footer {
            background: #eceff1;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .policy-card { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Windows Policy Audit Report</h1>
            <p class='subtitle'>Comprehensive Policy Analysis</p>
        </div>
        
        <div class='meta-info'>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Computer:</strong> $env:COMPUTERNAME</p>
            <p><strong>User:</strong> $env:USERDOMAIN\$env:USERNAME</p>
            <p><strong>Domain:</strong> $env:USERDOMAIN</p>
        </div>
        
        <div class='content'>
            <div class='summary'>
                <h2>Executive Summary</h2>
                <p style='font-size: 1.2em; margin-top: 10px;'><strong>Total Policies Found:</strong> $($script:AllPolicies.Count)</p>
                
                <div class='stats'>
                    <div class='stat-card'>
                        <h3>Policies by Source</h3>
                        <table>
                            $sourceTable
                        </table>
                    </div>
                    <div class='stat-card'>
                        <h3>Policies by Category</h3>
                        <table>
                            $categoryTable
                        </table>
                    </div>
                </div>
            </div>
            
            <h2 style='color: #1e3c72; margin-top: 40px; margin-bottom: 20px; font-size: 2em;'>Detailed Policy Inventory</h2>
            $policyDetailsHTML
        </div>
        
        <div class='footer'>
            <p>&copy; $(Get-Date -Format "yyyy") Windows Policy Audit Tool | Generated for compliance and auditing purposes</p>
            <p>This report contains sensitive system configuration information - handle accordingly</p>
        </div>
    </div>
</body>
</html>
"@
    
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
    if ($Mode -eq "comprehensive") {
        # Comprehensive mode: Scan ALL registry policies
        Write-ColorOutput "`n[!] Running in COMPREHENSIVE mode - scanning all policy registry paths" -Color Cyan
        Get-AllDeployedPolicies
        Get-MECMPolicies
    } else {
        # Standard mode: Use targeted policy functions
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
        Get-MECMPolicies
    }
    
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
