#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Collects local host configuration from the machine it is run on (intended for Domain Controllers).
.DESCRIPTION
    Gathers Windows version/release, local users (with IsAdmin flag), local administrators,
    SMB settings, firewall profile, Credential Guard / LSA Protection, and PowerShell logging
    status. Outputs a single JSON object. No remoting is used.
.PARAMETER OutputPath
    Path for the output JSON file. Default: C:\Temp\DCConfig.json
#>
param(
    [string]$OutputPath = "C:\Temp\DCConfig.json"
)

Write-Host "Collecting local configuration on $env:COMPUTERNAME..." -ForegroundColor Cyan

# --- Initialize result object ---
$result = [PSCustomObject]@{
    Hostname                = $env:COMPUTERNAME
    DNSHostName             = ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName
    DistinguishedName       = $null   # populated below if AD module available
    Online                  = $true
    RemotingAvailable       = $false  # N/A for local-only
    CollectionError         = $null
    CollectionTime          = Get-Date

    # Windows Version & Release
    OSCaption               = $null
    OSVersion               = $null
    OSBuildNumber           = $null
    DisplayVersion          = $null
    ReleaseId               = $null
    OSArchitecture          = $null
    InstallDate             = $null

    # Local Users (array of objects)
    LocalUsers              = @()

    # Local Administrators
    LocalAdministrators     = @()

    # Other local config
    SMBRequireSecuritySignature = $null
    SMBEnableSecuritySignature  = $null
    SMBv1Enabled                = $null
    FirewallDomainProfileEnabled = $null
    CredentialGuardEnabled      = $null
    LSAProtectionEnabled        = $null
    PowerShellScriptBlockLogging = $null
    PowerShellModuleLogging     = $null
}

# Try to get DistinguishedName from AD if the module is available
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adComputer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties DistinguishedName -ErrorAction SilentlyContinue
        if ($adComputer) {
            $result.DistinguishedName = $adComputer.DistinguishedName
        }
    }
} catch {}

# --- Windows Version + Release ---
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue

    $result.OSCaption       = $os.Caption
    $result.OSVersion       = $os.Version
    $result.OSBuildNumber   = $os.BuildNumber
    $result.DisplayVersion  = $reg.DisplayVersion
    $result.ReleaseId       = $reg.ReleaseId
    $result.OSArchitecture  = $os.OSArchitecture
    $result.InstallDate     = $os.InstallDate
} catch {
    $result.CollectionError = "Failed to read OS info: $($_.Exception.Message)"
}

# --- Local Users + IsAdmin ---
try {
    $adminNames = @()
    try {
        $adminNames = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name
    } catch {}

    $result.LocalUsers = @(Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Name             = $_.Name
            Enabled          = $_.Enabled
            PasswordLastSet  = $_.PasswordLastSet
            PasswordRequired = $_.PasswordRequired
            PasswordExpires  = $_.PasswordExpires
            LastLogon        = $_.LastLogon
            Description      = $_.Description
            IsAdmin          = ($adminNames -contains "$env:COMPUTERNAME\$($_.Name)") -or ($adminNames -contains $_.Name)
        }
    })

    $result.LocalAdministrators = $adminNames
} catch {
    if (-not $result.CollectionError) {
        $result.CollectionError = "Failed to read local users: $($_.Exception.Message)"
    }
}

# --- SMB settings ---
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    $result.SMBRequireSecuritySignature = $smb.RequireSecuritySignature
    $result.SMBEnableSecuritySignature  = $smb.EnableSecuritySignature
} catch {}

# --- SMBv1 ---
try {
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $result.SMBv1Enabled = ($smbv1.State -eq "Enabled")
} catch {}

# --- Firewall Domain profile ---
try {
    $fw = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
    $result.FirewallDomainProfileEnabled = $fw.Enabled
} catch {}

# --- Credential Guard / LSA Protection ---
try {
    $cg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
    $result.CredentialGuardEnabled = ($cg.EnableVirtualizationBasedSecurity -eq 1)
} catch {}

try {
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $result.LSAProtectionEnabled = ($lsa.RunAsPPL -eq 1)
} catch {}

# --- PowerShell logging ---
try {
    $psLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    $result.PowerShellScriptBlockLogging = ($psLogging.EnableScriptBlockLogging -eq 1)
} catch {}

try {
    $psModule = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    $result.PowerShellModuleLogging = ($psModule.EnableModuleLogging -eq 1)
} catch {}

# --- Export to JSON ---
$result | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8

Write-Host "Complete. Results written to $OutputPath" -ForegroundColor Green
Write-Host "Hostname: $($result.Hostname) | OS: $($result.OSCaption) $($result.DisplayVersion)" -ForegroundColor Cyan
Write-Host "Local users found: $($result.LocalUsers.Count) | Local admins: $($result.LocalAdministrators.Count)" -ForegroundColor Cyan
