<#
.SYNOPSIS
    Enumerates local host configuration from Windows workstations via Active Directory.
.DESCRIPTION
    Queries AD for Windows workstations, performs connectivity pre-checks (ping + WinRM),
    attempts WinRM service restart via WMI if needed, collects local configuration via
    Invoke-Command, and exports results to JSON.
.PARAMETER OutputPath
    Path for the output JSON file. Default: C:\Temp\WorkstationConfig.json
.PARAMETER ThrottleLimit
    Reserved for future parallel processing. Currently unused (sequential).
.PARAMETER WhatIf
    Reserved for future dry-run support.
#>
param(
    [string]$OutputPath = "C:\Temp\WorkstationConfig.json",
    [int]$ThrottleLimit = 10,
    [switch]$WhatIf
)

# --- 1. Get Windows workstations from AD ---
Write-Host "Querying AD for Windows workstations..." -ForegroundColor Cyan

$workstations = Get-ADComputer -Filter {
    OperatingSystem -like "*Windows*" -and 
    OperatingSystem -notlike "*Server*" -and 
    Enabled -eq $true
} -Properties OperatingSystem, OperatingSystemVersion, DistinguishedName, DNSHostName |
    Select-Object Name, DNSHostName, DistinguishedName, OperatingSystem, OperatingSystemVersion

Write-Host "Found $($workstations.Count) workstations." -ForegroundColor Green

# --- 2. Initialize PSCustomObjects ---
$results = foreach ($ws in $workstations) {
    [PSCustomObject]@{
        Hostname                = $ws.Name
        DNSHostName             = $ws.DNSHostName
        DistinguishedName       = $ws.DistinguishedName
        Online                  = $false
        RemotingAvailable       = $false
        CollectionError         = $null
        CollectionTime          = $null

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
}

# --- Remote script block (runs on the workstation) ---
$remoteScript = {
    $output = [PSCustomObject]@{}

    # Windows Version + Release
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue

    $output | Add-Member -NotePropertyName OSCaption        -NotePropertyValue $os.Caption
    $output | Add-Member -NotePropertyName OSVersion        -NotePropertyValue $os.Version
    $output | Add-Member -NotePropertyName OSBuildNumber    -NotePropertyValue $os.BuildNumber
    $output | Add-Member -NotePropertyName DisplayVersion   -NotePropertyValue $reg.DisplayVersion
    $output | Add-Member -NotePropertyName ReleaseId        -NotePropertyValue $reg.ReleaseId
    $output | Add-Member -NotePropertyName OSArchitecture   -NotePropertyValue $os.OSArchitecture
    $output | Add-Member -NotePropertyName InstallDate      -NotePropertyValue $os.InstallDate

    # Local Users + IsAdmin
    $adminNames = @()
    try {
        $adminNames = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name
    } catch {}

    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
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
    }
    $output | Add-Member -NotePropertyName LocalUsers -NotePropertyValue $localUsers

    # Local Administrators (raw membership)
    $output | Add-Member -NotePropertyName LocalAdministrators -NotePropertyValue $adminNames

    # SMB settings
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $output | Add-Member -NotePropertyName SMBRequireSecuritySignature -NotePropertyValue $smb.RequireSecuritySignature
        $output | Add-Member -NotePropertyName SMBEnableSecuritySignature  -NotePropertyValue $smb.EnableSecuritySignature
    } catch {}

    # SMBv1 (server)
    try {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $output | Add-Member -NotePropertyName SMBv1Enabled -NotePropertyValue ($smbv1.State -eq "Enabled")
    } catch {}

    # Firewall Domain profile
    try {
        $fw = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
        $output | Add-Member -NotePropertyName FirewallDomainProfileEnabled -NotePropertyValue $fw.Enabled
    } catch {}

    # Credential Guard / LSA Protection (basic registry check)
    $cg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
    $output | Add-Member -NotePropertyName CredentialGuardEnabled -NotePropertyValue ($cg.EnableVirtualizationBasedSecurity -eq 1)

    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $output | Add-Member -NotePropertyName LSAProtectionEnabled -NotePropertyValue ($lsa.RunAsPPL -eq 1)

    # PowerShell logging
    $psLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    $output | Add-Member -NotePropertyName PowerShellScriptBlockLogging -NotePropertyValue ($psLogging.EnableScriptBlockLogging -eq 1)

    $psModule = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    $output | Add-Member -NotePropertyName PowerShellModuleLogging -NotePropertyValue ($psModule.EnableModuleLogging -eq 1)

    return $output
}

# --- 3. Process each workstation ---
$i = 0
foreach ($obj in $results) {
    $i++
    $target = $obj.DNSHostName
    if (-not $target) { $target = $obj.Hostname }

    Write-Progress -Activity "Collecting workstation config" -Status "$target ($i/$($results.Count))" -PercentComplete (($i / $results.Count) * 100)

    # Pre-check: Ping
    if (-not (Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        $obj.CollectionError = "Ping failed"
        continue
    }
    $obj.Online = $true

    # Pre-check: WinRM
    $winrmOk = $false
    try {
        Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
        $winrmOk = $true
    } catch {}

    # Attempt WinRM restart via WMI if needed
    if (-not $winrmOk) {
        try {
            $svc = Get-CimInstance -ComputerName $target -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
            if ($svc) {
                Invoke-CimMethod -InputObject $svc -MethodName StopService -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Seconds 2
                Invoke-CimMethod -InputObject $svc -MethodName StartService -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 3
                Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
                $winrmOk = $true
            }
        } catch {
            $obj.CollectionError = "WinRM restart via WMI failed: $($_.Exception.Message)"
        }
    }

    if (-not $winrmOk) {
        if (-not $obj.CollectionError) { $obj.CollectionError = "WinRM unavailable" }
        continue
    }

    # Collect data
    try {
        $data = Invoke-Command -ComputerName $target -ScriptBlock $remoteScript -ErrorAction Stop
        $obj.RemotingAvailable = $true
        $obj.CollectionTime = Get-Date

        # Merge returned properties into the object
        foreach ($prop in $data.PSObject.Properties) {
            if ($obj.PSObject.Properties.Name -contains $prop.Name) {
                $obj.$($prop.Name) = $prop.Value
            }
        }
    } catch {
        $obj.CollectionError = "Invoke-Command failed: $($_.Exception.Message)"
    }
}

# --- 4. Export to JSON ---
$results | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Complete. Results written to $OutputPath" -ForegroundColor Green
Write-Host "Online: $(($results | Where-Object Online).Count) | Remoting OK: $(($results | Where-Object RemotingAvailable).Count)" -ForegroundColor Cyan
