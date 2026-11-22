$targets = $reachable

Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock {
    $os = Get-CimInstance Win32_OperatingSystem
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $fw = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3
    $localAdmins = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^[A-Z]\$' } | Select-Object Name, Path, Description
    $domainServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartName -like "*\*" -and $_.StartName -notmatch "NT AUTHORITY|LocalSystem|LocalService|NetworkService" } |
        Select-Object Name, StartName, State

    [PSCustomObject]@{
        Hostname                    = $env:COMPUTERNAME
        OSCaption                   = $os.Caption
        OSVersion                   = $os.Version
        BuildNumber                 = $os.BuildNumber
        DisplayVersion              = $reg.DisplayVersion
        LastBoot                    = $os.LastBootUpTime
        SMBRequireSigning           = $smb.RequireSecuritySignature
        SMBv1Enabled                = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State -eq "Enabled"
        FirewallDomainEnabled       = $fw.Enabled
        CredentialGuard             = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity -eq 1
        LSAProtection               = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL -eq 1
        PSScriptBlockLogging        = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
        LocalAdmins                 = $localAdmins -join ", "
        DomainUserServices          = ($domainServices | ForEach-Object { "$($_.Name) ($($_.StartName))" }) -join "; "
        NonAdminShares              = ($shares | ForEach-Object { $_.Name }) -join ", "
        RecentHotfixes              = ($hotfixes | ForEach-Object { "$($_.HotFixID) ($($_.InstalledOn.ToString('yyyy-MM-dd')))" }) -join "; "
        PrintSpoolerRunning         = (Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq "Running"
        RDPEnabled                  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
    }
} | Select-Object Hostname, OSCaption, DisplayVersion, BuildNumber, SMBRequireSigning, SMBv1Enabled, FirewallDomainEnabled, CredentialGuard, LSAProtection, PSScriptBlockLogging, LocalAdmins, DomainUserServices, NonAdminShares, RecentHotfixes, PrintSpoolerRunning, RDPEnabled, PSComputerName |
    Format-List
