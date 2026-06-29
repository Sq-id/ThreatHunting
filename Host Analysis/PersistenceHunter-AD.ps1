[CmdletBinding()]
param(
    [int]$ThrottleLimit = 15,
    [string]$OutputBase = "C:\temp\PerformanceCheck"
)

$ErrorActionPreference = 'Stop'

$CollectedPath = Join-Path $OutputBase "Collected"
$ReportsPath   = Join-Path $OutputBase "Reports"
$LogsPath      = Join-Path $OutputBase "Logs"

$null = New-Item -Path $CollectedPath -ItemType Directory -Force -ErrorAction SilentlyContinue
$null = New-Item -Path $ReportsPath   -ItemType Directory -Force -ErrorAction SilentlyContinue
$null = New-Item -Path $LogsPath      -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    Add-Content -Path (Join-Path $LogsPath "Collection_Summary.txt") -Value $logLine
    Write-Host $logLine
}

function Test-HostConnectivity {
    param([string]$ComputerName)
    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        WinRM        = $false
        SMB          = $false
        Reachable    = $false
    }
    try { $null = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop; $result.WinRM = $true } catch {}
    try { $null = Test-Path "\\$ComputerName\C$" -ErrorAction Stop; $result.SMB = $true } catch {}
    if ($result.WinRM -and $result.SMB) { $result.Reachable = $true }
    return $result
}

$CollectorScriptBlock = {
    param($ComputerName)

    $ErrorActionPreference = 'SilentlyContinue'
    $results = [ordered]@{
        ComputerName   = $ComputerName
        CollectionTime = (Get-Date).ToString("o")
        Domain         = $env:USERDNSDOMAIN
        Techniques     = @{}
    }

    function Get-RegistryPersistence {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            "HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls",
            "HKLM:\Software\Classes\*\Shell\Open\Command"
        )
        $items = @()
        foreach ($path in $regPaths) {
            try {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { 
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') 
                    } | ForEach-Object {
                        $items += [PSCustomObject]@{ Location = $path; Name = $_.Name; Value = $_.Value }
                    }
                }
            } catch {}
        }
        try {
            $userSids = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -match 'S-1-5-21' }
            foreach ($sid in $userSids) {
                $userPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
                $props = Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { 
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') 
                    } | ForEach-Object {
                        $items += [PSCustomObject]@{ Location = $userPath; Name = $_.Name; Value = $_.Value }
                    }
                }
            }
        } catch {}
        return $items
    }

    function Get-AllScheduledTasks {
        try {
            Get-ScheduledTask -TaskPath "\" | ForEach-Object {
                $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | "
                [PSCustomObject]@{
                    TaskPath = $_.TaskPath
                    TaskName = $_.TaskName
                    Actions  = $actions
                    UserId   = $_.Principal.UserId
                    State    = $_.State
                }
            }
        } catch { @() }
    }

    function Get-LNKFiles {
        $lnkItems = @()
        $searchPaths = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "C:\Users\Public\Desktop"
        )
        $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Name -notin @('Public','Default User','All Users') }
        foreach ($profile in $userProfiles) {
            $searchPaths += @(
                "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "$($profile.FullName)\Desktop"
            )
        }
        $shell = New-Object -ComObject WScript.Shell -ErrorAction SilentlyContinue
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter "*.lnk" -File -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $shortcut = $shell.CreateShortcut($_.FullName)
                        $lnkItems += [PSCustomObject]@{
                            Location   = $path
                            Name       = $_.Name
                            TargetPath = $shortcut.TargetPath
                            Arguments  = $shortcut.Arguments
                        }
                    } catch {}
                }
            }
        }
        return $lnkItems
    }

    function Get-PowerShellProfiles {
        $profilePaths = @(
            @{ Type = "AllUsersAllHosts";     Path = $PROFILE.AllUsersAllHosts },
            @{ Type = "AllUsersCurrentHost";  Path = $PROFILE.AllUsersCurrentHost },
            @{ Type = "CurrentUserAllHosts";  Path = $PROFILE.CurrentUserAllHosts },
            @{ Type = "CurrentUserCurrentHost"; Path = $PROFILE.CurrentUserCurrentHost }
        )
        $existing = @()
        foreach ($p in $profilePaths) {
            if (Test-Path $p.Path) {
                $existing += [PSCustomObject]@{
                    ProfileType = $p.Type
                    Path        = $p.Path
                    Size        = (Get-Item $p.Path).Length
                    Content     = Get-Content $p.Path -Raw
                }
            }
        }
        return $existing
    }

    function Get-AllServices {
        Get-WmiObject Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, Description
    }

    function Get-AdminShareExes {
        try {
            $adminPath = "\\$env:COMPUTERNAME\ADMIN$"
            if (Test-Path $adminPath) {
                $exes = Get-ChildItem -Path $adminPath -Filter "*.exe" -File -ErrorAction SilentlyContinue
                return [PSCustomObject]@{
                    Exists   = $true
                    ExeCount = $exes.Count
                    ExeNames = ($exes | Select-Object -ExpandProperty Name) -join ", "
                }
            }
        } catch {}
        return [PSCustomObject]@{ Exists = $false; ExeCount = 0; ExeNames = "" }
    }

    function Get-WSLDetection {
        $wslLinks = @()
        $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $userProfiles) {
            $possiblePaths = @(
                "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
                "$($profile.FullName)\Desktop"
            )
            foreach ($p in $possiblePaths) {
                if (Test-Path $p) {
                    Get-ChildItem -Path $p -Filter "*wsl*.lnk" -File -ErrorAction SilentlyContinue | ForEach-Object {
                        $wslLinks += [PSCustomObject]@{
                            User     = $profile.Name
                            Location = $p
                            Name     = $_.Name
                        }
                    }
                }
            }
        }
        return $wslLinks
    }

    $results.Techniques["RegistryRunKeys_Startup"] = Get-RegistryPersistence
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: RegistryRunKeys_Startup ($($results.Techniques["RegistryRunKeys_Startup"].Count) items)"

    $results.Techniques["ScheduledTasks"] = Get-AllScheduledTasks
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: ScheduledTasks ($($results.Techniques["ScheduledTasks"].Count) items)"

    $results.Techniques["ShortcutLNK"] = Get-LNKFiles
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: ShortcutLNK ($($results.Techniques["ShortcutLNK"].Count) items)"

    $results.Techniques["PowerShellProfiles"] = Get-PowerShellProfiles
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: PowerShellProfiles ($($results.Techniques["PowerShellProfiles"].Count) items)"

    $results.Techniques["WindowsServices"] = Get-AllServices
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: WindowsServices ($($results.Techniques["WindowsServices"].Count) items)"

    $results.Techniques["AdminShareExes"] = Get-AdminShareExes
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: AdminShareExes"

    $results.Techniques["WSLDetection"] = Get-WSLDetection
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Completed: WSLDetection ($($results.Techniques["WSLDetection"].Count) items)"

    $null = New-Item -Path "C:\temp" -ItemType Directory -Force -ErrorAction SilentlyContinue
    $jsonPath = "C:\temp\Performance_$($env:COMPUTERNAME).json"
    $results | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
    
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] JSON written successfully for $env:COMPUTERNAME"
    return $jsonPath
}

Write-Log "=== PerformanceCheck-AD Collection Started ==="

try {
    $allComputers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
    Write-Log "Retrieved $($allComputers.Count) computers from Active Directory"
} catch {
    Write-Log "Failed to query Active Directory: $_" "ERROR"
    exit 1
}

Write-Log "Starting connectivity checks..."
$connectivityResults = @()
$unreachable = @()

foreach ($comp in $allComputers) {
    $conn = Test-HostConnectivity -ComputerName $comp
    $connectivityResults += $conn
    if (-not $conn.Reachable) { $unreachable += $comp }
}

$unreachable | Out-File (Join-Path $LogsPath "Unreachable_Hosts.txt") -Encoding UTF8
Write-Log "Connectivity check complete. Unreachable hosts: $($unreachable.Count)"

$reachableHosts = $connectivityResults | Where-Object { $_.Reachable } | Select-Object -ExpandProperty ComputerName

if ($reachableHosts.Count -eq 0) {
    Write-Log "No reachable hosts found. Exiting." "ERROR"
    exit 1
}

Write-Log "Starting collection against $($reachableHosts.Count) reachable hosts (ThrottleLimit: $ThrottleLimit)"

$jobs = @()
$jobLookup = @{}   # job Id -> hostname

foreach ($hostName in $reachableHosts) {
    while ((Get-Job -State Running).Count -ge $ThrottleLimit) {
        Start-Sleep -Milliseconds 1500
    }
    $job = Invoke-Command -ComputerName $hostName -ScriptBlock $CollectorScriptBlock -ArgumentList $hostName -AsJob
    $jobs += $job
    $jobLookup[$job.Id] = $hostName
}

Write-Log "All jobs launched. Monitoring progress..."

while ($jobs | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'NotStarted' }) {
    foreach ($job in ($jobs | Where-Object { $_.HasMoreData })) {
        $hostName = $jobLookup[$job.Id]
        $output = Receive-Job -Job $job -Keep
        if ($output) {
            foreach ($line in $output) {
                if ($line) {
                    Write-Host "[$hostName] $line" -ForegroundColor Cyan
                }
            }
        }
    }
    Start-Sleep -Milliseconds 800
}

# Final receive for any remaining output on completed jobs
foreach ($job in $jobs) {
    $hostName = $jobLookup[$job.Id]
    $output = Receive-Job -Job $job
    if ($output) {
        foreach ($line in $output) {
            if ($line) {
                Write-Host "[$hostName] $line" -ForegroundColor Cyan
            }
        }
    }
}

Write-Log "All remote jobs completed. Retrieving JSON files..."

$collectedCount = 0
foreach ($job in $jobs) {
    $hostName = $jobLookup[$job.Id]
    $jsonRemote = "\\$hostName\C$\temp\Performance_$hostName.json"
    $jsonLocal  = Join-Path $CollectedPath "$hostName.json"
    
    try {
        if (Test-Path $jsonRemote) {
            Copy-Item -Path $jsonRemote -Destination $jsonLocal -Force -ErrorAction Stop
            Remove-Item -Path $jsonRemote -Force -ErrorAction SilentlyContinue
            $collectedCount++
        } else {
            Write-Log "JSON file not found for host: $hostName" "WARN"
        }
    } catch {
        Write-Log "Failed to retrieve data from $hostName : $_" "ERROR"
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

Write-Log "Successfully retrieved data from $collectedCount hosts."
Write-Log "=== PerformanceCheck-AD Finished ==="
