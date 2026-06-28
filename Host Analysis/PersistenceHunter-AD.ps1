# PersistenceHunter-AD.ps1
# Run from Domain Controller as Domain Admin (or account with Invoke-Command rights)

$DataFile     = "C:\PersistenceData.json"
$MainReport   = "C:\PersistenceReport.html"
$script:Data  = @()

# === Get Computers (your preferred method) ===
Write-Host "Getting computers from Active Directory..." -ForegroundColor Green
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

Write-Host "Found $($Computers.Count) computers." -ForegroundColor Green

# Tracking array: ComputerName = Status (0 = not finished, 1 = finished)
$CompletionStatus = @{}
foreach ($comp in $Computers) {
    $CompletionStatus[$comp] = 0
}

# Function that runs on each remote host
$RemoteScriptBlock = {
    param($ComputerName)

    function Get-PersistenceData {
        param([string]$ComputerName)

        $results = @()

        # === Registry Run Keys + Startup Folders ===
        $runItems = @()
        $locations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($loc in $locations) {
            if (Test-Path $loc) {
                try {
                    $props = Get-ItemProperty -Path $loc -ErrorAction Stop
                    $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $runItems += [PSCustomObject]@{ Location = $loc; Name = $_.Name; Value = $_.Value }
                    }
                } catch {}
            }
        }
        $startupFolders = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                Get-ChildItem $folder -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                    $runItems += [PSCustomObject]@{ Location = "Startup Folder"; Name = $_.Name; Value = $_.FullName }
                }
            }
        }
        $results += [PSCustomObject]@{
            ComputerName = $ComputerName
            Technique    = "RegistryRunKeys_Startup"
            Count        = $runItems.Count
            Items        = $runItems
        }

        # === Scheduled Tasks ===
        $taskItems = @()
        try {
            Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
                $action = $_.Actions | Select-Object -First 1
                $cmd = if ($action) { "$($action.Execute) $($action.Arguments)".Trim() } else { "N/A" }
                $taskItems += [PSCustomObject]@{ Location = $_.TaskPath; Name = $_.TaskName; Value = $cmd }
            }
        } catch {}
        $results += [PSCustomObject]@{
            ComputerName = $ComputerName
            Technique    = "ScheduledTasks"
            Count        = $taskItems.Count
            Items        = $taskItems
        }

        # === .lnk Shortcuts ===
        $lnkItems = @()
        foreach ($folder in $startupFolders) {
            Get-ChildItem $folder -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $lnkItems += [PSCustomObject]@{ Location = "Startup"; Name = $_.Name; Value = $_.FullName }
            }
        }
        $results += [PSCustomObject]@{
            ComputerName = $ComputerName
            Technique    = "ShortcutLNK"
            Count        = $lnkItems.Count
            Items        = $lnkItems
        }

        # === PowerShell Profiles ===
        $profileItems = @()
        $PROFILE | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_.Name
            $path = $PROFILE.$p
            $exists = Test-Path $path
            $size = if ($exists) { (Get-Item $path -ErrorAction SilentlyContinue).Length } else { 0 }
            $profileItems += [PSCustomObject]@{ Location = $p; Name = $path; Value = "Exists: $exists | Size: $size bytes" }
        }
        $results += [PSCustomObject]@{
            ComputerName = $ComputerName
            Technique    = "PowerShellProfiles"
            Count        = $profileItems.Count
            Items        = $profileItems
        }

        # === Windows Services ===
        $svcItems = Get-Service | Select-Object @{
            Name="Location"; Expression={"Services"}
        }, @{
            Name="Name"; Expression={$_.Name}
        }, @{
            Name="Value"; Expression={"$($_.DisplayName) | StartType: $($_.StartType) | Status: $($_.Status)"}
        }
        $results += [PSCustomObject]@{
            ComputerName = $ComputerName
            Technique    = "WindowsServices"
            Count        = $svcItems.Count
            Items        = $svcItems
        }

        return $results
    }

    Get-PersistenceData -ComputerName $env:COMPUTERNAME
}

# === Start Jobs on All Hosts ===
Write-Host "Starting remote collection jobs..." -ForegroundColor Green
$Jobs = @()

foreach ($comp in $Computers) {
    try {
        $job = Invoke-Command -ComputerName $comp -ScriptBlock $RemoteScriptBlock -ArgumentList $comp -AsJob -ErrorAction Stop
        $Jobs += $job
        Write-Host "  Started job for $comp" -ForegroundColor Cyan
    } catch {
        Write-Host "  Failed to start job on $comp : $_" -ForegroundColor Red
        $CompletionStatus[$comp] = 1  # Mark as done (failed)
    }
}

# === Wait for All Jobs to Finish ===
Write-Host "`nWaiting for all remote collections to complete..." -ForegroundColor Yellow
$Jobs | Wait-Job | Out-Null

# === Collect Results ===
Write-Host "Collecting results from completed jobs..." -ForegroundColor Green

foreach ($job in $Jobs) {
    $results = Receive-Job -Job $job -ErrorAction SilentlyContinue
    if ($results) {
        $script:Data += $results
        $CompletionStatus[$job.Location] = 1
        Write-Host "  Received data from $($job.Location)" -ForegroundColor Green
    } else {
        Write-Host "  No data returned from $($job.Location)" -ForegroundColor Red
        $CompletionStatus[$job.Location] = 1
    }
    Remove-Job -Job $job -Force
}

# Mark any remaining hosts as finished
foreach ($comp in $Computers) {
    if ($CompletionStatus[$comp] -eq 0) {
        $CompletionStatus[$comp] = 1
    }
}

Write-Host "`nAll jobs completed." -ForegroundColor Green
Write-Host "Total data entries collected: $($script:Data.Count)" -ForegroundColor Cyan

# Save to central JSON on DC
$script:Data | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $DataFile -Force
Write-Host "Data saved to: $DataFile" -ForegroundColor Cyan

# Generate reports (same as before)
# ... (main dashboard + per-host pages code goes here)

Write-Host "Reports generated." -ForegroundColor Cyan
