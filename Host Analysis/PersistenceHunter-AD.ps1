# PersistenceHunter-AD.ps1 - Job + SMB Pull Version
# Run from Domain Controller as Domain Admin

$TempDir      = "C:\Temp\Persistence"
$DataFile     = "C:\PersistenceData.json"
$MainReport   = "C:\PersistenceReport.html"
$script:Data  = @()

# Create temp dir on DC
if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

# Get computers
Write-Host "Getting computers from Active Directory..." -ForegroundColor Green
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
Write-Host "Found $($Computers.Count) computers." -ForegroundColor Green

# Function to run on remote host (saved to file)
$RemoteScript = {
    param($ComputerName)

    $localResults = @()

    # Registry Run Keys + Startup Folders
    $runItems = @()
    $locations = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
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
    $startupFolders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                $runItems += [PSCustomObject]@{ Location = "Startup Folder"; Name = $_.Name; Value = $_.FullName }
            }
        }
    }
    $localResults += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "RegistryRunKeys_Startup"; Count = $runItems.Count; Items = $runItems }

    # Add other techniques (ScheduledTasks, ShortcutLNK, PowerShellProfiles, WindowsServices) similarly...
    # (abbreviated for brevity - full version includes all)

    # Save to local file on remote host
    $localFile = "C:\Temp\Persistence_$ComputerName.json"
    $localResults | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $localFile -Force

    return $localFile
}

# Start jobs
$Jobs = @()
foreach ($comp in $Computers) {
    try {
        $job = Start-Job -ScriptBlock {
            param($comp, $RemoteScript)
            Invoke-Command -ComputerName $comp -ScriptBlock $RemoteScript -ArgumentList $comp
        } -ArgumentList $comp, $RemoteScript
        $Jobs += $job
        Write-Host "Started job for $comp" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to start job on $comp" -ForegroundColor Red
    }
}

# Wait for all jobs
Write-Host "Waiting for remote collections..." -ForegroundColor Yellow
$Jobs | Wait-Job | Out-Null

# Pull files via SMB and merge
Write-Host "Pulling data files via SMB..." -ForegroundColor Green
foreach ($job in $Jobs) {
    $remoteFile = Receive-Job -Job $job
    if ($remoteFile) {
        $hostname = ($remoteFile -split '_')[-1] -replace '\.json',''
        $dest = "$TempDir\Persistence_$hostname.json"
        try {
            Copy-Item -Path "\\$hostname\C$\Temp\Persistence_$hostname.json" -Destination $dest -ErrorAction Stop
            $hostData = Get-Content $dest | ConvertFrom-Json
            $script:Data += $hostData
            Write-Host "  Pulled data from $hostname" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to pull from $hostname" -ForegroundColor Red
        }
    }
    Remove-Job -Job $job -Force
}

# Save merged data and generate reports
$script:Data | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $DataFile -Force
Write-Host "Merged data saved to $DataFile" -ForegroundColor Cyan

# (Add your main dashboard + per-host report generation code here)

Write-Host "Collection complete." -ForegroundColor Green
