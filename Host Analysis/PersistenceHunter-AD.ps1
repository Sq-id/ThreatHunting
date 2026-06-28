# PersistenceHunter-AD.ps1
# Run from Domain Controller

$CollectorScript = "C:\Gpupdate_Check.ps1"
$TempDir        = "C:\Temp\Persistence"
$DataFile       = "C:\PersistenceData.json"
$MainReport     = "C:\PersistenceReport.html"
$script:Data    = @()

# === Create the remote collector script ===
$collectorContent = @'
param($ComputerName)

$results = @()

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
$results += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "RegistryRunKeys_Startup"; Count = $runItems.Count; Items = $runItems }

# Scheduled Tasks
$taskItems = @()
try {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        $cmd = if ($action) { "$($action.Execute) $($action.Arguments)".Trim() } else { "N/A" }
        $taskItems += [PSCustomObject]@{ Location = $_.TaskPath; Name = $_.TaskName; Value = $cmd }
    }
} catch {}
$results += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "ScheduledTasks"; Count = $taskItems.Count; Items = $taskItems }

# .lnk Shortcuts
$lnkItems = @()
foreach ($folder in $startupFolders) {
    Get-ChildItem $folder -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $lnkItems += [PSCustomObject]@{ Location = "Startup"; Name = $_.Name; Value = $_.FullName }
    }
}
$results += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "ShortcutLNK"; Count = $lnkItems.Count; Items = $lnkItems }

# PowerShell Profiles
$profileItems = @()
$PROFILE | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | ForEach-Object {
    $p = $_.Name
    $path = $PROFILE.$p
    $exists = Test-Path $path
    $size = if ($exists) { (Get-Item $path -ErrorAction SilentlyContinue).Length } else { 0 }
    $profileItems += [PSCustomObject]@{ Location = $p; Name = $path; Value = "Exists: $exists | Size: $size bytes" }
}
$results += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "PowerShellProfiles"; Count = $profileItems.Count; Items = $profileItems }

# Windows Services
$svcItems = Get-Service | Select-Object @{
    Name="Location"; Expression={"Services"}
}, @{
    Name="Name"; Expression={$_.Name}
}, @{
    Name="Value"; Expression={"$($_.DisplayName) | StartType: $($_.StartType) | Status: $($_.Status)"}
}
$results += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "WindowsServices"; Count = $svcItems.Count; Items = $svcItems }

# Save locally on remote host
$localFile = "C:\Temp\Persistence_$ComputerName.json"
$results | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $localFile -Force
return $localFile
'@

$collectorContent | Out-File -Encoding UTF8 $CollectorScript -Force

# Get computers
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Run collection
foreach ($comp in $Computers) {
    try {
        $remoteFile = Invoke-Command -ComputerName $comp -FilePath $CollectorScript -ArgumentList $comp -ErrorAction Stop
        if ($remoteFile) {
            $dest = "$TempDir\Persistence_$comp.json"
            Copy-Item -Path "\\$comp\C$\Temp\Persistence_$comp.json" -Destination $dest -ErrorAction Stop
            $hostData = Get-Content $dest | ConvertFrom-Json
            $script:Data += $hostData
            Write-Host "Collected from $comp" -ForegroundColor Green
        }
    } catch {
        Write-Host "Failed on $comp : $_" -ForegroundColor Red
    }
}

# Cleanup remote collector script
foreach ($comp in $Computers) {
    try {
        Invoke-Command -ComputerName $comp -ScriptBlock { Remove-Item "C:\Gpupdate_Check.ps1" -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
    } catch {}
}

# Save merged data
$script:Data | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $DataFile -Force
Write-Host "Data saved to $DataFile" -ForegroundColor Cyan

# Generate reports (add your dashboard code here)
Write-Host "Collection complete." -ForegroundColor Green
