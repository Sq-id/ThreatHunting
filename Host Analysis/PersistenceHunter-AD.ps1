# PersistenceHunter-AD.ps1
# Run this from a Domain Controller

$DataFile = "C:\PersistenceData.json"
$MainReport = "C:\PersistenceReport.html"
$script:Data = @()

# Get all Windows computers from AD
Write-Host "Querying Active Directory for Windows computers..." -ForegroundColor Green
$Computers = Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} | Select-Object -ExpandProperty Name

Write-Host "Found $($Computers.Count) Windows computers." -ForegroundColor Green

function Invoke-LocalPersistenceCollection {
    param([string]$ComputerName)
    
    $localData = @()

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
    $localData += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "RegistryRunKeys_Startup"; Count = $runItems.Count; Items = $runItems }

    # Scheduled Tasks
    $taskItems = @()
    try {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $action = $_.Actions | Select-Object -First 1
            $cmd = if ($action) { "$($action.Execute) $($action.Arguments)".Trim() } else { "N/A" }
            $taskItems += [PSCustomObject]@{ Location = $_.TaskPath; Name = $_.TaskName; Value = $cmd }
        }
    } catch {}
    $localData += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "ScheduledTasks"; Count = $taskItems.Count; Items = $taskItems }

    # .lnk Shortcuts
    $lnkItems = @()
    foreach ($folder in $startupFolders) {
        Get-ChildItem $folder -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $lnkItems += [PSCustomObject]@{ Location = "Startup"; Name = $_.Name; Value = $_.FullName }
        }
    }
    $localData += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "ShortcutLNK"; Count = $lnkItems.Count; Items = $lnkItems }

    # PowerShell Profiles
    $profileItems = @()
    $PROFILE | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_.Name
        $path = $PROFILE.$p
        $exists = Test-Path $path
        $size = if ($exists) { (Get-Item $path -ErrorAction SilentlyContinue).Length } else { 0 }
        $profileItems += [PSCustomObject]@{ Location = $p; Name = $path; Value = "Exists: $exists | Size: $size bytes" }
    }
    $localData += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "PowerShellProfiles"; Count = $profileItems.Count; Items = $profileItems }

    # Windows Services
    $svcItems = Get-Service | Select-Object @{
        Name="Location"; Expression={"Services"}
    }, @{
        Name="Name"; Expression={$_.Name}
    }, @{
        Name="Value"; Expression={"$($_.DisplayName) | StartType: $($_.StartType) | Status: $($_.Status)"}
    }
    $localData += [PSCustomObject]@{ ComputerName = $ComputerName; Technique = "WindowsServices"; Count = $svcItems.Count; Items = $svcItems }

    return $localData
}

# Run collection on all computers via Invoke-Command
Write-Host "Running collection across all hosts (this may take time)..." -ForegroundColor Green

$allResults = Invoke-Command -ComputerName $Computers -ScriptBlock {
    param($ComputerName)
    . ([scriptblock]::Create($using:MyInvocation.MyCommand.Definition))  # Import the function
    Invoke-LocalPersistenceCollection -ComputerName $env:COMPUTERNAME
} -ArgumentList $env:COMPUTERNAME -ThrottleLimit 20 -ErrorAction SilentlyContinue

# Flatten results into script scope
foreach ($result in $allResults) {
    $script:Data += $result
}

# Save central JSON on the DC
$script:Data | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $DataFile -Force
Write-Host "Central data saved to: $DataFile" -ForegroundColor Cyan

# Generate Main Dashboard + Per-Host Pages
Write-Host "Generating reports..." -ForegroundColor Green

$allHosts = $script:Data | Select-Object -ExpandProperty ComputerName -Unique

# Main Dashboard
$mainHtml = @"
<!DOCTYPE html>
<html><head><title>Persistence Multi-Host Report</title>
<style>
    body { font-family: Segoe UI, Arial; margin: 30px; background: #f9f9f9; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; cursor: pointer; }
    th { background: #eee; }
    tr:nth-child(even) { background: #f8f8f8; }
    a { color: #0066cc; }
    input { margin: 10px 0; padding: 5px; width: 300px; }
</style>
<script>
function sortTable(n) {
  var table = document.getElementById("summaryTable");
  var rows = Array.from(table.rows).slice(1);
  var dir = table.dataset.sortDir === "asc" ? "desc" : "asc";
  table.dataset.sortDir = dir;
  rows.sort((a, b) => {
    let x = a.cells[n].textContent.trim();
    let y = b.cells[n].textContent.trim();
    if (!isNaN(x) && !isNaN(y)) { x = parseFloat(x); y = parseFloat(y); }
    return dir === "asc" ? (x > y ? 1 : x < y ? -1 : 0) : (x < y ? 1 : x > y ? -1 : 0);
  });
  rows.forEach(row => table.appendChild(row));
}
function filterTable() {
  var input = document.getElementById("filterInput");
  var filter = input.value.toUpperCase();
  var table = document.getElementById("summaryTable");
  var rows = table.getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {
    var td = rows[i].getElementsByTagName("td")[0];
    if (td) {
      rows[i].style.display = td.textContent.toUpperCase().indexOf(filter) > -1 ? "" : "none";
    }
  }
}
</script></head><body>
<h1>Persistence Multi-Host Report</h1>
<p>Generated: $(Get-Date) | Total Hosts: $($allHosts.Count)</p>
<input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Filter by hostname...">
<h2>Main Dashboard - Host Summary (click headers to sort)</h2>
<table id="summaryTable" data-sort-dir="asc">
<tr><th onclick="sortTable(0)">ComputerName</th><th onclick="sortTable(1)">RegistryRunKeys_Startup</th><th onclick="sortTable(2)">ScheduledTasks</th><th onclick="sortTable(3)">ShortcutLNK</th><th onclick="sortTable(4)">PowerShellProfiles</th><th onclick="sortTable(5)">WindowsServices</th><th>Details</th></tr>
"@

foreach ($h in $allHosts) {
    $r = ($script:Data | Where-Object { $_.ComputerName -eq $h -and $_.Technique -eq "RegistryRunKeys_Startup" }).Count
    $s = ($script:Data | Where-Object { $_.ComputerName -eq $h -and $_.Technique -eq "ScheduledTasks" }).Count
    $l = ($script:Data | Where-Object { $_.ComputerName -eq $h -and $_.Technique -eq "ShortcutLNK" }).Count
    $p = ($script:Data | Where-Object { $_.ComputerName -eq $h -and $_.Technique -eq "PowerShellProfiles" }).Count
    $w = ($script:Data | Where-Object { $_.ComputerName -eq $h -and $_.Technique -eq "WindowsServices" }).Count
    $mainHtml += "<tr><td>$h</td><td>$r</td><td>$s</td><td>$l</td><td>$p</td><td>$w</td><td><a href='$($h)_details.html'>View Details</a></td></tr>"
}

$mainHtml += "</table></body></html>"
$mainHtml | Out-File -Encoding UTF8 $MainReport -Force

# Per-host detail pages
foreach ($h in $allHosts) {
    $hostData = $script:Data | Where-Object { $_.ComputerName -eq $h }
    $detailHtml = @"
<!DOCTYPE html>
<html><head><title>Details - $h</title>
<style>
    body { font-family: Segoe UI, Arial; margin: 30px; background: #f9f9f9; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #eee; }
</style></head><body>
<h1>Details for $h</h1>
<a href='$MainReport'>← Back to Main Dashboard</a>
"@
    foreach ($tech in $hostData) {
        $detailHtml += "<h2>$($tech.Technique) — Count: $($tech.Count)</h2>"
        if ($tech.Items.Count -gt 0) {
            $detailHtml += "<table><tr><th>Location</th><th>Name</th><th>Value</th></tr>"
            foreach ($item in $tech.Items) {
                $detailHtml += "<tr><td>$($item.Location)</td><td>$($item.Name)</td><td>$($item.Value)</td></tr>"
            }
            $detailHtml += "</table>"
        } else {
            $detailHtml += "<p><em>No items found.</em></p>"
        }
    }
    $detailHtml += "</body></html>"
    $detailHtml | Out-File -Encoding UTF8 "$h`_details.html" -Force
}

Write-Host "`nMain Dashboard: $MainReport" -ForegroundColor Cyan
Write-Host "Per-host detail pages generated in current directory." -ForegroundColor Cyan
Invoke-Item $MainReport