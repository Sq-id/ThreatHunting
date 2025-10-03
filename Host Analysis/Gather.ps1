$banner="
  __            _                  _   _       
 / _|_   _  ___| | __  _ __  _   _| |_(_)_ __  
| |_| | | |/ __| |/ / | '_ \| | | | __| | '_ \ 
|  _| |_| | (__|   <  | |_) | |_| | |_| | | | |
|_|  \__,_|\___|_|\_\ | .__/ \__,_|\__|_|_| |_|
                      |_|                      
"

$Length = $banner.Length
$counts = 0 .. $Length

$colors = [enum]::GetValues([System.ConsoleColor])
$colors = $colors -replace 'Black','Green' -replace 'DarkBlue','DarkYellow' -replace 'Blue','Magenta'
$random = $colors | Get-Random

foreach($m in $counts){
Write-Host $banner[$m] -NoNewline -ForegroundColor $random
$milisecondRange = 1..4
$randMili = $milisecondRange | Get-Random
sleep -Milliseconds ".$randMili"
}

Write-Host "
===========Select an option to preform============
|| [1]. Gather persistence Locations            ||
|| [2]. Gather Sus EventLogs                    ||
|| [3]. General system information              ||
==================================================
" -BackgroundColor Black -ForegroundColor $Random
$MainSelection = Read-Host "Select one" 


switch($MainSelection){

  '1'{
      Write-host "Gathering Registry Data..." -ForegroundColor $random
            $RegCheckpoints=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            "HKLM:\SYSTEM\CurrentControlSet\Services","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree","HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
      Foreach($RegCheckpoint in $RegCheckpoints){
        Get-Item $RegCheckpoint -ErrorAction SilentlyContinue
        }
      
      write-host "Gathering scheduled tasks..." -ForegroundColor $random
            $tasks=Get-ScheduledTask
            $taskRes=
            foreach($task in $tasks){
                if(($task.Author -eq 'Microsoft Corporation') -or ($task.Author -eq 'Microsoft') -or ($task.Author -eq 'Mozilla') -or ($task.Author -eq 'Microsoft Corporation.')){
                    $task | Out-Null

                    }
                else{
                    [pscustomobject]@{
                        TaskName=$task.TaskName
                        Author=$task.Author
                        Action=$task.actions.Execute
                        Description=$task.Description
                        Path=$task.Path}
                
                }
            }
            $taskRes
      write-host "Checking Start-up folder..." -ForegroundColor $random
        $usrDirs=Get-ChildItem C:\Users
        $startupFolder=@('C:\ProgramData\Microsoft\windows\Start Menu\Programs\StartUp')
        foreach($usrDir in $usrDirs.Name){
            $startupFolder += "C:\Users\$usrDir\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            
        }
        foreach($startup in $startupFolder){
            Write-host "Checking $startup" -ForegroundColor $random
            Get-ChildItem $startup -ErrorAction SilentlyContinue
        }

      write-host "Checking Powershell profiles..." -ForegroundColor $random
          $psprofiles=@($profile.AllUsersAllHosts,$profile.AllUsersCurrentHost,$profile.CurrentUserAllHosts,$profile.CurrentUserCurrentHost)
          foreach($usrDir in $usrDirs){
            $psprofiles+="C:\Users\$usrDir\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
            $psprofiles+="C:\Users\$usrDir\Documents\WindowsPowerShell\profile.ps1"
          }
          $psprofiles=$psprofiles | Select-Object -Unique

            foreach($psprof in $psprofiles){
                $tmp_tp = Test-Path $psprof
                
                if($tmp_tp -eq $true){
                    write-host "[+] PS Profile present at: $psprof" -ForegroundColor Red -ErrorAction SilentlyContinue
                
                }
                else{
                    write-host "[-] No PSProfile located at: $psprof" -ForegroundColor Cyan -ErrorAction SilentlyContinue
                
                }
            
            }
      }

  '2'{
      Write-host "Listing Login Times for all users..." -ForegroundColor $random
        Write-host "Listing Local Logon information.." -ForegroundColor $random
        $succLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -ErrorAction SilentlyContinue
        $failedLogins = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4625 }
        $ExplicitLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4648} -ErrorAction SilentlyContinue
        
        $failedresult = Get-WinEvent -FilterHashtable $failedLogins  | ForEach-Object {
            $eventXml = ([xml]$_.ToXml()).Event
            $userName = ($eventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $computer = ($eventXml.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    
            [PSCustomObject]@{
            Time     = [DateTime]$eventXml.System.TimeCreated.SystemTime
            UserName = $userName
            Computer = $computer
             }
            };$failedresult

    




      write-host "Listing File Creation..." -ForegroundColor $random
            
      write-host "Listing Process execution..." -ForegroundColor $random

      write-host "Listing Connections Made..." -ForegroundColor $random
  
      }
  '3'{ 

      Write-Host "Listing Current Connections..." -ForegroundColor $random
        $netConnections = Get-NetTCPConnection
        $netConToProc = foreach ($netConnection in $netConnections) {
        $process = Get-Process -Id $netConnection.OwningProcess
        [pscustomobject]@{
            LocalAddress = $netConnection.LocalAddress
            LocalPort = $netConnection.LocalPort
            RemoteAddress = $netConnection.RemoteAddress
            State = $netConnection.State
            OwningProcess = $process.Name
            OwningProcessLocation = $process.Path
            }
        }
        $netConToProc | Format-Table -AutoSize

      write-host "Listing Current Users and Logged on users..." -ForegroundColor $random
            Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName
      write-host "Checking for Non-Signed executables and Drivers" -ForegroundColor $random
        $drivers=Get-WindowsDriver -Online -All | select * |Where-Object {$_.DriverSignature -ne 'Signed'}
        $drivers
      write-host "Checking For ..." -ForegroundColor $random
      
  
      }
    



}
