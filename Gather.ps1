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
        $usrDirs=$usrDirs.Name
        $startupFolder=@('C:\ProgramData\Microsoft\windows\Start Menu\Programs\StartUp')
        foreach($usrDir in $usrDirs){
            $startupFolder += "C:\Users\$usrDir\Appdata\Roaming\Microsoft\Start Menu\Programs\Startup"
            
        }
        foreach($startup in $startupFolder){
            Write-host "Checking $startup"
            Get-ChildItem $startup -ErrorAction SilentlyContinue
        }

      write-host "Checking Powershell profiles..." -ForegroundColor $random
            
  
      }

  '2'{
      Write-host "Listing Login Times for all users..." 
      
      write-host "Listing File Creation..." 

      write-host "Listing Process execution..."

      write-host "Listing Connections Made..."
  
      }
  '3'{
      Write-host "Listing Current Connections..." 
      
      write-host "Listing Current Users and Logged on users..." 

      write-host "Checking for recently made files..."

      write-host "Checking For ..."
      
  
      }
    



}
