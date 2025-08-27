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
      Write-host "Gathering Registry Data..." 
            $RegCheckpoints = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            "HKLM:\SYSTEM\CurrentControlSet\Services","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree","HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
      Foreach($RegCheckpoint in $RegCheckpoints){
        

      
      }
      

      
      write-host "Gathering scheduled tasks..." 

      write-host "Checking Start-up folder..."

      write-host "Checking Powershell profiles..."
      
  
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
