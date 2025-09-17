# **<ins>Host Analysis Notes</ins>**
<details>

    [] Methodology
    [] Windows
        [] Detecting initial access
        [] Detecting Persistence
        [] Detecting Lateral Movement
        [] Detecting Communication
        [] Detecting PrivEsc
        [] Detecting Exfiltration

    [] Linux
        [] Detecting initial access
        [] Detecting Persistence
        [] Detecting Lateral Movement
        [] Detecting Communication
        [] Detecting PrivEsc
        [] Detecting Exfiltration
</details>

----------------------------------------------------------------------------
## **<ins>General Methodology</ins>**

<details>


</details>

----------------------------------------------------------------------------
## **<ins>Windows Host Analysis</ins>**

<details>

### **Increasing Visablilty and Host Logging**
Audit Policies
>Audit Policies are used to dictate which security related events are recorded. They can be used to record telemerty on activity like account logon events, Account Management, System events, Privilege use, And much more

```
[] 1. Launch Secpol.msc
[] 2. Local Policies > Audit Policies > enable auditing on all items
[] 3. Advanced Audit Policy Configuration > enable Auditing on all items
```
    
Process Visibility
>Increasing Process visability and enabling Process creation events to be recorded will allow for tracking of process creation and aid in the detection of TA activity.

```
[] 1. Launch Secpol.msc
[] 2. Security Settings > Advanced Audit Policy Configuration > System Audit Policies - Local Group Policy Object > Detailed Tracking.
[] 3. Audit Process Creation > Properties
[] 4. Select Config box, select Success, select Failure.
```

### **Tracking Processes**
```
Event Log / Name / Event ID
---------------------------------
Security / Process Creation / 4688

```
When Tracking down Processes the information i like to gather is below

```
[] 1. Who ran it:
[] 2. When did it run:
[] 3. What permissions did it run as:
[] 4. Where did it run From:
[] 5. What did it do:
```




<ins>Detect Me's</ins>

>Powershell to list all processes spawned and display unique Cmdline Args ran

```
$result = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688;StartTime = (Get-Date).AddDays(-7)} | ForEach-Object {
    $eventXml = ([xml]$_.ToXml()).Event
    $evt = [ordered]@{
        EventDate = [DateTime]$eventXml.System.TimeCreated.SystemTime
        Computer  = $eventXml.System.Computer
    }
    $eventXml.EventData.ChildNodes | ForEach-Object { $evt[$_.Name] = $_.'#text' }
    [PsCustomObject]$evt
}
$cmdCount = @()
Foreach($res in $result.CommandLine){
    $cmdCount += $res
}
$cmdCount | Sort-Object -unique
```

>Powershell to filter windows process creation for powershell instences running
```
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddDays(-7)
} | Select TimeCreated,Id,Message -ExpandProperty Message | Select-String powershell
```

### **Detecting account manipulation**
```
Event Log / Name / Event ID / Scope
--------------------------------------------------
Security / Account Logon Faliure / 4625 / Local
Security / Account Logon Success / 4624 / Local



``` 


### **Detecting initial access**

### **Detecting Persistence**
    
### **Detecting Lateral Movement**
    
### **Detecting Communication**
    
### **Detecting PrivEsc**
    
### **Detecting Exfiltration**

### **Detecting Indicator Removal**

Detecting TA Actions to cover their tracks

```
Event Log / Name / Event ID / Scope
---------------------------------------------------------
Security / Security Event Log is Cleared / 1102 / Domain



``` 


Attackers will clear event logs to decrease the visabliity into actions they preformed.
Below are some methods to do it and may help in identification of these actions

Logs are stored on disk at the following location
```
C:\windows\System32\winevt\logs\
```
that being said the first method you could use if permissions allow is to straight delete that directory.

other cmdline and powershell methods to do so are listed below

>cmd

```
wevtutil cl system
wevtutil cl security
wevtutil cl application

```


<ins>Detect Me's</ins>

> Check to see if event logs where cleared.
```
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 1102
    StartTime = (Get-Date).AddDays(-7)
}
```

</details>

----------------------------------------------------------------------------
## **<ins>Linux Host Analysis</ins>**

<details>

### **Detecting initial access**
        
### **Detecting Persistence**
    
### **Detecting Lateral Movement**
   
### **Detecting Communication**
    
### **Detecting PrivEsc**
    
### **Detecting Exfiltration**

</details>

----------------------------------------------------------------------------