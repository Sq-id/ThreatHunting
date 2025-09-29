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
-----------------------------------------------
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
With linux searching for TA activity luckily can be pretty cut and dry if you have the right commands. Luckily ive listed them below.

<details>

### **Locating Processes and Network Connections**

>List all running processes

```
ps aux
```

>List all running processes running as a specific user

```
ps aux | grep root
```

Lets say we have a process we beleive is planted by the TA. We can start our investigation by using the ```lsof``` command this will give a list of all open files and can be provided the pid of the process we currently have in question

```
lsof -p 12345
```

After analyzing our output here we can now start looking into if network connections are made. in all honesty id really start here. if you can start by using internal to external network connections as a base list to start your querys on then its probably a fair bet since attackers need external to internal connection. This can also reveal more information like what ports are being used, is it a common port? does the port appear to change over time? how often is the process calling back? these are all things we should be able to discover from running and analyzing the below command

```
lsof -i -P -n
```

Looking at our output we can run through a list to help decide whats wonky and whats normal external connection. We can further widdle this list down by checking to see if the list we have has any known IP addresses in it (e.g IP associated to a package manager). If we where able to narrow that down now we can start looking into src and dest ports in use. Does this pairing make sense? do we have a high port to 443? might be indicative of a C2 plant. do we standard protocols being used over non traditional ports they are assigned?




---------------------------------------------------------------------------------------------

### **Detecting initial access**

With linux, the primary reason to have this server in the first place is most likely to
host a service for other systems. 

<ins>Web IA</ins>
With web as a initial access

---------------------------------------------------------------------------------------------   

### **Detecting Persistence**

When detecting persistence on linux its layed out in a great way to create a running bash script to do it. Since linux everything is a file and persistence typically takes avantage of file reference and execution of contents we can make alil enumeration script to help us do this. first we need to understand common locations and what we want to grab out of them. 

>Common Persistence in linux

```
[] 1. Account Creation
[] 2. Cron Jobs
[] 3. Services
```
---------------------------------------------------------------------------------------------
**<ins>Account Creation</ins>**

When looking into account creation we can look into to the  ``` /var/log ``` directory
this directoy houses the  ``` /var/log/auth.log ``` file and from here we can grep for ```useradd``` or ```passwd``` commands run to check for account creation and minipulation

> checking for Account Creation
```
sudo cat /var/log/auth.log | grep useradd
```

>checking for Account Modification
```
sudo cat /var/log/auth.log | grep usermod
```
```
sudo cat /var/log/auth.log | grep useradd
```
```
sudo cat /var/log/auth.log | grep passwd
```

Next we can start seeing what shell this user logs in with

>checking spawn shell
```
sudo cat /etc/passwd
```
---------------------------------------------------------------------------------------------
**<ins>Cron Jobs</ins>**

Cron Jobs are pretty much the same as task scheduler in windows. these will run jobs on time based increment. these jobs can run commands or scripts that are referenced within the file.

>Location of Crontabs
```
User Crontabs:
/var/spool/cron/
/var/spool/cron/crontabs

System-wide Crontabs:
/etc/crontab
/etc/cron.d

```

When analyzing these we can just seach thru them and look for things like user cron jobs pointing to scripts in user dir's where we can then do some further reading on the script to see whats up.

---------------------------------------------------------------------------------------------
**<ins>Services</ins>**

The Reason services are ideal for attackers is for the fact they boot on startup and give you pretty granular control over longterm cover inside of a machine. Services are located inside the ```/etc/systemd/system/``` directory. To provide an example of how services can be used please see below

> Below is a sample service file
```
[Unit]
Description=Backup Manager
After=network.target

[Service]
ExecStart=/home/TA/.sus_proc
Restart=on-failure
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

above we can see a service file where on startup this badboy will kick off and launch a file from the TA's home directory. this file really can contain anything like a check to validte C2 beacon, backdoor acounts still active, a method of data exfil. so this is a really nice way to stay on target. the biggest downside to it is the fact its metioned here, to well known. None the less still a easy thing to check for 

>Example of how to pull every service file and grep the ExecStart locations
```
sudo cat /etc/systemd/system/* | grep ExecStart
```
This will give you some insight into what is being called and typically what sticks out is whats wrong.

Additional to this there are a few log locations we can check to see details of when/how its running

>syslogs
```
cat /var/log/syslog | grep .sus_proc
```
>journalctl
```
sudo journalctl -u .sus_proc
```


---------------------------------------------------------------------------------------------

### **Detecting Lateral Movement**



----------------------------------------------------------------------------------------------  

### **Detecting Communication**



-----------------------------------------------------------------------------------------------

### **Detecting PrivEsc**


-----------------------------------------------------------------------------------------------

### **Detecting Exfiltration**

-----------------------------------------------------------------------------------------------

</details>

----------------------------------------------------------------------------