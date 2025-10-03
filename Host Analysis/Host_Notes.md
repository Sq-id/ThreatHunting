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

### **Windows Host Investigation Checklist ** 
Copy and Paste out this checklist to use as a guide in endpoint investigation.

```
Situational Awareness:
[] hostname: 
    get-item HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName

[] IP:
[] Active Users: 
[] Current Connections?
    mem - vol -f .\memdump.mem windows.netscan.NetScan
    host - netstat -ano

[] 

```





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


### **Windows Memory Analysis**

**<ins>Capturing a full memory dump</ins>**

```
[] Open FTK
[] File > Capture memory 
[] pick outpath and name
[] after capture open powershell
[] get-filehash -algorithm md5 .\memdump.mem
```

**<ins>Capturing a process memory dump</ins>**

using procdump64:

```
[] Open Powershell
[] .\procdump64.exe -ma lsass.exe C:\Dir\to\Save -accepteula
[] get-filehash -algorithm md5 C:\dir\to\save\proc.dmp
```

**<ins>Capturing a Crash dump</ins>**

```
[] win + r > sysdm.cpl 
[] Advanced tab > settings > startup and recovery
[] configure mem dump in system faliure > write debugging information > Active Memory Dump
```


**<ins>Analysis with Volitility3</ins>**

Below is a checklist we can fill out as we go thru these steps to build a case on intrusions we find

**Vol Checklist**

```
[] Grab Open Network Connections
    [] What are the open connections to out of the network?
    [] What are the open connections to other hosts on the network and do they make sense?
    [] Are there any non-windows binaries running creating connections out?
    
[] Grab the Process tree list
    [] Are there any non-windows binaries running?
    [] Are these non-windows binaries running from a user or tmp directory?
    [] What is the virtual memory address and PID of the process in question?

[] Grap File's in question
    [] from the information above are we finding any active files we can dig into?
    [] what is the hash of the file in question? 
    [] check virustotal for hash
```




First we will need to load up the correct profile

```vol -f .\mem.mem windows.info```

From here we can start gatheing information on running Proccesses and open network connections

Listing Open network connections:

``` vol -f .\memory.dmp windows.netstat ```
            ** Then **
``` vol -f .\memory.dmp windows.netscan.NetScan ```

from here we can look at the ouput for non native windows binaries as a first check, deffinity want to pay attention to spelling for trying to hide in easy typos

after this we can start looking at proccesses running 

``` vol -f .\memory.dmp windows.pslist ```

            **Then**

``` vol -f .\memory.dmp windows.pstree ```

here we can start seeing the processes running that may also be connected to the netconnections, additionally were going to want to check and see where the binaries are running from.

from here we can start seeing what files we may have to dig into more.
in order to dig into a file we need its PID and virtual address so from the above process list we can pick thoes out and use them to provide as flags.

``` vol -f .\memory.dmp windows.dumpfiles --pid 4628 --virtaddr 0xca82b85325a0 ```

once we have the file lets grab the hash and provide that to virustotal as a quick check

```get-filehash -algorithm SHA1 .\file_sus.exe```

Now that we have the file lets start looking into what actions on objective where taken

To do this we can pull the cmdline histroy

```vol -f .\memory.dmp windows.cmdline```

from this we can use that previous PID to see what was ran when the processes started up.

**Listing Windows Host Info **
First Grab Offset of \REGISTRY\MACHINE\SYSTEM

```
vol -f .\memdump.mem windows.registry.hivelist
```

Once you have the offset


```
vol -f .\memdump.mem windows.registry.printkey --offset 0x86226008 --key "ControlSet001\Control\ComputerName"
```

Additionally this will work with any reg query.

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
With web as a initial access we first gotta know what service is installed as a web service.

We can look in the logging to see whats available.

```/var/log/```

if we start seeing things like ```/var/log/nginx``` or ```/var/log/apache2``` we should prob check there.


On that note. how do we detect funky traffic in these logs?


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


**<ins>Building a process tree</ins>**

with building a process tree out on a suspected file well want to follow the ppid of the process all the way up to pid 1

```

1. ausearch -i -x "<Command/file/text thats sus here>"
2. next record the starting location pid and the ppid
3. ausearch -i --pid <put previous pid here> 
4. record actions taken by the newly analyzed pid and the ppid
5. auseach -i --pid <new pid>
6. repeat.

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

### **Memory Analysis**

The Goals with memory analysis is to capture the data that's lifetime is often very short. if captured when compromise is suspected then we can look into the specifics of what is occuring and give a deeper look into what the attacker may have achived.


**<ins>Volatile memory</ins>**
Volatile memory is anything that is not preserved after system restart/powerloss/ service restart. In addition to this memory has a hierarchy to what is preserved first and what is instantly over written.

```
CPU Registers
    |
    V
CPU Cache
    |
    V
RAM
    |
    V
Disk Storage

```

When Going through volatile memory analysis, specifically on RAM this is divided up inbetween two spaces. kernal space and user space.

User Space consists of process launched by the user or applications. each space is seperate to be protected from others.

kernal space is a reserve for the OS and low-level services that will manage resources like drivers and memory access.

**<ins>Collection Objectives/Focus of analysis</ins>**

there are diffrent types of memory dumps and basically just detail how verbose they are. we have ```Full Memory Dump```,```Process Dump```, and ```PageFile And Swap Analysis```. in some cases you can also parse the systems hibernation file ```hiberfil.sys``` to extract RAM Contents. On linux the best tool to capture a memory image is
```LiME (Linux Memory Extractor)```

When Collecting a memory image where going to make sure we want to collect the following:

```
[] Running Processes
[] Open Network connections and ports
[] Logged-in users and recent commands
[] decrypted content, including encryption keys
[] injected code or fileless malware
```

Now the question arises, what should we look for in memory?

```
[] Suspicious or malicious processes that are running without a corresponding file on disk
[] DLL injection where malicious code is injected into memory space of a legit process
[] process hollowing and the mem space that is replaces with malicious code
[] API hooking and the interception of a normal function call
[] rootkits in a kernel level space where 

```

Timing on capture is obviously very important.

If you detect any of the following, capturing a mem_image is probably worth it:

```
[] Lateral Movement
    -If we start detecting lateral movement we can look into   what processes are running and what cmdline args have been ran to get a good timeline. this will also expose what credentials have been used and what account to monitor more.

[] Fileless/In-Memory Malware
    this type of activity will give us a look into the processes housing the beacons, we can gather C2 Addresses and if it is an interperted language like PS/VBS/Bash we can see whats ran in plaintext
[] Evidence Destruction
    This will also reveal a timeline for us, focusing on what cmdline args where ran and what was deleted/ the method of deletion.

```

**<ins>Capturing memory on linux</ins>**

full memory capture with **```LiME```**:

first we need to ensure LiME is installed
```git clone https://github.com/504ensicsLabs/LiME.git```




**<ins>Analysis with Volitility3</ins>**

First we will need to load up the correct profile

```vol -f .\mem.mem banners```

With in our ```volatility3\framework\constants\__init__.py``` file we need to replace the following ```REMOTE_ISF_URL = "https://raw.githubusercontent.com/leludo84/vol3-linux-profiles/main/banners-isf.json"```

now that thats out the way...

**grabing bash history:**

```
vol -f .\dump.mem linux.bash.Bash
```

**Grabbing the hosts interfaces and addr's:**

```
vol -f .\dump.mem linux.ip.Addr
```

**Listing all open processes:**

```
vol -f .\dump.mem linux.pslist.PsList
```

**grabbing open files in processes:**

```
vol -f .\dump.mem linux.lsof.Lsof
```

listing what teminal input from processes, by pid, ppid, and Process Name.

```


```


**grabbing Open network connections and nethooks:**

This will list the following properties (Pretty OP):
NetNS, Process Name, PID, TID, FD, Sock Offset, Family  Type, Proto, Source Addr, Source Port, Destination Addr, Destination Port, State, Filter 
```
vol -f .\dump.mem linux.sockstat
```
   
     **And**

```
vol -f .\dump.mem linux.netfilter
```

Checking for rootkits:
Pretty much were going to look for hooked syscalls 


```

```

**here is a list of all the common linux vol commands**

```
banners.Banners     Attempts to identify potential Linux banners in memory.
linux.bash.Bash     Recovers bash command history.
linux.boottime.Boottime  Retrieves system boot time.
linux.capabilities.Capabilities  Lists process capabilities.
linux.check_afinfo.Check_afinfo  Checks network address family information.
linux.check_creds.Check_creds  Identifies credential discrepancies.
linux.check_idt.Check_idt  Examines the interrupt descriptor table.
linux.check_modules.Check_modules  Lists kernel modules.
linux.check_syscall.Check_syscall  Checks syscall table integrity.
linux.ebpf.EBPF  Enumerates eBPF programs.
linux.elfs.Elfs  Lists ELF binaries mapped in memory.
linux.envars.Envars  Displays process environment variables.
linux.graphics.fbdev.Fbdev  Retrieves framebuffer device information.
linux.hidden_modules.Hidden_modules  Detects hidden kernel modules.
linux.iomem.IOMem  Retrieves memory map similar to /proc/iomem.
linux.kallsyms.Kallsyms  Extracts kernel symbol addresses.
linux.keyboard_notifiers.Keyboard_notifiers  Lists keyboard notifiers.
linux.kmsg.Kmsg  Reads the kernel log buffer.
linux.kthreads.Kthreads  Lists kernel threads.
linux.library_list.LibraryList  Enumerates shared libraries.
linux.lsmod.Lsmod  Lists loaded kernel modules.
linux.lsof.Lsof  Lists open files per process.
linux.malfind.Malfind  Scans for suspicious memory regions.
linux.modxview.Modxview  Detects kernel rootkits by module discrepancies.
linux.mountinfo.MountInfo  Retrieves mounted file system details.
linux.netfilter.Netfilter  Inspects netfilter hooks.
linux.pagecache.Files  Examines file-backed memory pages.
linux.pagecache.InodePages  Lists inode-associated memory pages.
linux.pidhashtable.PIDHashTable  Scans for hidden processes.
linux.proc.Maps  Displays memory maps of all processes.
linux.psaux.PsAux  Lists processes with command-line arguments.
linux.pscallstack.PsCallStack  Extracts kernel stack traces for processes.
linux.pslist.PsList  Lists active processes.
linux.psscan.PsScan  Scans for residual process structures.
linux.pstree.PsTree  Displays process hierarchy.
linux.ptrace.Ptrace  Lists processes with ptrace attachments.
linux.sockstat.Sockstat  Retrieves socket statistics.
linux.tty_check.tty_check  Checks for attached terminals.
linux.vmaregexscan.VmaRegExScan  Scans memory using regular expressions.
linux.vmayarascan.VmaYaraScan  Scans memory using YARA signatures.
linux.vmcoreinfo.VMCoreInfo  Extracts crash dump metadata.
```


-----------------------------------------------------------------------------------------------
</details>

-----------------------------------------------------------------------------------------------