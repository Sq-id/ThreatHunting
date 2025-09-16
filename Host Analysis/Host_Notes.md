# **<ins>Host Analysis Notes</ins>**

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
----------------------------------------------------------------------------
## **<ins>General Methodology</ins>**




----------------------------------------------------------------------------
## **<ins>Windows Host Analysis</ins>**

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




<ins>One-liners</ins>
>Powershell to filter windows process creation for powershell instences running
```
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddDays(-7)
} | Select TimeCreated,Id,Message -ExpandProperty Message | Select-String powershell
```




### **Detecting initial access**

### **Detecting Persistence**
    
### **Detecting Lateral Movement**
    
### **Detecting Communication**
    
### **Detecting PrivEsc**
    
### **Detecting Exfiltration**


----------------------------------------------------------------------------
## **<ins>Linux Host Analysis</ins>**

### **Detecting initial access**
        
### **Detecting Persistence**
    
### **Detecting Lateral Movement**
   
### **Detecting Communication**
    
### **Detecting PrivEsc**
    
### **Detecting Exfiltration**


----------------------------------------------------------------------------