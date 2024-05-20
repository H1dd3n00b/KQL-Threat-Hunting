# NTDS.dit Credential Dump Performed on a Domain Controller

### Description

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.

### Microsoft Defender XDR & Microsoft Sentinel
```
DeviceProcessEvents
| where DeviceName matches regex "(?i)dc" // Filter for Domain Controllers according to your respective device naming convention, currently this query looks for devices with the string "dc" in them
| where ProcessCommandLine has_any ("activate instance ntds", "ac i ntds", "create full", "q q") or ProcessCommandLine has_any ("YWN0aXZhdGUgaW5zdGFuY2UgbnRkcw==", "YWMgaSBudGRz", "Y3JlYXRlIGZ1bGw=", "cSBx")
```

### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique ID: T1003.003
- [OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
