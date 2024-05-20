# BABYWIPER Related Activity

### Description

BABYWIPER is a malware wiper that is used in the Israel-Palestine conflict. It wipes the files off the target system by overwriting them multiple times, before finally deleting them.

### Microsoft Defender XDR & Microsoft Sentinel
```
let MalProcess = dynamic(["cmd.exe /c vssadmin delete shadows /quiet /all", "cmd.exe /c /wmic shadowcopy delete", "cmd.exe /c bcdedit /set", "recoveryenabled"]);
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any (MalProcess) or ProcessCommandLine has_any (MalProcess)
| project TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```

### MITRE ATT&CK Mapping
- Tactics: Impact
- Technique ID: T1485
- [Data Destruction](https://attack.mitre.org/techniques/T1485/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
