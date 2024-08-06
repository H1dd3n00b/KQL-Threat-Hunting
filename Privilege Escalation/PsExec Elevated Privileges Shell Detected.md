# PsExec Elevated Privileges Shell Detected

### Description

This rule detects PsExec usage with elevated privileges, indicating potential malicious activities such as remote execution and privilege escalation via temporary services.

### Microsoft Defender XDR & Microsoft Sentinel
```
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessIntegrityLevel == "High"
| where FileName == "PsExec.exe"
| where ProcessCommandLine matches regex @"(\s|^)-[sidhlup]+(\s|$)"
```

### MITRE ATT&CK Mapping
- Tactic: Privilege Escalation
- Technique ID: T1543.003
- [Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 06/08/2024    | Initial publish                        |
