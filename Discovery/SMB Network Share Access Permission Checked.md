# SMB Network Share Access Permission Checked

### Description

Identifies instances where user account permissions are checked for accessing a network share (EventID 5145). Such enumeration activity often precedes a broader compromise, signaling potential malicious actors already gaining a foothold on your networks.

### Microsoft Defender XDR & Microsoft Sentinel
```
SecurityEvent
| where EventID == 5145
| where AccountType == "User"
| project TimeGenerated, Account, Activity, IpAddress, ShareLocalPath
```

### MITRE ATT&CK Mapping
- Tactic: Discovery
- Technique ID: T1021.002
- [Network Share Discovery](https://attack.mitre.org/techniques/T1135/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |