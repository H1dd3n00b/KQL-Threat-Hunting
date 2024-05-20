# High-Frequency User Access to SMB Network Shares

### Description

This detection identifies high-frequency user access to SMB network shares, triggered by users accessing shares more than three times per minute (EventID 5140), suggesting potential security threats.

### Microsoft Defender XDR & Microsoft Sentinel
```
SecurityEvent
| where EventID == 5140
| where AccountType == "User"
| where isnotempty( ShareLocalPath)
| summarize AmountOfTimesActivityPerformed = count() by bin(TimeGenerated, 1m), Account, Activity, ShareLocalPath, ShareName
| where AmountOfTimesActivityPerformed > 3
```

### MITRE ATT&CK Mapping
- Tactic: Lateral Movement
- Technique ID: T1021.002
- [Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
