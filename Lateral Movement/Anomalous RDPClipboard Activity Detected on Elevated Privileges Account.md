# Anomalous RDPClipboard Activity Detected on Elevated Privileges Account

### Description

This query detects unusual clipboard activity via RDP on accounts with elevated privileges, indicating potential misuse or suspicious behavior. It specifically looks for high integrity processes (elevated privileges) and flags if rdpclip was used 5 or more times within a 5-minute span.

### Microsoft Defender XDR
```
DeviceProcessEvents
| where ProcessIntegrityLevel == "High"
| where ProcessCommandLine has "rdpclip"
| summarize RDPClipAmountPer5Minutes = count() by bin(Timestamp, 5m), AccountName, DeviceName
| where RDPClipAmountPer5Minutes >= 5
```

### Microsoft Sentinel
```
DeviceProcessEvents
| where ProcessIntegrityLevel == "High"
| where ProcessCommandLine has "rdpclip"
| summarize RDPClipAmountPer5Minutes = count() by bin(TimeGenerated, 5m), AccountName, DeviceName
| where RDPClipAmountPer5Minutes >= 5
```

### MITRE ATT&CK Mapping
- Tactic: Lateral Movement
- Technique ID: T1021.001
- [Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/07/2024    | Initial publish                        |