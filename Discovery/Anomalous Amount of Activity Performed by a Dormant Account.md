# Anomalous Amount of Activity Performed by a Dormant Account

### Description

This query flags suspicious activity from dormant user accounts: sudden increased logon attempts and resource access after a period of inactivity, raising concerns for potential unauthorized access or compromise.

### References
 - https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics

### Microsoft Sentinel
```
BehaviorAnalytics
| where ActivityType == "LogOn" and ActionType == "ResourceAccess"
| where InvestigationPriority > 0 
| where isnotempty ( UserName)
| extend UncommonHighVolumeOfActions = ActivityInsights.UncommonHighVolumeOfActions, IsDormantAccount = UsersInsights.IsDormantAccount
| where IsDormantAccount == true and UncommonHighVolumeOfActions == true
```

### MITRE ATT&CK Mapping
- Tactics: Discovery
- Technique ID: T1087.004
- [Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
