# Anomalous Logon and Resource Access from Uncommonly Used Device

### Description

This query detects suspicious logon activity, particularly when users access resources. It flags anomalies such as first-time device logons, uncommon device usage, and high volumes of atypical logon actions.

### References
 - https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics

### Microsoft Sentinel
```
BehaviorAnalytics
| where ActivityType == "LogOn" and ActionType == "ResourceAccess"
| where InvestigationPriority > 0
| where isnotempty( UserName)
| extend FirstTimeUserLoggedOnToDevice = ActivityInsights.FirstTimeUserLoggedOnToDevice, DeviceUncommonlyUsedInTenant = ActivityInsights.DeviceUncommonlyUsedInTenant
| where FirstTimeUserLoggedOnToDevice == true and DeviceUncommonlyUsedInTenant == true
```

### MITRE ATT&CK Mapping
- Tactics: Discovery
- Technique ID: T1087.002
- [Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |