# Anomalous First-Time User Logon with Uncommon App and ISP

### Description

This KQL detection analyzes logon activities, targeting first-time logons via specific ISPs and web browsers, signaling potential suspicious behavior.

### References
 - https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics

### Microsoft Sentinel
```
BehaviorAnalytics
| where ActivityType == "LogOn"
| where InvestigationPriority > 0
| extend FirstTimeUserUsedApp = ActivityInsights.FirstTimeUserUsedApp, FirstTimeUserConnectedViaISP = ActivityInsights.FirstTimeUserConnectedViaISP, App = ActivityInsights.App, IsNewAccount = UsersInsights.IsNewAccount, AppUncommonlyUsedAmongPeers = ActivityInsights.AppUncommonlyUsedAmongPeers
| where FirstTimeUserUsedApp == true and FirstTimeUserConnectedViaISP == true and AppUncommonlyUsedAmongPeers == true
| where IsNewAccount == false
| project TimeGenerated, App, UserPrincipalName, SourceDevice
```

### MITRE ATT&CK Mapping
- Tactics: Discovery
- Technique ID: T1087.004
- [Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |