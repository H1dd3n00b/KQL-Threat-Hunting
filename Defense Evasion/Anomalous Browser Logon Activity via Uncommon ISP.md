# Anomalous Browser Logon Activity via Uncommon ISP

### Description

This KQL detection analyzes logon activities, targeting first-time logons via specific ISPs and web browsers, signaling potential suspicious behavior.

### References
 - https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics

### Microsoft Sentinel
```
BehaviorAnalytics
| where ActivityType == "LogOn"
| extend FirstTimeUserConnectedFromCountry = ActivityInsights.FirstTimeUserConnectedFromCountry, FirstTimeUserConnectedViaBrowser = ActivityInsights.FirstTimeUserConnectedViaBrowser, FirstTimeUserConnectedViaISP = ActivityInsights.FirstTimeUserConnectedViaISP
| extend IsNewAccount = UsersInsights.IsNewAccount, AccountObjectID = UsersInsights.AccountObjectID
| extend UserAgentFamily = DevicesInsights.UserAgentFamily, ISP = DevicesInsights.ISP
| where InvestigationPriority > 0
| where IsNewAccount != true
| where FirstTimeUserConnectedViaISP == true and FirstTimeUserConnectedViaBrowser == true
| project TimeGenerated, UserAgentFamily, ISP, UserName, AccountObjectID
```

### MITRE ATT&CK Mapping
- Tactics: Defense Evasion, Persistence, Privilege Escalation, Initial Access
- Technique ID: T1078.003
- [Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |