# Password Spray Detected

### Description

This query effectively identifies clusters of failed logon attempts from multiple IP addresses within short time intervals, suggesting a coordinated effort (password spraying) to compromise user accounts. Specifically, it targets instances where there are 6 or more failed attempts from distinct IP addresses occurring within a one-minute period.

### Microsoft Sentinel
```
SigninLogs
| where IsInteractive
| where isnotempty(ResultDescription)
| summarize UnknownIPs = make_set(IPAddress) by bin(TimeGenerated, 1m), UserPrincipalName, AppDisplayName
| extend NumberOfFailedAttempts = array_length(UnknownIPs)
| where NumberOfFailedAttempts >= 6
| join kind=inner (IdentityInfo | where IsAccountEnabled) on $left.UserPrincipalName == $right.AccountUPN
| project TimeGenerated, UserPrincipalName, AppDisplayName, UnknownIPs, NumberOfFailedAttempts
```

### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique ID: T1110.003
- [Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/07/2024    | Initial publish                        |