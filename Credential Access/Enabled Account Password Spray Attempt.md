# Enabled Account Password Spray Attempt

### Description

This query is designed to detect and alert on potential anomalous sign-in activities based on a comparison between the average failed logon attempts per user and the actual number of failed attempts recorded within the last hour.
It focuses on enabled accounts that have shown significant deviations from their historical average failed logon rates.

### Microsoft Sentinel
```
let lookback = 14d;
let AverageFailedLogonPerUser = IdentityLogonEvents
| where TimeGenerated >= ago(lookback)
| where isnotempty( AccountUpn)
| where ActionType == "LogonFailed"
| project TimeGenerated,  AccountUpn = tolower(AccountUpn), ActionType
| summarize FailedLogonsPerMinute = count() by bin(TimeGenerated, 1m), AccountUpn
| summarize FailedLogonAverage = avg(FailedLogonsPerMinute) by AccountUpn
| extend FailedLogonAverageRounded = round(FailedLogonAverage);
let EnabledAccounts = IdentityInfo
| where TimeGenerated >= ago(lookback) 
| where IsAccountEnabled
| where isnotempty( AccountUPN)
| project AccountUPN = tolower(AccountUPN)
| distinct AccountUPN;
SigninLogs
| where TimeGenerated >= ago(1h)
| where IsInteractive
| where isnotempty(ResultDescription)
| summarize UnknownIPs = make_set(IPAddress) by bin(TimeGenerated, 1m), UserPrincipalName, AppDisplayName
| where UserPrincipalName has_any (EnabledAccounts)
| extend NumberOfFailedAttemptsPerMinute = array_length(UnknownIPs), UserPrincipalName = tolower(UserPrincipalName)
| join kind=inner AverageFailedLogonPerUser on $left.UserPrincipalName == $right.AccountUpn
| where NumberOfFailedAttemptsPerMinute > FailedLogonAverageRounded
| project-away AccountUpn
```

### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique ID: T1110.003
- [Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/07/2024    | Initial publish                        |
| 1.1           | 17/07/2024    | Modified to base detection thresholds per user, not a fixed count of 6 or more                        |

