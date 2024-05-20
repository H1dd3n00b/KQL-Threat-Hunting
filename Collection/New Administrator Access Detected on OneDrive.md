# New Administrator Access Detected on OneDrive

### Description

A new event has been detected in our Office 365 tenant: a Site Collection Administrator was added to another user's OneDrive.

### Microsoft Sentinel
```
OfficeActivity
| where OfficeWorkload == "OneDrive"
| where Operation == "SiteCollectionAdminAdded"
| extend TransformedUserId = replace(@'[^A-Za-z0-9]', '_', UserId)
| extend TransformedOfficeObjectId = tostring(split(OfficeObjectId, "/")[-1])
| where TransformedUserId != TransformedOfficeObjectId
| extend AdminThatHasAccess = UserId
| extend TrueOwnerSite = OfficeObjectId
| extend ModifiedPropertiesParsed = parse_json(ModifiedProperties)
| extend AdminResponsibleforChange = tostring(ModifiedPropertiesParsed[0].NewValue)
| project TimeGenerated, TrueOwnerSite, AdminThatHasAccess, AdminResponsibleforChange, ClientIP, Site_Url
```

### MITRE ATT&CK Mapping
- Tactic: Collection
- Technique ID: T1530
- [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
