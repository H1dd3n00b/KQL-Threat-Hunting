# New Administrator Access Detected on SharePoint

### Description

A new event has been identified in our Office 365 tenant: another user's SharePoint has gained a new Site Collection Administrator.

### Microsoft Sentinel
```
OfficeActivity
| where OfficeWorkload == "SharePoint"
| where Operation == "SiteCollectionAdminAdded"
| extend TransformedUserId = replace(@'[^A-Za-z0-9]', '_', UserId)
| extend TransformedOfficeObjectId = tostring(split(OfficeObjectId, "/")[-1])
| where TransformedUserId != TransformedOfficeObjectId
| extend AdminThatHasAccess = UserId
| extend SiteName = OfficeObjectId
| extend ModifiedPropertiesParsed = parse_json(ModifiedProperties)
| extend AdminResponsibleforChange = tostring(ModifiedPropertiesParsed[0].NewValue)
| project TimeGenerated, SiteName, AdminThatHasAccess, AdminResponsibleforChange, ClientIP, Site_Url
```

### MITRE ATT&CK Mapping
- Tactic: Collection
- Technique ID: T1213.002
- [Data from Information Repositories: Sharepoint](https://attack.mitre.org/techniques/T1213/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |