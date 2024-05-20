# Suspicious Email Attachment Detected in Japanese Correspondence

### Description

This query detects emails delivered to the recipients' inbox from a Japanese domain, showing English language detection. The combination of specific attachment type and file size suggests potential phishing activity

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount >= 0 and AttachmentCount > 0
| where isempty( SenderObjectId) and isempty( BulkComplaintLevel)
| where EmailLanguage != "ja"
| where SenderFromDomain endswith "jp"
| join EmailAttachmentInfo on NetworkMessageId
| where FileType in~ ("eml;mime", "unknown;", "msg", "pst", "mbox", "ost", "dbx", "emlx", "ics")
| where FileSize < 30000
| project-away *1
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |