# Non-legitimate Japanese Emails Received

### Description

This query identifies potentially malicious Sender Display Names previously flagged for phishing activities, associated with known Japanese domains. It detects keywords aligned with typical phishing language and notes that despite the email originating from a .jp domain, the email language is in English.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where isempty( BulkComplaintLevel)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0 or AttachmentCount > 0
| where SenderFromDomain endswith ".jp" and EmailLanguage != "ja"
| where SenderDisplayName matches regex "(?i)hr|unit|admin|manage|office|help|desk|via|support|share|team|acc|secur|service|sign|doc|online|mail|record|behalf|return|pass|pay|internal|portal|auth|automate|point|file|link|\\.com"
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
