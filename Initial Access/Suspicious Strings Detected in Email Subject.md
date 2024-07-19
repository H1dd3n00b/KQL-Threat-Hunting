# Suspicious Strings Detected in Email Subject

### Description

This query detects potential phishing emails based on suspicious subject strings. It identifies patterns commonly found in phishing emails, often containing seemingly random alphanumeric sequences ranging from 30 to 50 characters.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where isempty( BulkComplaintLevel)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0 or AttachmentCount > 0
| where Subject matches regex @"\b[a-z0-9]{30,}\b"
| where not( Subject has "report domain:")
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/07/2024    | Initial publish                        |
