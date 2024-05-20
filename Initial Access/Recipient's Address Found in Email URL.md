# Recipient's Address Found in Email URL

### Description

This query identifies delivered inbound emails with URLs containing recipient email addresses and fragment identifiers (#), which are common indicators of phishing attempts aimed at compromising sensitive information.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0
| join EmailUrlInfo on NetworkMessageId
| where Url has RecipientEmailAddress and Url has "#"
| project-away *1
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |