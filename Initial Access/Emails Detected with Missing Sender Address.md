# Emails Detected with Missing Sender Address

### Description

This detection identifies potential phishing emails by flagging inbound messages with no specified sender address. Such anomalies, coupled with attachments or URLs, are indicative of phishing attempts. Stay vigilant against potential threats.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0 or AttachmentCount > 0
| where isempty( SenderFromAddress)
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |