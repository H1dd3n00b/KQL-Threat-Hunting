# Suspiciously Long SenderDisplayName

### Description

This query hunts for sender display names over 100 characters, often indicating malicious impersonation attempts. Notably, these emails may still be in users' mailboxes, as they have not been blocked.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where AttachmentCount > 0 or UrlCount > 0
| where strlen( SenderDisplayName) >= 100
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
