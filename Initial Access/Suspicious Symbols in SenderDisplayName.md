# Suspicious Symbols in SenderDisplayName

### Description

This query detects email events with sender display names using potentially deceptive special symbols. It aims to identify attempts to deceive users and appear legitimate. These emails haven't been blocked and may still be in users' mailboxes.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where isempty( BulkComplaintLevel)
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[-1]), RecipientName = tostring(split(RecipientEmailAddress, "@")[0])
| where SenderDisplayName has RecipientDomain or SenderDisplayName has RecipientName or Subject has RecipientDomain or Subject has RecipientName
| where SenderDisplayName matches regex "\\p{S}"
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |