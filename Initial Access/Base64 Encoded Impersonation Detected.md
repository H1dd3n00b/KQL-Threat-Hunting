# Base64 Encoded Impersonation Detected

### Description

This query detects phishing by finding suspicious sender display names with Base64 encoded parts of the recipient's email, domain, first name, or last name. It only filters emails successfully delivered to users' inboxes.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[-1]), RecipientName = tostring(split(RecipientEmailAddress, "@")[0])
| extend RecipientFirstName = tostring(split(RecipientName, ".")[0]), RecipientLastName = tostring(split(RecipientName, ".")[-1])
| extend Base64Recipient = base64_encode_tostring(RecipientEmailAddress), Base64Domain = base64_encode_tostring(RecipientDomain), Base64RecipientFirstName = base64_encode_tostring(RecipientFirstName), Base64RecipientLastName = base64_encode_tostring(RecipientLastName)
| where SenderDisplayName contains Base64Recipient or SenderDisplayName contains Base64Domain or SenderDisplayName contains Base64Recipient or SenderDisplayName contains Base64RecipientFirstName or SenderDisplayName contains Base64RecipientLastName
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
