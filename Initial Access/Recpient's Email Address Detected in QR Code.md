# Recpient's Email Address Detected in QR Code

### Description

This alert signals potential phishing activity as the recipient's email address has been identified within a QR code location.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0 or AttachmentCount > 0 
| extend Base64Recipient = base64_encode_tostring(RecipientEmailAddress)
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| where Url has RecipientEmailAddress or Url has Base64Recipient
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