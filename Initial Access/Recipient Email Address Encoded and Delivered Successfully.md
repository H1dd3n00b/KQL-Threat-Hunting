# Recipient Email Address Encoded and Delivered Successfully

### Description

This query identifies inbound emails with the recipient's address encoded in URLs, posing a security threat. Clicking may lead to a phishing page to harvest credentials. These emails haven't been blocked and may be in users' mailboxes.

### References
 - https://github.com/KustoKing/Hunting-Queries-Detection-Rules/blob/main/Microsoft%20365%20Defender%20For%20Office%20365/Detect%20Inbound%20Phish%20With%20Base64%20Encoded%20Receipient.md

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where UrlCount > 0
| where isempty( BulkComplaintLevel)
| join EmailUrlInfo on NetworkMessageId
| where not( Url matches regex "register|unsub")
| extend Base64Recipient = base64_encode_tostring(RecipientEmailAddress)
| where Url has Base64Recipient
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