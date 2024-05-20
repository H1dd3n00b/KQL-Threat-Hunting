# Malicious QR Code File Attachment Found

### Description

This query identifies potentially malicious inline QR code files in email bodies, concealing deceptive links. QR codes, common in phishing, exploit file sizes and naming conventions to hide harmful URLs.

### Microsoft Defender XDR
```
EmailAttachmentInfo
| where FileType in~ ("png", "jpg", "svg", "eps")
| where isempty( SenderObjectId)
| where FileName matches regex "^[A-Z]{4,}\\.[A-Za-z0-9]+$"
| where FileSize >= 300 and FileSize <= 1000
```

### Microsoft Sentinel
```
 EmailAttachmentInfo
| where FileType in~ ("png", "jpg", "svg", "eps")
| where isempty( SenderObjectId)
| where FileName matches regex "^[A-Z]{4,}\\.[A-Za-z0-9]+$"
| where FileSize between (300 .. 1000)
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |