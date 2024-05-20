# Malicious Image File Attachment Detected

### Description

This query identifies potentially malicious image file attachments with filenames exhibiting specific patterns and file sizes that suggest the presence of threats, often involving malicious hyperlink redirects.

### Microsoft Defender XDR
```
EmailAttachmentInfo
| where FileType in~ ("png", "jpg", "jpeg", "svg", "gif", "jfif", "bmp", "tiff", "tif", "heif", "heic", "raw", "eps")
| where isempty( SenderObjectId)
| where FileName matches regex "^[A-Z]{3,}\\.[A-Za-z0-9]+$"
| where FileSize >= 1000 and FileSize <= 6000
```

### Microsoft Sentinel
```
EmailAttachmentInfo
| where FileType in~ ("png", "jpg", "jpeg", "svg", "gif", "jfif", "bmp", "tiff", "tif", "heif", "heic", "raw", "eps")
| where isempty( SenderObjectId)
| where FileName matches regex "^[A-Z]{3,}\\.[A-Za-z0-9]+$"
| where FileSize between (1000 .. 6000)
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |