# Emoji Detected in HTML File Attachment

### Description

This query helps identify potentially malicious .html file attachments featuring emojis in their file names, often indicative of spear-phishing attempts. Legitimate business documents typically avoid the use of emojis in their names.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailAttachmentInfo
| where FileType == "html"
| where FileName matches regex @"[\x{1F600}-\x{1F64F}\x{1F300}-\x{1F5FF}\x{1F680}-\x{1F6FF}\x{1F700}-\x{1F77F}\x{1F780}-\x{1F7FF}\x{1F800}-\x{1F8FF}\x{1F900}-\x{1F9FF}\x{1FA00}-\x{1FA6F}\x{2600}-\x{26FF}\x{2700}-\x{27BF}]"
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |