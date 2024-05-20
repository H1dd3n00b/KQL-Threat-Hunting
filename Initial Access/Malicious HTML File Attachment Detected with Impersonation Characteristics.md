# Malicious HTML File Attachment Detected with Impersonation Characteristics

### Description

This detection identifies HTML attachments that potentially indicate impersonation, flagging files containing recipient domain parts (FQD, SLD, TLD) in the filename.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailAttachmentInfo
| where FileType == "html"
| extend FQD = tostring(split(RecipientEmailAddress, "@")[-1])
| extend SLD = tostring(split(FQD, ".")[0]), TLD = tostring(split(FQD, ".")[-1])
| where FileName has FQD or FileName has SLD or FileName has TLD
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |