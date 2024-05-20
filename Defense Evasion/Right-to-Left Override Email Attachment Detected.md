# Right-to-Left Override Email Attachment Detected

### Description

Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailAttachmentInfo
| where FileName matches regex "‮"
```

### MITRE ATT&CK Mapping
- Tactic: Defense Evasion
- Technique ID: T1036.002
- [Masquerading: Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
