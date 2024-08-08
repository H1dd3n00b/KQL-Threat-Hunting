# Suspicious Emails Using Date-Time References

### Description

This query identifies patterns in emails with specific subject details: a combination of a particular day of the week, month, and AM or PM time references. These messages likely indicate phishing attempts targeting user credentials.

### Microsoft Defender XDR & Microsoft Sentinel
```
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where isempty( BulkComplaintLevel)
//| where SenderMailFromDomain !in~ ("microsoft.com", "sharepointonline.com") // Please exclude known benign domains, such as microsoft.com, sharepointonline.com etc. on this line
| where Subject matches regex "(?i)am|pm"
| where Subject matches regex "(?i)jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec"
| where Subject matches regex "(?i)mon|tue|wed|thu|fri|sat|sun"
| where Subject matches regex "\\d{4,}"
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.002
- [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 20/05/2024    | Initial publish                        |
| 1.1           | 08/08/2024    | Modified DeliveryAction to "Delivered"                        |
