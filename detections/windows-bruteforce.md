# Windows Authentication Brute-Force Detection

## What I Checked

I used Windows failed-logon events to look for repeated authentication attempts from the same source IP. The lab search uses EventCode 4625 and flags a source after five failed attempts.

## MITRE ATT&CK

- Technique: T1110
- Name: Brute Force
- Tactic: Credential Access
- Data source: Windows Security Log

## SPL

```spl
index=* EventCode=4625
| eval Source_IP=coalesce(Source_Network_Address, SourceIp, IpAddress)
| stats count AS failed_attempts values(Account_Name) AS targeted_accounts by Source_IP
| where failed_attempts >= 5
| sort - failed_attempts
```

The `coalesce()` step handles different field names that may contain the source address. The search then groups events by source IP and counts the failures.

## Alert

- Name: Windows Authentication Brute Force Detection
- Search type: Scheduled
- Trigger: Number of results greater than 0
- Severity: High

## What I Would Check Next

Before deciding that the activity is malicious, I would review the source IP, number of failures, targeted accounts, timestamps, and any successful logons that happened afterward.
