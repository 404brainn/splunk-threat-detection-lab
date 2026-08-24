# Windows Authentication Brute Force Detection

## Objective
Identify repeated failed Windows logon attempts originating from the same source IP.

## MITRE ATT&CK
- Technique: T1110
- Technique Name: Brute Force
- Tactic: Credential Access
- Log Source: Windows Security Log

## SPL

```spl
index=* EventCode=4625
| eval Source_IP=coalesce(Source_Network_Address, SourceIp, IpAddress)
| stats count AS failed_attempts values(Account_Name) AS targeted_accounts by Source_IP
| where failed_attempts >= 5
| sort - failed_attempts
```

## Alert
- Name: Windows Authentication Brute Force Detection
- Search Type: Scheduled
- Trigger: Number of Results > 0
- Severity: High

## Analyst Investigation
Review the source IP, number of failed attempts, targeted accounts, and event timestamps before determining whether the activity is malicious.
