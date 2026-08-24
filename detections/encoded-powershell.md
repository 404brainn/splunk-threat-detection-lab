# Encoded PowerShell Detection

## Objective
Identify PowerShell processes launched with `-EncodedCommand` or `-enc` parameters.

## MITRE ATT&CK
- Technique: T1059.001
- Tactic: Execution
- Data Source: Sysmon

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| where like(lower(Image), "%powershell%")
| where match(lower(CommandLine), "-enc(odedcommand)?")
| table _time Computer User Image CommandLine
| sort -_time
```

## Analyst Notes
- Review the encoded command.
- Decode the Base64 string if necessary.
- Investigate the parent process.
- Check for subsequent network activity.
