# PowerShell Execution Detection

## Objective
Identify PowerShell execution on the monitored Windows endpoint using Sysmon Process Creation events.

## MITRE ATT&CK
- Technique: T1059.001
- Name: PowerShell
- Data Source: Sysmon
- Event: EventCode 1

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search Image="*powershell.exe"
| table _time Computer User Image CommandLine
| sort -_time
```

## Analyst Notes
- Verify the executing user.
- Review the complete command line.
- Determine whether the execution is expected.
- Correlate with other endpoint events.
