# PowerShell Execution Detection

## What I Checked

I used Sysmon Process Creation events to find PowerShell executions on the Windows endpoint.

## MITRE ATT&CK

- Technique: T1059.001
- Name: PowerShell
- Data source: Sysmon
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

The search extracts the executable path and command line from the Sysmon event, then shows the user, computer, and time of execution.

## What I Would Check Next

- Who started PowerShell?
- What was in the command line?
- Was the activity expected on that machine?
- Are there other related Sysmon or Windows events around the same time?

PowerShell activity is not automatically malicious, so the event needs to be reviewed in context.
