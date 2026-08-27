# Suspicious Parent-Child Process Detection

## What I Checked

I used Sysmon Process Creation events to look at how Windows processes started each other. One of the test cases was `cmd.exe` launching `powershell.exe`.

## Test Activity

I started PowerShell from the Windows Command Prompt. Sysmon recorded both the parent and child process details, which were then available in Splunk.

## MITRE ATT&CK

- Technique: T1204
- Name: User Execution
- Data source: Sysmon

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| where (
    (like(lower(ParentImage), "%cmd.exe%") AND like(lower(Image), "%powershell.exe%"))
    OR
    (like(lower(ParentImage), "%powershell.exe%") AND like(lower(Image), "%cmd.exe%"))
    OR
    (like(lower(ParentImage), "%powershell.exe%") AND like(lower(Image), "%powershell.exe%"))
)
| table _time ParentImage Image CommandLine
| sort -_time
```

The search extracts the parent process, child process, and command line from the Sysmon event and filters for the relationships used in the test.

## Alert

- Alert name: Suspicious Parent-Child Process Detection
- Severity: High

## What I Would Check Next

- Review the parent and child process.
- Check the command line.
- See whether the activity makes sense for the user and host.
- Look for related authentication or network activity.

A process relationship can be unusual without being malicious, so I would use this detection as a starting point for investigation rather than treating every match as a confirmed compromise.
