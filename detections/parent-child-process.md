# Suspicious Parent–Child Process Detection

## Objective

Identify suspicious Windows process relationships, such as `cmd.exe` spawning `powershell.exe`, using Sysmon Process Creation telemetry.

## Attack Simulation

The Windows Command Prompt was used to launch PowerShell, generating Sysmon Process Creation events containing parent and child process information.

## MITRE ATT&CK

- Technique: T1204
- Name: User Execution
- Data Source: Sysmon

## SPL Detection

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

## Query Explanation

The search extracts the parent process, child process, and command-line arguments from Sysmon Process Creation events. It then filters for the suspicious parent–child relationships documented in the laboratory report.

## Alert

- Alert Name: Suspicious Parent–Child Process Detection
- Severity: High

## Analyst Investigation

1. Verify the parent process.
2. Review the child process.
3. Examine the command line.
4. Correlate with authentication events.
5. Check for related network connections.

## Evidence

Add the Splunk query and result screenshot to `screenshots/parent-child-process.png` once available.
