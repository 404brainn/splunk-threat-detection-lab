# Encoded PowerShell Detection

## What I Checked

This search looks for PowerShell started with `-EncodedCommand` or `-enc`. I used Sysmon process creation events as the data source.

## MITRE ATT&CK

- Technique: T1059.001
- Tactic: Execution
- Data source: Sysmon

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

The search filters PowerShell process events and checks the command line for the encoded-command switches.

## What I Would Check Next

- Review the full command line.
- Decode the Base64 value when needed to understand what was executed.
- Check which process started PowerShell.
- Look for related network or process activity.

Using an encoded command is not enough by itself to prove malicious activity, but it is useful for finding executions that need a closer look.
