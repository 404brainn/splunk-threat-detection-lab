# Threat Detection & Incident Response Using Splunk Enterprise

A hands-on Security Operations Center (SOC) laboratory focused on Splunk-based detection engineering, SPL analysis, security alerting, dashboards, and MITRE ATT&CK mapping.

## Project Overview

This laboratory uses:

- Splunk Enterprise
- Ubuntu Server 24.04.4 LTS
- Windows 11 Pro
- Microsoft Sysmon
- Splunk Universal Forwarder
- Kali Linux

Windows Security Logs, Sysmon telemetry, and Windows Firewall logs are forwarded to Splunk for centralized analysis. Custom SPL detections are then used to identify suspicious activity, generate alerts, and support analyst investigation.

## Lab Architecture

```text
Kali Linux
   |
   | Attack simulation
   v
Windows 11 + Sysmon
   |
   | Splunk Universal Forwarder
   v
Splunk Enterprise on Ubuntu
   |
   +--> SPL detections
   +--> Alerts
   +--> Dashboards
   +--> Investigation
   +--> MITRE ATT&CK mapping
```

## Detection Use Cases

| # | Detection | ATT&CK |
|---|---|---|
| 1 | PowerShell Execution | T1059.001 |
| 2 | Encoded PowerShell | T1059.001 |
| 3 | Suspicious Parent–Child Process | T1204 |
| 4 | Windows Authentication Brute Force | T1110 |
| 5 | TCP Port Scan | T1046 |

## Detection Engineering Workflow

```text
Attack Simulation
      ↓
Log Collection
      ↓
SPL Query
      ↓
Detection Validation
      ↓
Alert
      ↓
Dashboard
      ↓
Analyst Investigation
```

## Repository Structure

```text
.
├── architecture/
├── dashboards/
├── detections/
├── reports/
├── screenshots/
├── spl/
└── README.md
```

## Key SPL Skills Demonstrated

- Sysmon event filtering
- Field extraction with `rex`
- Conditional filtering with `where`
- Aggregation with `stats`
- Event correlation and investigation
- Search-driven alert creation
- Security dashboard development

## Example Detection

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search Image="*powershell.exe"
| table _time Computer User Image CommandLine
| sort -_time
```

This identifies Sysmon Process Creation events involving PowerShell and presents the time, host, user, executable, and command line for investigation.

## Security Disclaimer

All attack simulations were performed in an isolated laboratory environment against systems controlled for security testing and learning purposes.

## Project Report

The complete laboratory report will be added under `reports/`.

## Author

**Ibrahim Khaleel**
