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

![Splunk Lab Architecture](architecture/splunk-lab-architecture.svg)

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

## Dashboard Evidence

### SOC Executive Dashboard
![SOC Executive Dashboard](screenshots/soc-executive-dashboard.png)

### Endpoint Detection Dashboard
![Endpoint Detection Dashboard](screenshots/endpoint-detection-dashboard.png)

### Authentication & Network Security Dashboard
![Authentication & Network Security](screenshots/authentication-network-security.png)

## Detection Evidence

| Detection | Evidence |
|---|---|
| PowerShell Execution | [Screenshot](screenshots/powershell-execution.png) · [SPL](spl/powershell-execution.spl) |
| Encoded PowerShell | [Screenshot](screenshots/encoded-powershell.png) · [SPL](spl/encoded-powershell.spl) |
| Suspicious Parent–Child Process | [Screenshot](screenshots/parent-child-process.png) · [SPL](spl/parent-child-process.spl) |
| Windows Brute Force | [Screenshot](screenshots/windows-bruteforce.png) · [SPL](spl/windows-bruteforce.spl) |
| TCP Port Scan | [Screenshot](screenshots/tcp-port-scan.png) · [SPL](spl/tcp-port-scan.spl) |

## Alerts

The project includes five detection use cases configured as Splunk searches/alerts. Evidence of the configured detections is available in [configured-alerts.png](screenshots/configured-alerts.png).

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

## Wazuh vs Splunk

A short qualitative comparison is documented in [comparison/wazuh-vs-splunk.md](comparison/wazuh-vs-splunk.md). The comparison focuses on query flexibility, dashboarding, detection workflow, and analyst investigation rather than unsupported performance claims.

## Project Report

[Download/View the complete laboratory report](reports/Splunk-Threat-Detection-Incident-Response-Report.pdf)

## Repository Structure

```text
.
├── architecture/
├── comparison/
├── dashboards/
├── detections/
├── reports/
├── screenshots/
├── spl/
└── README.md
```

## Security Disclaimer

All attack simulations were performed in an isolated laboratory environment against systems controlled for security testing and learning purposes.

## Author

**Ibrahim Khaleel**
