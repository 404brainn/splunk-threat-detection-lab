# Threat Detection & Incident Response Using Splunk Enterprise

A hands-on Security Operations Center (SOC) laboratory focused on Splunk detection engineering, SPL development, security alerting, dashboarding, investigation, and MITRE ATT&CK mapping.

## What this project demonstrates

- Centralized Windows telemetry collection
- Practical SPL query development
- Detection engineering and alert configuration
- Investigation-oriented dashboards
- Process and authentication analysis
- Network activity detection
- Evidence-driven documentation

## Lab Environment

- **Splunk Enterprise** — Ubuntu Server 24.04.4 LTS
- **Windows 11 Pro** — monitored endpoint
- **Microsoft Sysmon** — process and endpoint telemetry
- **Splunk Universal Forwarder** — log forwarding
- **Kali Linux** — controlled attack simulation

Windows Security Logs, Sysmon telemetry, and Windows Firewall logs are forwarded to Splunk for centralized analysis.

## Architecture

![Splunk Lab Architecture](architecture/splunk-lab-architecture.svg)

```text
Kali Linux
   |
   | Controlled attack simulation
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

| # | Detection | Primary ATT&CK mapping |
|---|---|---|
| 1 | PowerShell Execution | T1059.001 — PowerShell |
| 2 | Encoded PowerShell | T1059.001 — PowerShell |
| 3 | Suspicious Parent–Child Process | T1059.001 / T1059.003 — PowerShell / Windows Command Shell |
| 4 | Windows Authentication Brute Force | T1110 — Brute Force |
| 5 | TCP Port Scan | T1046 — Network Service Scanning |

> ATT&CK mappings describe the behavior represented by the telemetry; they are not intended to imply that every matching event is malicious.

## Detection Engineering Workflow

```text
Attack Simulation
      ↓
Log Collection
      ↓
SPL Query Development
      ↓
Detection Validation
      ↓
Alert Configuration
      ↓
Dashboard / Investigation
      ↓
Analyst Interpretation
```

## Detection Evidence

| Detection | Evidence |
|---|---|
| PowerShell Execution | [Screenshot](screenshots/powershell-execution.png) · [SPL](spl/powershell-execution.spl) · [Detection notes](detections/powershell-execution.md) |
| Encoded PowerShell | [Screenshot](screenshots/encoded-powershell.png) · [SPL](spl/encoded-powershell.spl) · [Detection notes](detections/encoded-powershell.md) |
| Suspicious Parent–Child Process | [Screenshot](screenshots/parent-child-process.png) · [SPL](spl/parent-child-process.spl) · [Detection notes](detections/parent-child-process.md) |
| Windows Brute Force | [Screenshot](screenshots/windows-bruteforce.png) · [SPL](spl/windows-bruteforce.spl) · [Detection notes](detections/windows-bruteforce.md) |
| TCP Port Scan | [Screenshot](screenshots/tcp-port-scan.png) · [SPL](spl/tcp-port-scan.spl) · [Detection notes](detections/tcp-port-scan.md) |

## Alerting

The lab contains configured Splunk searches/alerts for the documented detection use cases. Evidence is available in [configured-alerts.png](screenshots/configured-alerts.png).

## False-Positive and Tuning Considerations

A production detection should not treat every match as malicious. Examples of tuning considerations used for this lab include:

- **PowerShell:** distinguish normal administrative activity from unusual command-line usage, encoded commands, or suspicious parent processes.
- **Brute force:** establish a baseline for normal authentication failures and consider source, target account, host criticality, and time window.
- **Port scanning:** account for legitimate vulnerability scanners, monitoring systems, and administrative discovery activity.
- **Parent-child processes:** treat unusual process relationships as investigation signals rather than automatic proof of compromise.

The thresholds in this laboratory are demonstration values and should be tuned against production baselines before deployment.

## Key SPL Skills Demonstrated

- Sysmon Event ID 1 filtering
- Windows Event ID 4625 analysis
- Firewall-log parsing with `rex`
- Field extraction
- Conditional filtering with `where`
- Aggregation with `stats`
- Distinct-count analysis
- Search-driven alert creation
- Investigation dashboards
- Detection documentation

## Interview-Ready Use Case

**Windows brute-force detection:** Built an SPL search for Windows Event ID 4625 that normalizes the source IP, aggregates failed attempts and targeted accounts by source IP, and flags sources with at least five failed attempts.

The important engineering steps are:

**log source → field normalization → aggregation → threshold → validation → alert/dashboard evidence**

### Example SPL

```spl
index=* EventCode=4625
| eval Source_IP=coalesce(Source_Network_Address,SourceIP,IpAddress)
| stats count AS failed_attempts values(Account_Name) AS targeted_accounts by Source_IP
| where failed_attempts >= 5
| sort - failed_attempts
```

## Example: PowerShell Investigation

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search Image="*powershell.exe"
| table _time Computer User Image CommandLine
| sort -_time
```

This extracts the executable and command line from Sysmon Process Creation events so an analyst can investigate the execution context.

## Wazuh vs Splunk

A separate qualitative comparison is documented in [comparison/wazuh-vs-splunk.md](comparison/wazuh-vs-splunk.md). It focuses on workflow, query flexibility, dashboarding, alerting, and investigation experience rather than unsupported benchmark claims.

## Project Report

[View the complete laboratory report](reports/Splunk-Threat-Detection-Incident-Response-Report.pdf)

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

All attack simulations were performed in an isolated laboratory environment against systems controlled for security testing and learning purposes. Do not reproduce testing against systems without authorization.

## Author

**Ibrahim Khaleel**