# Lab Architecture

## Components

- Splunk Enterprise on Ubuntu Server 24.04.4 LTS
- Windows 11 Pro endpoint
- Microsoft Sysmon v15.21
- Splunk Universal Forwarder
- Kali Linux attack simulation host
- Windows Security, Sysmon, Application, System, and Firewall logs

## Data Flow

```text
Kali Linux
    |
    | Attack simulation
    v
Windows 11 Pro + Sysmon + Windows Firewall
    |
    | Splunk Universal Forwarder
    v
Splunk Enterprise
    |
    +--> SPL detections
    +--> Scheduled alerts
    +--> Dashboards
    +--> Analyst investigation
```

## Purpose

The architecture provides centralized security telemetry for custom SPL-based detection engineering and controlled validation of five attack scenarios.
