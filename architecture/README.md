# Lab Architecture

The lab has three main systems:

- **Ubuntu Server 24.04.4 LTS** - runs Splunk Enterprise.
- **Windows 11 Pro** - the monitored endpoint, with Sysmon and the Splunk Universal Forwarder.
- **Kali Linux** - used to generate controlled test activity.

The Windows machine sends Security, Application, System, Sysmon, and Firewall events to Splunk through the Universal Forwarder.

## Data Flow

```text
Kali Linux
    |
    | Controlled testing
    v
Windows 11 + Sysmon + Windows Firewall
    |
    | Splunk Universal Forwarder
    v
Splunk Enterprise
    |
    +--> SPL searches
    +--> Scheduled alerts
    +--> Dashboards
    +--> Investigation
```

Kali generates the test activity, but the Windows endpoint is the main source of telemetry for the detections. Splunk receives the logs and I use SPL searches to find the activity, test the results, and build alerts and dashboards around it.
