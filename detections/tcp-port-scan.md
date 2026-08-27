# TCP Port-Scan Detection

## What I Checked

I used Windows Firewall logs to look for a source connecting to multiple TCP destination ports. Kali Linux was used to run the controlled Nmap scan against the Windows endpoint.

## Test Activity

Windows Firewall recorded the connection attempts in `pfirewall.log`. The Splunk Universal Forwarder collected the log and sent it to Splunk Enterprise for analysis.

## MITRE ATT&CK

- Technique: T1046
- Name: Network Service Discovery
- Tactic: Discovery
- Data source: Windows Firewall Log

## SPL

```spl
index=main sourcetype=pfirewall
| rex field=_raw "(?<action>ALLOW|DROP)\s+(?<protocol>\S+)\s+(?<src_ip>\S+)\s+(?<dest_ip>\S+)\s+(?<src_port>\d+|-)\s+(?<dest_port>\d+|-)"
| search protocol=TCP
| stats dc(dest_port) AS unique_ports values(dest_port) AS scanned_ports count AS total_connections by src_ip
| where unique_ports >= 3
| rename src_ip AS "Source IP"
| rename unique_ports AS "Unique Ports Scanned"
| rename scanned_ports AS "Ports"
| rename total_connections AS "Connection Attempts"
```

The search extracts the firewall fields, filters for TCP traffic, and counts the number of different destination ports contacted by each source IP. In this lab, the threshold was set to three unique ports.

## Alert

- Alert name: Network Reconnaissance Detection
- Search type: Scheduled
- Trigger: Number of results greater than 0
- Severity: Medium

## What I Would Check Next

If this alert appeared in a real environment, I would first check whether the source belongs to an approved scanner or monitoring system. I would then review the ports, look for follow-up activity, and correlate the result with authentication and endpoint events.

The threshold is only a lab value and would need tuning for a production network.
