# TCP Port Scan Detection

## Objective

Identify TCP port scanning activity by analyzing Windows Firewall logs. The laboratory uses Nmap from Kali Linux to simulate reconnaissance against the Windows endpoint.

## Attack Simulation

An Nmap TCP scan was executed from Kali Linux against the Windows endpoint. Windows Firewall recorded incoming connection attempts in `pfirewall.log`, which were forwarded by the Splunk Universal Forwarder to Splunk Enterprise.

## MITRE ATT&CK

- Technique: T1046
- Name: Network Service Discovery
- Tactic: Discovery
- Data Source: Windows Firewall Log

## SPL Detection

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

## Query Explanation

The query extracts network fields from the Windows Firewall log using regular expressions. It filters TCP traffic, counts unique destination ports contacted by each source IP, and identifies sources exceeding the configured threshold of three unique ports.

## Alert

- Alert Name: Network Reconnaissance Detection
- Search Type: Scheduled
- Trigger Condition: Number of Results > 0
- Severity: Medium

## Expected Output

- Source IP
- Number of Unique Ports Scanned
- List of Scanned Ports
- Total Connection Attempts

## Analyst Investigation

1. Determine whether the source IP belongs to an approved vulnerability scanner.
2. Review the scanned ports.
3. Check for subsequent exploitation attempts.
4. Correlate with authentication and Sysmon events.
5. Monitor or block the source host if the activity is unauthorized.

## Evidence

Add the Splunk query and result screenshot to `screenshots/tcp-port-scan.png` once available.
