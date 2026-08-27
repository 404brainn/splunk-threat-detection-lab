# Splunk Dashboards

I created three dashboards to make the lab results easier to review.

## 1. SOC Executive Dashboard

A high-level view of endpoint, authentication, and network activity.

![SOC Executive Dashboard](../screenshots/soc-executive-dashboard.png)

## 2. Endpoint Detection Dashboard

This view focuses on Sysmon process events, PowerShell activity, encoded PowerShell, and the parent-child process test.

![Endpoint Detection Dashboard](../screenshots/endpoint-detection-dashboard.png)

## 3. Authentication & Network Security Dashboard

This dashboard brings together failed and successful logons, network activity, and the port-scan results.

![Authentication & Network Security](../screenshots/authentication-network-security.png)

The list of dashboards is also captured in [dashboards-list.png](../screenshots/dashboards-list.png).

The dashboard panels are based on SPL searches from this lab. The screenshots are kept separately under `screenshots/` as evidence of the results I captured during testing.
