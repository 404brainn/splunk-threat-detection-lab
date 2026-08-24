# Wazuh vs Splunk — Lab Observations

This project is intentionally documented as a Splunk-focused detection engineering lab. A separate Wazuh lab was used as a complementary SOC platform, so the comparison below focuses on workflow and analyst experience rather than unsupported benchmark claims.

| Area | Splunk | Wazuh |
|---|---|---|
| Query language | SPL provides flexible search, extraction, filtering, and aggregation | Wazuh uses its own rule/query and dashboard workflow |
| Detection engineering | Strong fit for building and iterating custom SPL detections | Strong fit for rule-based detection and integrated agent monitoring |
| Dashboarding | Flexible dashboard construction around search results | Integrated security monitoring dashboards |
| Investigation | Search-first workflow makes ad-hoc event investigation straightforward | Integrated alert and agent context is useful for endpoint-focused investigation |
| Alerting | Saved searches can be turned into scheduled detections/alerts | Rules and alerting are built into the Wazuh platform |
| Portfolio value | Demonstrates SPL, search-driven detection engineering, correlation, and dashboard design | Demonstrates SIEM deployment, endpoint monitoring, FIM, alert investigation, and threat-intelligence integration |

## Key takeaway

The two platforms should not be presented as interchangeable. This Splunk project demonstrates the ability to **write and explain SPL**, turn searches into detections, validate results, and present them through dashboards. The Wazuh work demonstrates a different operational workflow around endpoint monitoring and integrated security controls.

## Interview-ready comparison

> "I used both platforms in separate lab environments. In Splunk, I focused on writing custom SPL detections, validating the returned events, configuring alerts, and building investigation dashboards. That gave me practical experience with search-driven detection engineering rather than only operating a prebuilt SIEM."
