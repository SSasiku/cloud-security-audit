# AWS Lab Security Risk Register

## Overview
Formal risk register for the SecurityLab-Sashy AWS environment.
Identifies key threats, scores risk using Likelihood x Impact,
and documents treatment decisions.

**Risk Formula:** Risk Score = Likelihood (1-5) x Impact (1-5)
**Maximum Possible Score:** 25

## Risk Register

| Risk ID | Threat | Vulnerability | Likelihood | Impact | Score | Treatment | Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| R001 | Attacker exploits open SSH port | Port 22 open to 0.0.0.0/0 | 5 | 5 | 25 | Accept | Test lab only — no real data, documented decision |
| R002 | IAM Access Keys stolen | No MFA on security-audit-user | 3 | 4 | 12 | Mitigate | Rotate keys regularly, restrict to known IPs |
| R003 | Public S3 bucket exposes data | S3 ACL open to AllUsers | 5 | 5 | 25 | Mitigate | Enable S3 Block Public Access at account level |
| R004 | No audit trail for account activity | CloudTrail not enabled | 3 | 5 | 15 | Mitigate | Enable CloudTrail in all regions |
| R005 | Unexpected charges from breach or misconfiguration | No billing alerts | 2 | 4 | 8 | Mitigate | Set billing alert at $10 threshold |

## Risk Priority Order
1. R001 & R003 — Score 25 (Critical)
2. R004 — Score 15 (High)
3. R002 — Score 12 (Medium-High)
4. R005 — Score 8 (Medium)

## Review Date
Next review: 90 days from creation