# Automated Cloud Security Audit Engine

A Python-based DevSecOps tool that automatically audits AWS 
infrastructure across three security domains — network exposure, 
storage access, and identity controls — and generates a single 
executive risk report.

## Business Case
In cloud deployments, engineers frequently misconfigure security 
settings — leaving network ports open to the internet, storage 
buckets publicly readable, or user accounts without multi-factor 
authentication. This tool automates detection across all three, 
closing the visibility gap between engineering agility and cloud 
governance.

## Architecture

Your PC (Python Script)

│

├── Authenticates via IAM credentials (aws configure)

│

├── Scans VPC Security Groups (network exposure)

├── Scans S3 Buckets (public storage access)

├── Scans IAM Users (missing MFA)

│

└── Generates one unified Executive Risk Report

## Technology Stack
- Language: Python 3.12
- Cloud SDK: boto3 (AWS SDK)
- Cloud Platform: AWS EC2, VPC, S3, IAM
- Auth: IAM with least-privilege, read-only access

## Security Checks Performed

| # | Check | What It Detects |
| :--- | :--- | :--- |
| 1 | Security Group Audit | Critical ports (SSH 22, RDP 3389) open to 0.0.0.0/0 |
| 2 | S3 Bucket Audit | Buckets with public read access via ACL |
| 3 | IAM MFA Audit | Users without Multi-Factor Authentication enabled |

## Security Design Decisions
- IAM user has read-only permissions only — cannot modify any resource
- No credentials stored in code — uses aws configure (local credentials file)
- All findings consolidated into one Markdown report, not scattered output
- Designed to be extended — new checks follow the same function pattern

## Sample Finding
| Severity | Security Group | Port | Protocol |
| :--- | :--- | :--- | :--- |
| CRITICAL | vulnerable-test-group | 22 | tcp |

| Severity | User | Issue |
| :--- | :--- | :--- |
| WARNING | security-audit-user | No MFA device enabled |

## How to Run