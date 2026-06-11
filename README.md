# Automated Cloud Security Audit Engine

A Python-based DevSecOps tool that automatically audits AWS 
infrastructure to identify security group misconfigurations 
and public network exposures.

## Business Case
In cloud deployments, engineers frequently misconfigure security 
groups — accidentally leaving critical ports open to the entire 
internet. This tool automates the discovery process, closing the 
visibility gap between engineering agility and cloud governance.

## Architecture
Your PC (Python Script)
│
├── Authenticates via IAM credentials
│
└── Scans AWS VPC Security Groups
│
└── Generates Executive Risk Report
## Technology Stack
- Language: Python 3.12
- Cloud SDK: boto3 (AWS SDK)
- Cloud Platform: AWS EC2/VPC
- Auth: IAM with least-privilege access

## Security Design Decisions
- IAM user has read-only permissions — cannot modify anything
- No credentials stored in code — uses aws configure
- Scans for critical ports: SSH (22), RDP (3389)
- Flags any rule open to 0.0.0.0/0 (entire internet)

## Sample Finding
| Severity | Security Group | Port | Protocol |
| :--- | :--- | :--- | :--- |
| CRITICAL | vulnerable-test-group | 22 | tcp |

## How to Run
pip install boto3
aws configure
python cloud_audit.py

## Author
19 years experience in Software Development, 
Telecom and Network Infrastructure.
Certified: PMP, CSM