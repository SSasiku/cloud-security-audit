import boto3
import os
from datetime import datetime

def run_network_audit():

    """
    Scans all EC2 Security Groups in the AWS account and checks
    their inbound rules for ports exposed to the public internet
    (0.0.0.0/0). Flags critical ports (SSH 22, RDP 3389) as
    high-severity findings.

    Calls generate_report() to write results to a Markdown file.
    """
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    print("Initializing AWS Cloud Network Audit...")
    response = ec2.describe_security_groups()
    security_groups = response['SecurityGroups']
    
    vulnerabilities = []
    
    for sg in security_groups:
        sg_name = sg['GroupName']
        sg_id = sg['GroupId']
        
        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort', 'All')
            to_port = permission.get('ToPort', 'All')
            ip_protocol = permission.get('IpProtocol', 'All')
            
            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                
                if cidr == '0.0.0.0/0':
                    is_critical = from_port in [22, 3389, 'All']
                    severity = "CRITICAL" if is_critical else "WARNING"
                    
                    vulnerabilities.append({
                        "sg_name": sg_name,
                        "sg_id": sg_id,
                        "port": f"{from_port}-{to_port}" if from_port != to_port else from_port,
                        "protocol": ip_protocol,
                        "severity": severity
                    })

    s3_findings = check_s3_buckets()
    iam_findings = check_iam_mfa()
    generate_report(vulnerabilities, s3_findings, iam_findings)



def generate_report(vulnerabilities, s3_findings=None, iam_findings=None):
    """
    Writes all vulnerability findings to a single Markdown report —
    Security Groups, S3 buckets, and IAM MFA combined.

    Args:
        vulnerabilities (list): Security Group findings.
        s3_findings (list): Public S3 bucket findings.
        iam_findings (list): IAM users without MFA findings.

    Output:
        Cloud_Security_Audit_Report.md — saved in the project folder.
    """
    s3_findings = s3_findings or []
    iam_findings = iam_findings or []
    filename = "Cloud_Security_Audit_Report.md"
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(filename, "w") as f:
        f.write(f"# Executive Cloud Security Audit Report\n")
        f.write(f"**Audit Timestamp:** {date_str}\n\n")
        f.write(f"## Executive Summary\n")
        
        if not vulnerabilities:
            f.write("PASS: No publicly exposed firewall rules detected.\n")
            return
            
        f.write(f"ACTION REQUIRED: Detected {len(vulnerabilities)} firewall rules exposing ports to the public internet.\n\n")
        f.write(f"## Findings\n")
        f.write("| Severity | Security Group | ID | Port | Protocol |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        
        for vuln in vulnerabilities:
            f.write(f"| {vuln['severity']} | {vuln['sg_name']} | {vuln['sg_id']} | {vuln['port']} | {vuln['protocol']} |\n")

        f.write(f"\n## S3 Bucket Findings\n")
        if not s3_findings:
            f.write("PASS: No publicly accessible S3 buckets detected.\n")
        else:
            f.write("| Severity | Bucket | Issue |\n")
            f.write("| :--- | :--- | :--- |\n")
            for s3 in s3_findings:
                f.write(f"| {s3['severity']} | {s3['bucket']} | {s3['issue']} |\n")

        f.write(f"\n## IAM MFA Findings\n")
        if not iam_findings:
            f.write("PASS: All IAM users have MFA enabled.\n")
        else:
            f.write("| Severity | User | Issue |\n")
            f.write("| :--- | :--- | :--- |\n")
            for iam_f in iam_findings:
                f.write(f"| {iam_f['severity']} | {iam_f['user']} | {iam_f['issue']} |\n")

    print(f"Audit complete! Report saved to: {os.path.abspath(filename)}")

def check_s3_buckets():
    """
    Scans all S3 buckets in the AWS account and checks their
    Access Control Lists (ACLs) for public read access.

    Returns:
        list: Findings where a bucket is publicly accessible
              to all internet users (AllUsers group).
    """
    s3 = boto3.client('s3', region_name='us-east-1')
    findings = []
    
    buckets = s3.list_buckets()['Buckets']
    
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append({
                        "bucket": name,
                        "issue": "Public access via ACL",
                        "severity": "CRITICAL"
                    })
        except Exception as e:
            pass
    
    return findings

def check_iam_mfa():
    """
    Scans all IAM users in the AWS account and checks whether
    each one has Multi-Factor Authentication (MFA) enabled.

    Returns:
        list: Findings for any IAM user without MFA enabled —
              a common identity security gap.
    """
    iam = boto3.client('iam')
    findings = []

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']

        if len(mfa_devices) == 0:
            findings.append({
                "user": username,
                "issue": "No MFA device enabled",
                "severity": "WARNING"
            })

    return findings

if __name__ == "__main__":
    run_network_audit()