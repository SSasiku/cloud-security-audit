import boto3
import os
from datetime import datetime

def run_network_audit():
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

    generate_report(vulnerabilities)

def generate_report(vulnerabilities):
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
            
    print(f"Audit complete! Report saved to: {os.path.abspath(filename)}")

if __name__ == "__main__":
    run_network_audit()