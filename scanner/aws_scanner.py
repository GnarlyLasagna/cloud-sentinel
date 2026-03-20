import subprocess
import json


def scan_open_ssh():
    result = subprocess.run(
        [
            "aws", "ec2", "describe-security-groups",
            "--query", "SecurityGroups[*].{GroupId:GroupId,IpPermissions:IpPermissions}",
            "--output", "json"
        ],
        capture_output=True,
        text=True
    )

    groups = json.loads(result.stdout)

    findings = []

    for group in groups:
        group_id = group["GroupId"]

        for rule in group["IpPermissions"]:
            if rule.get("FromPort") == 22:
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "provider": "aws",
                            "resource_type": "security_group",
                            "resource_id": group_id,
                            "issue": "SSH open to internet",
                            "severity": "HIGH",
                            "description": "Port 22 is accessible from 0.0.0.0/0"
                        })

    return findings

