
import subprocess
import json


def scan_open_ssh():
    result = subprocess.run(
        [
            "aws", "ec2", "describe-security-groups",
            "--query", "SecurityGroups[*].IpPermissions",
            "--output", "json"
        ],
        capture_output=True,
        text=True
    )

    permissions = json.loads(result.stdout)

    findings = []

    for group in permissions:
        for rule in group:
            if rule.get("FromPort") == 22:
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "issue": "SSH open to internet",
                            "severity": "HIGH"
                        })

    return findings
