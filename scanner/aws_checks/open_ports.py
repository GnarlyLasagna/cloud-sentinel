
# scanner/checks/open_ports.py

import subprocess
import json


def run():
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
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":

                    # Skip SSH (22) and RDP (3389) if you don't want to report
                    if from_port is not None and to_port is not None:
                        if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                            continue

                    # Determine severity dynamically
                    if from_port in [22, 3389]:
                        severity = "HIGH"
                    elif from_port is not None and from_port < 1024:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                    # Handle "all ports open" case
                    if from_port is None:
                        findings.append({
                            "provider": "aws",
                            "resource_type": "security_group",
                            "resource_id": group_id,
                            "check":"open_ports.py",
                            "issue": "All ports open to internet",
                            "severity": "CRITICAL",
                            "description": "All ports are accessible from 0.0.0.0/0"
                        })
                    else:
                        findings.append({
                            "provider": "aws",
                            "resource_type": "security_group",
                            "resource_id": group_id,
                            "check":"open_ports.py",
                            "issue": f"Port {from_port}-{to_port} open to internet",
                            "severity": severity,
                            "description": f"Ports {from_port}-{to_port} accessible from 0.0.0.0/0"
                        })

    return findings

