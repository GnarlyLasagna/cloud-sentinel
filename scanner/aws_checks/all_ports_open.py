
import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["aws", "ec2", "describe-security-groups"],
        capture_output=True, text=True
    )

    sgs = json.loads(result.stdout)["SecurityGroups"]

    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if (
                rule.get("IpProtocol") == "-1" and
                any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            ):
                findings.append({
                    "provider": "aws",
                    "resource_type": "security_group",
                    "resource_id": sg["GroupId"],
                    "check":"all_ports_open.py",
                    "issue": "All ports open to internet",
                    "severity": "CRITICAL",
                    "description": "Security group allows ALL traffic from 0.0.0.0/0"
                })

    return findings
