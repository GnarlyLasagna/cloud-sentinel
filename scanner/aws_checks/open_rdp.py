
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
            if rule.get("FromPort") == 3389:
                for ip in rule.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "provider": "aws",
                            "resource_type": "security_group",
                            "resource_id": sg["GroupId"],
                            "check":"open_rdp.py",
                            "issue": "RDP open to internet",
                            "severity": "HIGH",
                            "description": "Port 3389 open to the world"
                        })

    return findings
