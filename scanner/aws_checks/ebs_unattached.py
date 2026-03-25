
import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["aws", "ec2", "describe-volumes"],
        capture_output=True, text=True
    )

    volumes = json.loads(result.stdout)["Volumes"]

    for vol in volumes:
        if len(vol.get("Attachments", [])) == 0:
            findings.append({
                "provider": "aws",
                "resource_type": "ebs",
                "resource_id": vol["VolumeId"],
                "issue": "Unattached EBS volume",
                "severity": "LOW",
                "description": "Unused volume may expose sensitive data"
            })

    return findings
