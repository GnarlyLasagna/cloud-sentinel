
import subprocess
import json


def run():
    result = subprocess.run(
        [
            "aws", "ec2", "describe-volumes",
            "--query", "Volumes[*].{VolumeId:VolumeId,Encrypted:Encrypted}",
            "--output", "json"
        ],
        capture_output=True,
        text=True
    )

    volumes = json.loads(result.stdout)
    findings = []

    for vol in volumes:
        if not vol["Encrypted"]:
            findings.append({
                "provider": "aws",
                "resource_type": "ebs_volume",
                "resource_id": vol["VolumeId"],
                "check":"ebs_encryption.py",
                "issue": "Unencrypted EBS volume",
                "severity": "MEDIUM",
                "description": "EBS volume is not encrypted"
            })

    return findings
