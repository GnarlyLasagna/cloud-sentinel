
import subprocess
import json


def run():
    result = subprocess.run(
        ["aws", "cloudtrail", "describe-trails", "--query", "trailList[*].Name", "--output", "json"],
        capture_output=True,
        text=True
    )

    trails = json.loads(result.stdout)
    findings = []

    if not trails:
        findings.append({
            "provider": "aws",
            "resource_type": "cloudtrail",
            "resource_id": "N/A",
            "issue": "CloudTrail not enabled",
            "severity": "HIGH",
            "description": "No CloudTrail trails are configured"
        })

    return findings
