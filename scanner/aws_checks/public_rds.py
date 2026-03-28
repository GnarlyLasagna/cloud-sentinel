
import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["aws", "rds", "describe-db-instances"],
        capture_output=True, text=True
    )

    dbs = json.loads(result.stdout)["DBInstances"]

    for db in dbs:
        if db.get("PubliclyAccessible"):
            findings.append({
                "provider": "aws",
                "resource_type": "rds",
                "resource_id": db["DBInstanceIdentifier"],
                "check":"public_rds.py",
                "issue": "RDS publicly accessible",
                "severity": "HIGH",
                "description": "Database is exposed to the internet"
            })

    return findings
