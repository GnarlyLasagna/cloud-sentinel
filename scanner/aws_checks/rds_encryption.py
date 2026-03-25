
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
        if not db.get("StorageEncrypted"):
            findings.append({
                "provider": "aws",
                "resource_type": "rds",
                "resource_id": db["DBInstanceIdentifier"],
                "issue": "RDS not encrypted",
                "severity": "MEDIUM",
                "description": "Database storage is not encrypted"
            })

    return findings
