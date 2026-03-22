
import subprocess
import json


def run():
    result = subprocess.run(
        ["aws", "s3api", "list-buckets", "--query", "Buckets[*].Name", "--output", "json"],
        capture_output=True,
        text=True
    )

    buckets = json.loads(result.stdout)
    findings = []

    for bucket in buckets:
        acl_result = subprocess.run(
            ["aws", "s3api", "get-bucket-acl", "--bucket", bucket, "--output", "json"],
            capture_output=True,
            text=True
        )

        acl = json.loads(acl_result.stdout)

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission")

            if grantee.get("URI", "").endswith("AllUsers"):
                findings.append({
                    "provider": "aws",
                    "resource_type": "s3_bucket",
                    "resource_id": bucket,
                    "issue": "S3 bucket publicly accessible",
                    "severity": "HIGH",
                    "description": f"Bucket allows {permission} access to everyone"
                })

    return findings
