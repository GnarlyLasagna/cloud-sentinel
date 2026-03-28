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
        # --- Check ACLs ---
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
                    "check":"public_s3.py",
                    "issue": "S3 bucket publicly accessible (ACL)",
                    "severity": "HIGH",
                    "description": f"Bucket allows {permission} access to everyone via ACL"
                })

        # --- Check Bucket Policy ---
        try:
            policy_result = subprocess.run(
                ["aws", "s3api", "get-bucket-policy", "--bucket", bucket, "--output", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            policy = json.loads(policy_result.stdout)["Policy"]
            policy_json = json.loads(policy)

            for stmt in policy_json.get("Statement", []):
                principal = stmt.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    findings.append({
                        "provider": "aws",
                        "resource_type": "s3_bucket",
                        "resource_id": bucket,
                        "check":"public_s3.py",
                        "issue": "S3 bucket publicly accessible (Policy)",
                        "severity": "HIGH",
                        "description": f"Bucket allows public access via bucket policy: {stmt.get('Action')}"
                    })
        except subprocess.CalledProcessError:
            # No bucket policy exists, ignore
            pass

    return findings


