
# scanner/gcp_checks/public_storage.py
def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "storage", "buckets", "list", "--format=json"],
            capture_output=True, text=True
        )
        buckets = json.loads(result.stdout) if result.stdout else []

        for b in buckets:
            if b.get("iamConfiguration", {}).get("uniformBucketLevelAccess") is False:
                findings.append({
                    "provider": "GCP",
                    "resource_type": "Storage Bucket",
                    "check":"public_storage.py",
                    "resource_id": b["name"],
                    "issue": "Bucket ACLs allow non-uniform access",
                    "severity": "HIGH",
                    "description": "Bucket does not enforce uniform bucket-level access."
                })

    except Exception as e:
        print(f"[GCP ERROR] public_storage check failed: {e}")

    return findings
