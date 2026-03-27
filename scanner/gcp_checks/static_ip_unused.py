
def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "addresses", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        ips = json.loads(result.stdout) if result.stdout else []

        for ip in ips:
            if not ip.get("users"):
                findings.append({
                    "provider": "GCP",
                    "resource_type": "Static IP",
                    "resource_id": ip["name"],
                    "issue": "Unused static IP",
                    "severity": "LOW",
                    "description": "Static IP reserved but not attached to any resource."
                })

    except Exception as e:
        print(f"[GCP ERROR] static_ip failed: {e}")

    return findings
