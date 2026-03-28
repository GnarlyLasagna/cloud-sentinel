
def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "disks", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        disks = json.loads(result.stdout) if result.stdout else []

        for disk in disks:
            if not disk.get("users"):  # No attached VMs
                findings.append({
                    "provider": "GCP",
                    "resource_type": "Disk",
                    "resource_id": disk["name"],
                    "check":"unattached_disk.py",
                    "issue": "Unattached disk (orphaned resource)",
                    "severity": "LOW",
                    "description": "Disk exists but is not attached to any VM."
                })

    except Exception as e:
        print(f"[GCP ERROR] unattached_disk failed: {e}")

    return findings
