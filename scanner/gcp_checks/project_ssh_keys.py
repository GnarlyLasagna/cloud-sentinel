
# scanner/gcp_checks/project_ssh_keys.py

def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "project-info", "describe", "--format=json"],
            capture_output=True,
            text=True
        )

        data = json.loads(result.stdout)

        metadata = data.get("commonInstanceMetadata", {}).get("items", [])

        for item in metadata:
            if item.get("key") == "ssh-keys":
                findings.append({
                    "provider": "GCP",
                    "resource_type": "Project",
                    "check":"project_ssh_keys.py",
                    "resource_id": "global",
                    "issue": "Project-wide SSH keys enabled",
                    "severity": "MEDIUM",
                    "description": "Global SSH keys increase attack surface."
                })

    except Exception as e:
        print(f"[GCP ERROR] project_ssh_keys failed: {e}")

    return findings
