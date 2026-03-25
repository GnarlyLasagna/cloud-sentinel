
# scanner/gcp_checks/project_ssh_keys.py
import subprocess
import json

def run():
    findings = []

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
                "resource_type": "project",
                "resource_id": "global",
                "issue": "Project-wide SSH keys configured",
                "severity": "MEDIUM",
                "description": "Centralized SSH keys increase attack surface"
            })

    return findings
