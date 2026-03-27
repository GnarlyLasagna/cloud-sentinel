
# scanner/gcp_checks/public_vm.py

import subprocess
import json

def run():
    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        instances = json.loads(result.stdout) if result.stdout else []

        for vm in instances:
            for interface in vm.get("networkInterfaces", []):
                if interface.get("accessConfigs"):
                    findings.append({
                        "provider": "GCP",
                        "resource_type": "VM Instance",
                        "resource_id": vm["name"],
                        "issue": "VM has public IP",
                        "severity": "MEDIUM",
                        "description": "Instance is exposed to the internet via a public IP."
                    })
                    break

    except Exception as e:
        print(f"[GCP ERROR] public_vm failed: {e}")

    return findings
