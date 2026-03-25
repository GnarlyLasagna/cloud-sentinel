
# scanner/gcp_checks/public_vm.py
import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["gcloud", "compute", "instances", "list", "--format=json"],
        capture_output=True,
        text=True
    )

    instances = json.loads(result.stdout)

    for vm in instances:
        for interface in vm.get("networkInterfaces", []):
            if "accessConfigs" in interface:
                findings.append({
                    "provider": "GCP",
                    "resource_type": "vm",
                    "resource_id": vm["name"],
                    "issue": "VM has public IP",
                    "severity": "MEDIUM",
                    "description": "Instance is publicly accessible"
                })

    return findings
