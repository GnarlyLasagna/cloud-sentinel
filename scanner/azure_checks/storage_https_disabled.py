
# scanner/azure_checks/storage_https_disabled.py

import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["az", "storage", "account", "list", "-o", "json"],
        capture_output=True,
        text=True
    )

    accounts = json.loads(result.stdout) if result.stdout else []

    for acc in accounts:
        if not acc.get("enableHttpsTrafficOnly", True):
            findings.append({
                "provider": "Azure",
                "resource_type": "Storage Account",
                "resource_id": acc["name"],
                "issue": "HTTPS not enforced",
                "severity": "MEDIUM",
                "description": "Storage account allows HTTP traffic."
            })

    return findings
