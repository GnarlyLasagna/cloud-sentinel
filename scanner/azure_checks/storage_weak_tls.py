
# scanner/azure_checks/storage_weak_tls.py

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
        if acc.get("minimumTlsVersion") in ["TLS1_0", "TLS1_1"]:
            findings.append({
                "provider": "Azure",
                "resource_type": "Storage Account",
                "resource_id": acc["name"],
                "check":"storage_weak_tls.py",
                "issue": "Weak TLS version",
                "severity": "MEDIUM",
                "description": "Storage account allows outdated TLS versions."
            })

    return findings
