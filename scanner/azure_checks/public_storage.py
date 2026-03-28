
# scanner/azure_checks/public_storage.py

import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["az", "storage", "container", "list",
         "--account-name", "",
         "--auth-mode", "login",
         "-o", "json"],
        capture_output=True,
        text=True
    )

    accounts = subprocess.run(
        ["az", "storage", "account", "list", "-o", "json"],
        capture_output=True,
        text=True
    )

    storage_accounts = json.loads(accounts.stdout) if accounts.stdout else []

    for acc in storage_accounts:
        acc_name = acc["name"]

        containers_result = subprocess.run(
            ["az", "storage", "container", "list",
             "--account-name", acc_name,
             "--auth-mode", "login",
             "-o", "json"],
            capture_output=True,
            text=True
        )

        containers = json.loads(containers_result.stdout) if containers_result.stdout else []

        for c in containers:
            if c.get("publicAccess") in ["blob", "container"]:
                findings.append({
                    "provider": "Azure",
                    "resource_type": "Storage Container",
                    "resource_id": f"{acc_name}/{c['name']}",
                    "check":"public_storage.py",
                    "issue": "Public storage container",
                    "severity": "HIGH",
                    "description": "Container allows anonymous public access."
                })

    return findings
