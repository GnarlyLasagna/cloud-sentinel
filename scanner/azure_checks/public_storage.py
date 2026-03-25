
import subprocess
import json

def run_azure_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else []

def run():
    findings = []

    accounts = run_azure_command([
        "az", "storage", "account", "list",
        "--query", "[].{name:name, publicAccess:allowBlobPublicAccess}",
        "-o", "json"
    ])

    for acc in accounts:
        if acc.get("publicAccess"):
            findings.append({
                "provider": "azure",
                "resource_type": "storage_account",
                "resource_id": acc["name"],
                "issue": "Public blob access enabled",
                "severity": "HIGH",
                "description": "Storage account allows public blob access"
            })

    return findings
