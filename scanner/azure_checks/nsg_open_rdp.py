
# scanner/azure_checks/nsg_open_rdp.py

import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["az", "network", "nsg", "rule", "list", "-o", "json"],
        capture_output=True,
        text=True
    )

    rules = json.loads(result.stdout) if result.stdout else []

    for rule in rules:
        if (
            rule.get("destinationPortRange") == "3389" and
            rule.get("access") == "Allow" and
            rule.get("sourceAddressPrefix") == "*"
        ):
            findings.append({
                "provider": "Azure",
                "resource_type": "NSG Rule",
                "resource_id": rule.get("name"),
                "check":"nsg_open_rdp.py",
                "issue": "RDP open to the internet",
                "severity": "HIGH",
                "description": "Port 3389 exposed to 0.0.0.0/0."
            })

    return findings
