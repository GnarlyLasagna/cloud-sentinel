
# scanner/azure_checks/nsg_allow_all.py

import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["az", "network", "nsg", "rule", "list", "--query", "[].{nsg:networkSecurityGroup.name, rules:securityRules}", "-o", "json"],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout) if result.stdout else []

    for nsg in data:
        for rule in nsg.get("rules", []):
            if (
                rule.get("access") == "Allow" and
                rule.get("direction") == "Inbound" and
                rule.get("sourceAddressPrefix") == "*" and
                rule.get("destinationPortRange") == "*"
            ):
                findings.append({
                    "provider": "Azure",
                    "resource_type": "NSG",
                    "resource_id": nsg["nsg"],
                    "check":"nsg_open_rdp.py",
                    "issue": "NSG allows ALL inbound traffic",
                    "severity": "CRITICAL",
                    "description": "Inbound rule allows all traffic from any source."
                })

    return findings
