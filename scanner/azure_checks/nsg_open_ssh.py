
from .utils import run_azure_command


def run():
    findings = []

    nsgs = run_azure_command([
        "az", "network", "nsg", "list",
        "--query", "[].{name:name, rules:securityRules}",
        "-o", "json"
    ])

    for nsg in nsgs:
        for rule in nsg.get("rules", []):
            if (
                rule.get("destinationPortRange") == "22" and
                rule.get("access") == "Allow" and
                rule.get("sourceAddressPrefix") == "*"
            ):
                findings.append({
                    "provider": "azure",
                    "resource_type": "nsg",
                    "resource_id": nsg["name"],
                    "issue": "SSH open to internet",
                    "severity": "HIGH",
                    "description": "NSG allows SSH (22) from any source"
                })

    return findings
