import subprocess
import json

def run_azure_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else []

def run():
    findings = []

    nsgs = run_azure_command([
        "az", "network", "nsg", "list",
        "--query", "[].{name:name, rules:securityRules}",
        "-o", "json"
    ])

    for nsg in nsgs:
        for rule in nsg.get("rules", []):
            access = rule.get("access")
            direction = rule.get("direction")
            protocol = rule.get("protocol")

            # Combine single string and array prefixes
            src_prefixes = []
            if rule.get("sourceAddressPrefix"):
                src_prefixes.append(rule["sourceAddressPrefix"])
            if rule.get("sourceAddressPrefixes"):
                src_prefixes.extend(rule["sourceAddressPrefixes"])

            dst_ports = []
            if rule.get("destinationPortRange"):
                dst_ports.append(rule["destinationPortRange"])
            if rule.get("destinationPortRanges"):
                dst_ports.extend(rule["destinationPortRanges"])

            # Detect inbound rules that allow traffic from anywhere
            if access == "Allow" and direction == "Inbound" and any(p in ["*", "0.0.0.0/0"] for p in src_prefixes):
                findings.append({
                    "provider": "azure",
                    "resource_type": "nsg",
                    "resource_id": nsg["name"],
                    "issue": f"NSG rule '{rule['name']}' open to internet",
                    "severity": "HIGH",
                    "description": f"NSG rule '{rule['name']}' allows inbound traffic from any source ({src_prefixes}) on ports {dst_ports} with protocol '{protocol}'."
                })

    return findings

