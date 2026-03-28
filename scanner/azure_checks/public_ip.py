
# scanner/azure_checks/public_ip.py

import subprocess
import json

def run():
    findings = []

    result = subprocess.run(
        ["az", "network", "public-ip", "list", "-o", "json"],
        capture_output=True,
        text=True
    )

    ips = json.loads(result.stdout) if result.stdout else []

    for ip in ips:
        findings.append({
            "provider": "Azure",
            "resource_type": "Public IP",
            "resource_id": ip["name"],
            "check":"public_ip.py",
            "issue": "Public IP address exposed",
            "severity": "MEDIUM",
            "description": "Resource has a public IP address."
        })

    return findings
