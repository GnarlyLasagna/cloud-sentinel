
# scanner/azure_checks/defender_disabled.py

import subprocess
import json

def run():
    findings = []

    try:
        result = subprocess.run(
            ["az", "security", "pricing", "list", "-o", "json"],
            capture_output=True,
            text=True
        )

        if not result.stdout:
            return findings

        plans = json.loads(result.stdout)

        for plan in plans:
            # ✅ Handle case where Azure returns strings instead of dicts
            if isinstance(plan, str):
                findings.append({
                    "provider": "Azure",
                    "resource_type": "Subscription",
                    "resource_id": plan,
                    "issue": "Microsoft Defender not enabled",
                    "severity": "HIGH",
                    "description": "Defender plan appears missing or not properly configured."
                })
                continue

            # ✅ Normal expected case
            if isinstance(plan, dict):
                if plan.get("pricingTier") == "Free":
                    findings.append({
                        "provider": "Azure",
                        "resource_type": "Subscription",
                        "resource_id": plan.get("name", "unknown"),
                        "issue": "Microsoft Defender not enabled",
                        "severity": "HIGH",
                        "description": "Advanced threat protection is not enabled."
                    })

    except Exception as e:
        print(f"[AZURE ERROR] defender_disabled failed: {e}")

    return findings
