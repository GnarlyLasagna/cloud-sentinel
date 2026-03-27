
def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "firewall-rules", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        firewalls = json.loads(result.stdout) if result.stdout else []

        for fw in firewalls:
            if fw.get("direction") != "INGRESS":
                continue

            if "0.0.0.0/0" not in fw.get("sourceRanges", []):
                continue

            for rule in fw.get("allowed", []):
                if rule.get("IPProtocol", "").lower() == "tcp":
                    ports = rule.get("ports", [])

                    if "0-65535" in ports:
                        findings.append({
                            "provider": "GCP",
                            "resource_type": "Firewall Rule",
                            "resource_id": fw["name"],
                            "issue": "Fully open firewall (all ports)",
                            "severity": "CRITICAL",
                            "description": "All TCP ports are open to the internet."
                        })

    except Exception as e:
        print(f"[GCP ERROR] open_firewall_all_ports failed: {e}")

    return findings
