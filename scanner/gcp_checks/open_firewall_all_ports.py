def run():
    import subprocess, json

    findings = []
    seen = set()

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
                if rule.get("IPProtocol", "").lower() != "tcp":
                    continue

                ports = rule.get("ports", [])

                # Normalize check
                if not any(p in ["0-65535", "0-65535/tcp"] for p in ports):
                    continue

                # 🔥 Dedup key (VERY important)
                key = fw.get("name")

                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "provider": "GCP",
                    "resource_type": "Firewall Rule",
                    "check":"open_firewall_all_ports.py",
                    "resource_id": fw.get("name"),
                    "issue": "Fully open firewall (all ports)",
                    "severity": "CRITICAL",
                    "description": "All TCP ports are open to the internet."
                })

    except Exception as e:
        print(f"[GCP ERROR] open_firewall_all_ports failed: {e}")

    return findings
