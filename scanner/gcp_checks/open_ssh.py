def run():
    import subprocess, json

    findings = []
    seen = set()

    try:
        fw_result = subprocess.run(
            ["gcloud", "compute", "firewall-rules", "list", "--format=json"],
            capture_output=True, text=True
        )
        firewalls = json.loads(fw_result.stdout) if fw_result.stdout else []

        vm_result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True, text=True
        )
        instances = json.loads(vm_result.stdout) if vm_result.stdout else []

        for vm in instances:
            has_public_ip = any(
                ni.get("accessConfigs") for ni in vm.get("networkInterfaces", [])
            )

            if not has_public_ip:
                continue

            for fw in firewalls:
                if fw.get("direction") != "INGRESS":
                    continue

                source_ranges = fw.get("sourceRanges", [])
                if not any("0.0.0.0/0" in s for s in source_ranges):
                    continue

                for rule in fw.get("allowed", []):
                    if rule.get("IPProtocol", "").lower() != "tcp":
                        continue

                    ports = rule.get("ports", [])

                    # Normalize port matching
                    if not any(p in ["22", "22-22"] for p in ports):
                        continue

                    # 🔥 Improved dedup key
                    key = (
                        fw.get("name"),
                        vm.get("name"),
                        rule.get("IPProtocol"),
                        tuple(sorted(ports)),
                    )

                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append({
                        "provider": "GCP",
                        "resource_type": "Firewall Rule",
                        "resource_id": fw.get("name"),
                        "check":"open_ssh.py",
                        "issue": "SSH open to the internet",
                        "severity": "CRITICAL",
                        "description": f"Port 22 open to 0.0.0.0/0 on VM {vm.get('name')}"
                    })

    except Exception as e:
        print(f"[GCP ERROR] open_ssh failed: {e}")

    return findings
