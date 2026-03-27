
# scanner/gcp_checks/open_ssh.py
def run():
    import subprocess, json

    findings = []

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

                if "0.0.0.0/0" not in fw.get("sourceRanges", []):
                    continue

                for rule in fw.get("allowed", []):
                    if rule.get("IPProtocol", "").lower() == "tcp":
                        if "22" in rule.get("ports", []):
                            findings.append({
                                "provider": "GCP",
                                "resource_type": "Firewall Rule",
                                "resource_id": fw["name"],
                                "issue": "SSH open to the internet",
                                "severity": "CRITICAL",
                                "description": "Port 22 open to 0.0.0.0/0"
                            })

    except Exception as e:
        print(f"[GCP ERROR] open_ssh failed: {e}")

    return findings
