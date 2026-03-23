
def run():
    import subprocess, json

    findings = []

    try:
        # Get firewall rules
        fw_result = subprocess.run(
            ["gcloud", "compute", "firewall-rules", "list", "--format=json"],
            capture_output=True, text=True
        )
        firewalls = json.loads(fw_result.stdout) if fw_result.stdout else []

        # Get instances
        vm_result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True, text=True
        )
        instances = json.loads(vm_result.stdout) if vm_result.stdout else []

        for vm in instances:
            has_public_ip = False

            for ni in vm.get("networkInterfaces", []):
                if "accessConfigs" in ni:
                    has_public_ip = True

            if not has_public_ip:
                continue

            # Check firewall rules
            for fw in firewalls:
                if fw.get("direction") == "INGRESS":
                    if "0.0.0.0/0" in fw.get("sourceRanges", []):
                        allowed = fw.get("allowed", [])
                        for rule in allowed:
                            if "tcp" in rule.get("IPProtocol", "").lower():
                                if "22" in rule.get("ports", []):
                                    findings.append({
                                        "provider": "GCP",
                                        "resource_type": "VM Instance",
                                        "resource_id": vm["name"],
                                        "issue": "SSH open to the internet",
                                        "severity": "CRITICAL",
                                        "description": "Firewall allows port 22 from 0.0.0.0/0 on a public VM."
                                    })

    except Exception as e:
        print(f"[GCP ERROR] open_ssh failed: {e}")

    return findings
