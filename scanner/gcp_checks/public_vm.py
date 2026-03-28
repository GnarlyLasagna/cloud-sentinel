
# scanner/gcp_checks/public_vm.py
import subprocess
import json

def run():
    findings = []
    seen = set()

    try:
        result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        instances = json.loads(result.stdout) if result.stdout else []

        for vm in instances:
            vm_name = vm.get("name")

            has_public_ip = any(
                interface.get("accessConfigs")
                for interface in vm.get("networkInterfaces", [])
            )

            if not has_public_ip:
                continue

            # 🔥 Dedup per VM
            if vm_name in seen:
                continue
            seen.add(vm_name)

            findings.append({
                "provider": "GCP",
                "resource_type": "VM Instance",
                "resource_id": vm_name,
                "check":"public_vm.py",
                "issue": "VM has public IP",
                "severity": "MEDIUM",
                "description": "Instance is exposed to the internet via a public IP.",
                "vuln_id": "GCP_VM_PUBLIC_IP"
            })

    except Exception as e:
        print(f"[GCP ERROR] public_vm failed: {e}")

    return findings

