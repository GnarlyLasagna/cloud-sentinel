
def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True,
            text=True
        )

        instances = json.loads(result.stdout) if result.stdout else []

        for vm in instances:
            sa = vm.get("serviceAccounts", [])
            if sa:
                findings.append({
                    "provider": "GCP",
                    "resource_type": "VM Instance",
                    "check":"service_account_attached.py",
                    "resource_id": vm["name"],
                    "issue": "Service account attached to VM",
                    "severity": "MEDIUM",
                    "description": "VM is running with a service account (check for overprivilege)."
                })

    except Exception as e:
        print(f"[GCP ERROR] service_account check failed: {e}")

    return findings
