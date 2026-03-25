
# scanner/gcp_checks/iam_roles.py

def run():
    import subprocess, json

    findings = []

    try:
        result = subprocess.run(
            ["gcloud", "projects", "get-iam-policy", 
             subprocess.run(["gcloud", "config", "get-value", "project"], capture_output=True, text=True).stdout.strip(),
             "--format=json"],
            capture_output=True, text=True
        )

        policy = json.loads(result.stdout) if result.stdout else {}

        bindings = policy.get("bindings", [])

        risky_roles = ["roles/owner", "roles/editor"]

        for binding in bindings:
            role = binding.get("role")

            if role in risky_roles:
                for member in binding.get("members", []):
                    findings.append({
                        "provider": "GCP",
                        "resource_type": "IAM",
                        "resource_id": member,
                        "issue": f"Overly permissive role: {role}",
                        "severity": "HIGH",
                        "description": "User/service account has excessive permissions."
                    })

    except Exception as e:
        print(f"[GCP ERROR] iam_roles failed: {e}")

    return findings
