
# scanner/gcp_checks/iam_roles.py

def run():
    import subprocess, json

    findings = []

    try:
        # Get current project
        project_result = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True, text=True
        )

        project = project_result.stdout.strip()

        if not project:
            return []

        # Get IAM policy
        result = subprocess.run(
            ["gcloud", "projects", "get-iam-policy", project, "--format=json"],
            capture_output=True, text=True
        )

        policy = json.loads(result.stdout) if result.stdout else {}

        bindings = policy.get("bindings", [])

        risky_roles = {"roles/owner", "roles/editor"}

        seen_roles = set()

        for binding in bindings:
            role = binding.get("role")

            if role in risky_roles:

                # Deduplicate by role
                if role in seen_roles:
                    continue

                seen_roles.add(role)

                members = binding.get("members", [])

                findings.append({
                    "provider": "GCP",
                    "resource_type": "IAM Role",
                    "check":"iam_roles.py",
                    "resource_id": role,
                    "issue": f"Overly permissive role: {role}",
                    "severity": "HIGH",
                    "description": f"Role is assigned to {len(members)} member(s)."
                })

    except Exception as e:
        print(f"[GCP ERROR] iam_roles failed: {e}")

    return findings
