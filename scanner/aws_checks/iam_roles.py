
import subprocess
import json


def run():
    result = subprocess.run(
        ["aws", "iam", "list-roles", "--query", "Roles[*].RoleName", "--output", "json"],
        capture_output=True,
        text=True
    )

    roles = json.loads(result.stdout)
    findings = []

    for role in roles:
        policy_result = subprocess.run(
            ["aws", "iam", "list-attached-role-policies", "--role-name", role, "--output", "json"],
            capture_output=True,
            text=True
        )

        policies = json.loads(policy_result.stdout)

        for policy in policies.get("AttachedPolicies", []):
            if "AdministratorAccess" in policy.get("PolicyName", ""):
                findings.append({
                    "provider": "aws",
                    "resource_type": "iam_role",
                    "check":"iam_roles.py",
                    "resource_id": role,
                    "issue": "Over-permissive IAM role",
                    "severity": "CRITICAL",
                    "description": "Role has AdministratorAccess policy attached"
                })

    return findings
