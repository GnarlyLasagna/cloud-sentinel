
import traceback
import json

# AWS CHECKS
import scanner.aws_checks.open_ssh as aws_open_ssh
import scanner.aws_checks.open_ports as aws_open_ports
import scanner.aws_checks.public_s3 as aws_public_s3
import scanner.aws_checks.iam_roles as aws_iam_roles
import scanner.aws_checks.cloudtrail as aws_cloudtrail
import scanner.aws_checks.ebs_encryption as aws_ebs_encryption
import scanner.aws_checks.all_ports_open as aws_all_ports_open
import scanner.aws_checks.open_rdp as aws_open_rdp
import scanner.aws_checks.public_rds as aws_public_rds
import scanner.aws_checks.rds_encryption as aws_rds_encryption
import scanner.aws_checks.ebs_unattached as aws_ebs_unattached

# AZURE CHECKS
import scanner.azure_checks.nsg_open_ports as azure_nsg_open_ports
import scanner.azure_checks.public_storage as azure_public_storage
import scanner.azure_checks.nsg_allow_all as azure_nsg_allow_all
import scanner.azure_checks.nsg_open_ssh as azure_nsg_open_ssh
import scanner.azure_checks.nsg_open_rdp as azure_nsg_open_rdp
import scanner.azure_checks.storage_https_disabled as azure_storage_https_disabled
import scanner.azure_checks.storage_weak_tls as azure_storage_weak_tls
import scanner.azure_checks.public_ip as azure_public_ip
import scanner.azure_checks.defender_disabled as azure_defender_disabled

# GCP CHECKS
import scanner.gcp_checks.open_ssh as gcp_open_ssh
import scanner.gcp_checks.public_storage as gcp_public_storage
import scanner.gcp_checks.public_vm as gcp_public_vm
import scanner.gcp_checks.project_ssh_keys as gcp_project_ssh_keys
import scanner.gcp_checks.iam_roles as gcp_iam_roles
import scanner.gcp_checks.open_firewall_all_ports as gcp_open_all
import scanner.gcp_checks.unattached_disk as gcp_disk
import scanner.gcp_checks.static_ip_unused as gcp_ip
import scanner.gcp_checks.service_account_attached as gcp_sa


# HELPERS

def safe_run_check(check, provider):
    try:
        result = check()

        if not result:
            return []

        if not isinstance(result, list):
            print(f"[{provider} WARNING] {check.__name__} did not return a list")
            return []

        valid = []
        for f in result:
            if isinstance(f, dict) and "issue" in f:
                valid.append(f)
            else:
                print(f"[{provider} WARNING] Invalid finding format in {check.__name__}")

        return valid

    except Exception as e:
        print(f"[{provider} ERROR] {check.__name__} failed: {e}")
        traceback.print_exc()
        return []

def deduplicate_findings(findings):
    seen = set()
    unique = []

    for f in findings:
        provider = (f.get("provider") or "").lower().strip()
        issue = (f.get("issue") or "").lower().strip()
        resource_type = (f.get("resource_type") or "").lower().strip()
        resource_id = (f.get("resource_id") or "").lower().strip()

        key = (provider, issue, resource_type, resource_id)

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique



# AWS

def run_aws_checks():
    checks = [
        aws_open_ssh.run,
        aws_open_ports.run,
        aws_public_s3.run,
        aws_iam_roles.run,
        aws_ebs_encryption.run,
        aws_cloudtrail.run,
        aws_all_ports_open.run,
        aws_open_rdp.run,
        aws_public_rds.run,
        aws_rds_encryption.run,
        aws_ebs_unattached.run,
    ]

    findings = []
    for check in checks:
        findings.extend(safe_run_check(check, "AWS"))

    return findings


# AZURE

def run_azure_checks():
    checks = [
        azure_nsg_open_ports.run,
        azure_public_storage.run,
        azure_nsg_allow_all.run,
        azure_nsg_open_ssh.run,
        azure_nsg_open_rdp.run,
        azure_storage_https_disabled.run,
        azure_storage_weak_tls.run,
        azure_public_ip.run,
        azure_defender_disabled.run,
    ]

    findings = []
    for check in checks:
        findings.extend(safe_run_check(check, "AZURE"))

    return findings


# GCP

def run_gcp_checks():
    checks = [
        gcp_project_ssh_keys.run,
        gcp_open_ssh.run,
        gcp_public_storage.run,
        gcp_iam_roles.run,
        gcp_public_vm.run,
        gcp_sa.run,
        gcp_open_all.run,
        gcp_disk.run,
        gcp_ip.run,
    ]
    

    findings = []
    for check in checks:
        findings.extend(safe_run_check(check, "GCP"))

    return findings


# ACCOUNT-LEVEL CHECKS

def run_account_checks():
    findings = []

    try:
        findings.extend(safe_run_check(aws_cloudtrail.run, "AWS"))
        findings.extend(safe_run_check(azure_defender_disabled.run, "AZURE"))
        findings.extend(safe_run_check(gcp_iam_roles.run, "GCP"))

    except Exception as e:
        print(f"[ACCOUNT ERROR] {e}")

    return findings


# MAIN ENGINE

def run_all_checks():
    resource_findings = []

    resource_findings.extend(run_aws_checks())
    resource_findings.extend(run_azure_checks())
    resource_findings.extend(run_gcp_checks())

    if len(resource_findings) == 0:
        print("\n[INFO] No vulnerable resources found.\n")

    account_findings = run_account_checks()

    all_findings = resource_findings + account_findings
    return deduplicate_findings(all_findings)


# SUMMARY

def generate_summary(findings):
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    weights = {
        "CRITICAL": 5,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    total_score = 0

    for f in findings:
        severity = f.get("severity", "LOW")

        if severity in severity_counts:
            severity_counts[severity] += 1

        total_score += weights.get(severity, 1)

    max_possible = len(findings) * 5 if findings else 1
    normalized_score = round((total_score / max_possible) * 10, 2)

    return {
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "risk_score": normalized_score
    }


# SAVE RESULTS

def save_findings(filename, findings):
    output = {
        "summary": generate_summary(findings),
        "findings": findings
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[INFO] Findings saved to {filename}")
