# scanner/engine.py

import traceback

# --- AWS ---
import scanner.aws_checks.open_ssh as aws_open_ssh
import scanner.aws_checks.open_ports as aws_open_ports
import scanner.aws_checks.public_s3 as aws_public_s3
import scanner.aws_checks.iam_roles as aws_iam_roles
import scanner.aws_checks.cloudtrail as aws_cloudtrail
import scanner.aws_checks.ebs_encryption as aws_ebs_encryption

# --- AZURE ---
import scanner.azure_checks.nsg_open_ssh as azure_nsg_open_ssh
import scanner.azure_checks.public_storage as azure_public_storage

# --- GCP ---
import scanner.gcp_checks.open_ssh as gcp_open_ssh
import scanner.gcp_checks.public_storage as gcp_public_storage
import scanner.gcp_checks.iam_roles as gcp_iam_roles


# =========================
# AWS Checks
# =========================
def run_aws_checks():
    findings = []

    checks = [
        aws_open_ssh.run,
        aws_open_ports.run,
        aws_public_s3.run,
        aws_iam_roles.run,
        aws_cloudtrail.run,
        aws_ebs_encryption.run,
    ]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[AWS ERROR] {check.__name__} failed: {e}")
            traceback.print_exc()

    return findings


# =========================
# Azure Checks
# =========================
def run_azure_checks():
    findings = []

    checks = [
        azure_nsg_open_ssh.run,
        azure_public_storage.run,
    ]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[AZURE ERROR] {check.__name__} failed: {e}")
            traceback.print_exc()

    return findings


# =========================
# GCP Checks
# =========================
def run_gcp_checks():
    findings = []

    checks = [
        gcp_open_ssh.run,
        gcp_public_storage.run,
        gcp_iam_roles.run,
    ]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[GCP ERROR] {check.__name__} failed: {e}")
            traceback.print_exc()

    return findings


# =========================
# Run All Clouds
# =========================
def run_all_checks():
    findings = []
    findings.extend(run_aws_checks())
    findings.extend(run_azure_checks())
    findings.extend(run_gcp_checks())
    return findings


# =========================
# Summary & Risk Scoring
# =========================
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


# =========================
# Optional: Save Findings
# =========================
def save_findings(filename, findings):
    import json

    output = {
        "summary": generate_summary(findings),
        "findings": findings
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[INFO] Findings saved to {filename}")

