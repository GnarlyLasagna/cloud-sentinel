# scanner/engine.py

import traceback
from scanner.azure_checks import (
    nsg_open_ssh,
    public_storage
)

from scanner.aws_checks import (
    open_ssh,
    open_ports,
    public_s3,
    iam_roles,
    cloudtrail,
    ebs_encryption
)

# AWS Checks
def run_aws_checks():
    findings = []

    checks = [
        open_ssh.run,
        open_ports.run,
        public_s3.run,
        iam_roles.run,
        cloudtrail.run,
        ebs_encryption.run,
    ]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[AWS ERROR] {check.__name__} failed: {e}")
            traceback.print_exc()

    return findings

# Azure Checks
def run_azure_checks():
    findings = []

    checks = [
        nsg_open_ssh.run,
        public_storage.run,
    ]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[AZURE ERROR] {check.__name__} failed: {e}")
            traceback.print_exc()

    return findings

# Run All Clouds
def run_all_checks():
    findings = []
    findings.extend(run_aws_checks())
    findings.extend(run_azure_checks())
    return findings

# Summary & Risk Scoring
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

# Optional: Save Findings
def save_findings(filename, findings):
    import json
    from datetime import datetime

    output = {
        "summary": generate_summary(findings),
        "findings": findings
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[INFO] Findings saved to {filename}")
