#!/usr/bin/env python3

import sys
import os
import json
import csv
from datetime import datetime
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner.engine import run_all_checks, generate_summary

# Terraform Deploy/Destroy
def deploy():
    print("\n[CloudSentinel] Deploying infrastructure...\n")
    providers = ["aws", "azure", "gcp"]

    for provider in providers:
        path = f"terraform/{provider}"
        print(f"[+] Deploying {provider.upper()}...")
        run_terraform(["terraform", "init"], path)
        run_terraform(["terraform", "apply", "-auto-approve"], path)

    print("\n[CloudSentinel] Deployment complete.\n")

def destroy():
    print("\n[CloudSentinel] Destroying infrastructure...\n")
    providers = ["aws", "azure", "gcp"]

    for provider in providers:
        path = f"terraform/{provider}"
        print(f"[-] Destroying {provider.upper()}...")
        run_terraform(["terraform", "destroy", "-auto-approve"], path)


    print("\n[CloudSentinel] Destruction complete.\n")

def run_terraform(cmd, path):
    print(f"[Terraform] Running: {' '.join(cmd)} in {path}")
    result = subprocess.run(cmd, cwd=path)
    if result.returncode != 0:
        print(f"[ERROR] Terraform failed in {path}")
        sys.exit(1)

# Scan / Report
def scan():
    print("\n[CloudSentinel] Running security scan (AWS + Azure + GCP)...\n")

    findings = run_all_checks()
    summary = generate_summary(findings)

    print(f"Found {summary['total_findings']} vulnerabilities:\n")

    for f in findings:
        provider = f.get("provider", "UNKNOWN").upper()
        print(f"[{provider}] {f['issue']} ({f['severity']})")

    if not findings:
        print("No vulnerabilities detected ✅")

    # --- PRINT SUMMARY ---
    print("\n--- Security Summary ---")
    print(f"CRITICAL: {summary['severity_counts']['CRITICAL']}")
    print(f"HIGH:     {summary['severity_counts']['HIGH']}")
    print(f"MEDIUM:   {summary['severity_counts']['MEDIUM']}")
    print(f"LOW:      {summary['severity_counts']['LOW']}")
    print(f"\nRisk Score (0-10): {summary['risk_score']}")

    risk_score = summary.get("risk_score", 0)
    if risk_score >= 7:
        level = "HIGH"
    elif risk_score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    print(f"Overall Risk Level: {level}")

    # --- SAVE JSON ---
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_{timestamp}.json"
    output = {"summary": summary, "findings": findings}

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nScan results saved to: {filename}")


def report():
    print("\n[CloudSentinel] Generating report...\n")
    reports_dir = "reports"
    files = [f for f in os.listdir(reports_dir) if f.startswith("scan_") and f.endswith(".json")]

    if not files:
        print("No scan data found. Run 'scan' first.\n")
        return

    latest_file = sorted(files)[-1]
    filepath = os.path.join(reports_dir, latest_file)

    with open(filepath, "r") as f:
        data = json.load(f)
        findings = data.get("findings", [])
        summary = data.get("summary", {})

    print(f"Using scan data: {latest_file}\n")
    print(f"Found {len(findings)} vulnerabilities:\n")
    for fnd in findings:
        print(f"- {fnd['issue']} ({fnd['severity']})")
    if not findings:
        print("No vulnerabilities detected ✅")

    print("\n--- Security Summary ---")
    print(f"CRITICAL: {summary.get('severity_counts', {}).get('CRITICAL', 0)}")
    print(f"HIGH:     {summary.get('severity_counts', {}).get('HIGH', 0)}")
    print(f"MEDIUM:   {summary.get('severity_counts', {}).get('MEDIUM', 0)}")
    print(f"LOW:      {summary.get('severity_counts', {}).get('LOW', 0)}")
    print(f"\nRisk Score (0-10): {summary.get('risk_score', 0)}")

    # Generate CSV
    csv_file = filepath.replace("scan_", "report_").replace(".json", ".csv")
    if findings:
        fieldnames = findings[0].keys()
    else:
        fieldnames = ["provider", "resource_type", "resource_id", "issue", "severity", "description"]

    with open(csv_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        if findings:
            writer.writerows(findings)

    print(f"\nCSV report saved to: {csv_file}\n")

def run_aws_command(cmd):
    """Run AWS CLI commands and return JSON output"""
    import subprocess, json

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[AWS ERROR] Command failed: {' '.join(cmd)}")
        return []
    try:
        return json.loads(result.stdout) if result.stdout else []
    except json.JSONDecodeError:
        return []


def status():
    import subprocess, json
    print("\n[CloudSentinel] Checking AWS resources...\n")
    issues_found = False

    # --- AWS CHECKS ---
    def run_aws_command(cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout) if result.stdout else []
        except json.JSONDecodeError:
            return []

    # EC2 Instances
    instances = run_aws_command([
        "aws", "ec2", "describe-instances",
        "--filters", "Name=instance-state-name,Values=running,pending,stopped,stopping",
        "--query", "Reservations[*].Instances[*].InstanceId",
        "--output", "json"
    ])
    instance_count = sum(len(r) for r in instances)
    print(f"EC2 Instances:      {instance_count}")
    if instance_count > 0:
        issues_found = True

    # Security Groups
    sgs = run_aws_command([
        "aws", "ec2", "describe-security-groups",
        "--query", "SecurityGroups[*].GroupName",
        "--output", "json"
    ])
    cs_sgs = [sg for sg in sgs if "cloudsentinel" in sg.lower()]
    print(f"Security Groups:    {len(cs_sgs)}")
    if cs_sgs:
        issues_found = True

    # S3 Buckets
    s3_buckets = run_aws_command([
        "aws", "s3api", "list-buckets",
        "--query", "Buckets[*].Name",
        "--output", "json"
    ])
    cs_buckets = [b for b in s3_buckets if "cloudsentinel" in b.lower()]
    print(f"S3 Buckets:         {len(cs_buckets)}")
    if cs_buckets:
        issues_found = True

    # RDS Instances
    rds_instances = run_aws_command([
        "aws", "rds", "describe-db-instances",
        "--query", "DBInstances[*].DBInstanceIdentifier",
        "--output", "json"
    ])
    cs_rds = [r for r in rds_instances if "cloudsentinel" in r.lower()]
    print(f"RDS Instances:      {len(cs_rds)}")
    if cs_rds:
        issues_found = True

    # EBS Volumes (unattached)
    volumes = run_aws_command([
        "aws", "ec2", "describe-volumes",
        "--query", "Volumes[?State=='available'].VolumeId",
        "--output", "json"
    ])
    cs_volumes = [v for v in volumes if v]  # optional filtering
    print(f"EBS Volumes:        {len(cs_volumes)}")
    if cs_volumes:
        issues_found = True

    # --- AZURE CHECKS ---
    print("\n[CloudSentinel] Checking Azure resources...\n")

    def azure_list(cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout) if result.stdout else []
        except json.JSONDecodeError:
            return []

    # Resource Groups
    azure_rgs = azure_list(["az", "group", "list", "--query", "[].name", "-o", "json"])
    ignored_rg_prefixes = ["networkwatcher", "microsoft-azure"]
    user_rgs = [rg for rg in azure_rgs if not any(rg.lower().startswith(p) for p in ignored_rg_prefixes)]
    print(f"Resource Groups:    {len(user_rgs)}")
    if user_rgs:
        issues_found = True

    # Virtual Machines
    azure_vms = azure_list(["az", "vm", "list", "--query", "[].name", "-o", "json"])
    print(f"Virtual Machines:   {len(azure_vms)}")
    if azure_vms:
        issues_found = True

    # Network Security Groups
    azure_nsgs = azure_list(["az", "network", "nsg", "list", "--query", "[].name", "-o", "json"])
    print(f"Network Security Groups: {len(azure_nsgs)}")
    if azure_nsgs:
        issues_found = True

    # Storage Accounts
    azure_sas = azure_list(["az", "storage", "account", "list", "--query", "[].name", "-o", "json"])
    print(f"Storage Accounts:   {len(azure_sas)}")
    if azure_sas:
        issues_found = True

    # Public IP Addresses
    azure_ips = azure_list(["az", "network", "public-ip", "list", "--query", "[].name", "-o", "json"])
    print(f"Public IP Addresses: {len(azure_ips)}")
    if azure_ips:
        issues_found = True

    # Managed Disks (unattached)
    azure_disks = azure_list(["az", "disk", "list", "--query", "[?managedBy==null].name", "-o", "json"])
    print(f"Unattached Disks:   {len(azure_disks)}")
    if azure_disks:
        issues_found = True

    # --- GCP CHECKS ---
    print("\n[CloudSentinel] Checking GCP resources...\n")

    def gcp_list(cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout) if result.stdout else []
        except json.JSONDecodeError:
            return []

    # Compute Instances
    gcp_vms = gcp_list(["gcloud", "compute", "instances", "list", "--format=json"])
    cs_vms = [vm for vm in gcp_vms if "cloudsentinel" in vm["name"].lower()]
    print(f"GCP Compute Instances:  {len(cs_vms)}")
    if cs_vms:
        issues_found = True

    # Persistent Disks (unattached)
    gcp_disks = gcp_list(["gcloud", "compute", "disks", "list", "--format=json"])
    unattached_disks = [d for d in gcp_disks if d.get("users") is None]
    print(f"GCP Unattached Disks:   {len(unattached_disks)}")
    if unattached_disks:
        issues_found = True

    # Static IPs (reserved)
    gcp_ips = gcp_list(["gcloud", "compute", "addresses", "list", "--format=json"])
    print(f"GCP Reserved IPs:       {len(gcp_ips)}")
    if gcp_ips:
        issues_found = True

    # Storage Buckets
    gcp_buckets = gcp_list(["gcloud", "storage", "buckets", "list", "--format=json"])
    cs_buckets = [b for b in gcp_buckets if "cloudsentinel" in b["name"].lower()]
    print(f"GCP Storage Buckets:    {len(cs_buckets)}")
    if cs_buckets:
        issues_found = True

    # Networks
    gcp_networks = gcp_list(["gcloud", "compute", "networks", "list", "--format=json"])
    user_networks = [n for n in gcp_networks if n["name"] != "default"]
    print(f"GCP Networks:           {len(user_networks)}")
    if user_networks:
        issues_found = True

    # --- FINAL STATUS ---
    print()
    if not issues_found:
        print("Cloud Environment Status: CLEAN ✅\n")
    else:
        print("Cloud Environment Status: RESOURCES REMAIN ⚠️\n")



# CLI Main
def main():
    if len(sys.argv) < 2:
        print("\nUsage: cloudsentinel <command>")
        print("Commands: deploy | scan | report | destroy | status")
        sys.exit(1)

    command = sys.argv[1].lower()
    if command == "deploy":
        deploy()
    elif command == "destroy":
        destroy()
    elif command == "scan":
        scan()
    elif command == "report":
        report()
    elif command == "status":
        status()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()

