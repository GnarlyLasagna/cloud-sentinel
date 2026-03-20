#!/usr/bin/env python3

import sys
import os
import json
import csv
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import subprocess
from scanner.aws_scanner import scan_open_ssh

def deploy():
    print("\n")
    print("[CloudSentinel] Deploying AWS infrastructure...")

    subprocess.run(["terraform", "init"], cwd="terraform/aws")
    subprocess.run(["terraform", "apply", "-auto-approve"], cwd="terraform/aws")

def scan():
    print("\n[CloudSentinel] Running AWS security scan...\n")

    findings = []
    findings.extend(scan_open_ssh())

    print(f"Found {len(findings)} vulnerabilities:\n")

    for f in findings:
        print(f"- {f['issue']} ({f['severity']})")

    if not findings:
        print("No vulnerabilities detected ✅")

    # Save raw scan results ONLY
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\nScan results saved to: {filename}\n")

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
        findings = json.load(f)

    print(f"Using scan data: {latest_file}\n")

    print(f"Found {len(findings)} vulnerabilities:\n")

    for fnd in findings:
        print(f"- {fnd['issue']} ({fnd['severity']})")

    # --- Generate CSV ---
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


def destroy():
    print("\n")
    print("[CloudSentinel] Destroying AWS infrastructure...")

    subprocess.run(["terraform", "destroy", "-auto-approve"], cwd="terraform/aws")


def run_aws_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else []

def status():
    print("\n[CloudSentinel] Checking AWS resources...\n")

    issues_found = False

    # --- EC2 INSTANCES ---
    instances = run_aws_command([
        "aws", "ec2", "describe-instances",
        "--filters", "Name=instance-state-name,Values=running,pending,stopped,stopping",
        "--query", "Reservations[*].Instances[*].InstanceId",
        "--output", "json"
    ])

    instance_count = sum(len(r) for r in instances)

    if instance_count == 0:
        print(f"EC2 Instances:      {instance_count} ")
    else:
        print(f"EC2 Instances:      {instance_count} ")
        issues_found = True

    # --- SECURITY GROUPS (CloudSentinel only) ---
    sgs = run_aws_command([
        "aws", "ec2", "describe-security-groups",
        "--query", "SecurityGroups[*].GroupName",
        "--output", "json"
    ])

    cs_sgs = [sg for sg in sgs if "cloudsentinel" in sg.lower()]

    if len(cs_sgs) == 0:
        print(f"Security Groups:    0 ")
    else:
        print(f"Security Groups:    {len(cs_sgs)} ")
        issues_found = True

    # --- ELASTIC IPs ---
    eips = run_aws_command([
        "aws", "ec2", "describe-addresses",
        "--query", "Addresses[*].PublicIp",
        "--output", "json"
    ])

    if len(eips) == 0:
        print(f"Elastic IPs:        0 ")
    else:
        print(f"Elastic IPs:        {len(eips)} ")
        issues_found = True

    # --- EBS VOLUMES (AVAILABLE = unattached) ---
    volumes = run_aws_command([
        "aws", "ec2", "describe-volumes",
        "--query", "Volumes[?State=='available'].VolumeId",
        "--output", "json"
    ])

    if len(volumes) == 0:
        print(f"EBS Volumes:        0 ")
    else:
        print(f"EBS Volumes:        {len(volumes)} ")
        issues_found = True

    # --- FINAL STATUS ---
    print()

    if not issues_found:
        print("AWS Environment Status: CLEAN \n")
    else:
        print("AWS Environment Status: RESOURCES REMAIN \n")


def main():
    if len(sys.argv) < 2:
        print("\n")
        print("Usage: cloudsentinel <command>")
        print("Commands: deploy | scan | report | destroy")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "deploy":
        deploy()
    elif command == "scan":
        scan()
    elif command == "report":
        report()
    elif command == "destroy":
        destroy()
    elif command == "status":
        status()
    else:
        print(f"Unknown command: {command}")
        print("Valid commands: deploy | scan | report | destroy")


if __name__ == "__main__":
    main()

