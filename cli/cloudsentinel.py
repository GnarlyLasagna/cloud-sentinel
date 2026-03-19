#!/usr/bin/env python3

import sys
import subprocess

def deploy():
    print("\n")
    print("[CloudSentinel] Deploying AWS infrastructure...")

    subprocess.run(["terraform", "init"], cwd="terraform/aws")
    subprocess.run(["terraform", "apply", "-auto-approve"], cwd="terraform/aws")
    print("You have deployed infrastructure using Terraform.")


def scan():
    print("\n")
    print("[CloudSentinel] Scan command triggered")
    print("This will scan cloud resources for security misconfigurations.")


def report():
    print("\n")
    print("[CloudSentinel] Report command triggered")
    print("This will generate a unified vulnerability report.")

def destroy():
    print("\n")
    print("[CloudSentinel] Destroying AWS infrastructure...")

    subprocess.run(["terraform", "destroy", "-auto-approve"], cwd="terraform/aws")
    print("You have torn down all deployed cloud infrastructure.")


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
    else:
        print(f"Unknown command: {command}")
        print("Valid commands: deploy | scan | report | destroy")


if __name__ == "__main__":
    main()

