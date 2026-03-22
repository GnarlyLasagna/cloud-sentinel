
# scanner/engine.py

from scanner.checks import (
    open_ssh,
    open_ports,
    public_s3,
    iam_roles,
    cloudtrail,
    ebs_encryption
)


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
            print(f"[ERROR] {check.__name__} failed: {e}")

    return findings
