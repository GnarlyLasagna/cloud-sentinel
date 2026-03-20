
# scanner/engine.py

from scanner.checks import open_ssh, open_ports

def run_aws_checks():
    findings = []

    checks = [
    open_ssh.run,
    open_ports.run,
]

    for check in checks:
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[ERROR] Check failed: {check.__name__} → {e}")

    return findings
