# 🌩️ CloudSentinel

A multi-cloud vulnerability deployment and security assessment framework.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
  - [Multi-Cloud Support](#multi-cloud-support)
  - [Infrastructure as Code](#infrastructure-as-code)
  - [Security Scanning Engine](#security-scanning-engine)
  - [Risk Scoring System](#risk-scoring-system)
  - [Reporting](#reporting)
  - [Environment Cleanup](#environment-cleanup)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Install Dependencies](#2-install-dependencies)
  - [3. Authenticate Cloud Providers](#3-authenticate-cloud-providers)
- [Usage](#usage)
  - [Deploy Infrastructure](#deploy-infrastructure)
  - [Run Security Scan](#run-security-scan)
  - [Generate Report](#generate-report)
  - [Destroy Infrastructure](#destroy-infrastructure)
  - [Verify Cleanup](#verify-cleanup)
  - [Example Output](#example-output)
  - [Security Checks Implemented](#security-checks-implemented)
- [Disclaimer](#disclaimer)
- [Purpose](#purpose)
- [Future Improvements](#future-improvements)
- [Author](#author)
- [Why This Project Matters](#why-this-project-matters)
- [Design Documentation](#design-documentation)
- [License](#license)

## Overview

CloudSentinel is a multi-cloud security scanning platform that:

- Deploys intentionally vulnerable infrastructure across **AWS, Azure, and GCP**
- Scans for cloud misconfigurations
- Generates structured security reports
- Cleans up environments automatically

It simulates real-world cloud security issues and demonstrates workflows used by:

- SOC Analysts  
- Cloud Security Engineers  
- DevSecOps Engineers  

---

## Features

### Multi-Cloud Support
- AWS  
- Azure  
- Google Cloud Platform (GCP)

### Infrastructure as Code
- Terraform-based deployments  
- Reproducible vulnerable environments  

### Security Scanning Engine
Detects common cloud misconfigurations:
- Open SSH (0.0.0.0/0)
- Public storage buckets
- Weak IAM configurations
- Missing encryption
- Logging misconfigurations

### Risk Scoring System
- Severity classification: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Weighted risk score (0–10)

### Reporting
- JSON output (scan results)
- CSV export (reporting)

### Environment Cleanup
- Full teardown via Terraform
- Post-destroy validation (`status` command)

---

## Architecture Overview
```
cloudsentinel/
│
├── cli/
│ └── cloudsentinel.py # Main CLI interface
│
├── scanner/
│ ├── engine.py # Core scanning engine
│ ├── aws_checks/ # AWS security checks
│ ├── azure_checks/ # Azure security checks
│ └── gcp_checks/ # GCP security checks
│
├── terraform/
│ ├── aws/ # AWS vulnerable infrastructure
│ ├── azure/ # Azure vulnerable infrastructure
│ └── gcp/ # GCP vulnerable infrastructure
│
├── reports/ # Scan results + reports
│
├── docs/
│ └── design.md # Project design document
│
└── README.md
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/cloudsentinel.git
cd cloudsentinel
```

### 2. Install Dependencies

Ensure you have:

- Python 3.9+
- Terraform
- AWS CLI
- Azure CLI (az)
- Google Cloud CLI (gcloud)

### 3. Authenticate Cloud Providers
AWS
``` bash
aws configure
```
Azure
``` bash
az login
```
GCP
``` bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

### Usage

All functionality is exposed through the CLI:
``` bash
./cli/cloudsentinel.py <command>
```
### Deploy Infrastructure
``` bash
cloudsentinel deploy
```
Deploys vulnerable resources across:
- AWS
- Azure
- GCP

### Run Security Scan
``` bash
cloudsentinel scan
```
- Runs all cloud checks
- Outputs findings to terminal
- Saves results to:
```
reports/scan_<timestamp>.json
```

### Generate Report
``` bash
cloudsentinel report
```
- Reads latest scan file
- Outputs:
  - Summary
  - CSV report
```
reports/report_<timestamp>.csv
```

### Destroy Infrastructure
``` bash
cloudsentinel destroy
```
Removes all deployed cloud resources

### Verify Cleanup
``` bash
cloudsentinel status
```
- Ensures no CloudSentinel resources remain
- Detects leftover infrastructure across all providers
Example Output
``` bash
[CloudSentinel] Running security scan...

Found 4 vulnerabilities:

[AWS] Open SSH port (HIGH)
[AWS] Public S3 bucket (CRITICAL)
[AZURE] NSG allows SSH from Internet (HIGH)
[GCP] Public storage bucket (CRITICAL)

--- Security Summary ---
CRITICAL: 2
HIGH:     2
MEDIUM:   0
LOW:      0

Risk Score (0-10): 8.5
Overall Risk Level: HIGH
```

### Security Checks Implemented

AWS
- Open SSH access
- Open ports
- Public S3 buckets
- IAM role issues
- CloudTrail disabled
- Unencrypted EBS volumes
Azure
- NSG open to internet (SSH)
- Public storage accounts
GCP
- Open SSH firewall rules
- Public storage buckets
- Over-permissive IAM roles

### Disclaimer

This project intentionally deploys insecure configurations for educational and testing purposes.

Do NOT use in production environments.

### Purpose

CloudSentinel was built to demonstrate:

- Multi-cloud security fundamentals
- Infrastructure automation with Terraform
- Security scanning logic development
- CLI tool design
- Real-world misconfiguration detection

### Future Improvements

- Add more GCP security checks
- Integrate with SIEM tools (e.g., Splunk)
- Add dashboard / web UI
- CI/CD pipeline for automated scans
- Export to JSON → SIEM ingestion format

### Author

Evan Dolatowski

- IT Operations Specialist (CIOS)
- Pursuing Security+ and SOC Analyst roles
- Focused on cloud security and automation

### Why This Project Matters

CloudSentinel demonstrates the ability to:

- Work across AWS, Azure, and GCP
- Build real-world security tooling
- Automate infrastructure deployment and teardown
- Detect and report security risks programmatically

This is directly applicable to roles such as:

- SOC Analyst
- Cloud Security Engineer
- DevSecOps Engineer

### Design Documentation

For a deeper look into the architecture and planning behind CloudSentinel, see:
[Project Design Document](cloudSentinelDesign.md)

License

MIT License





