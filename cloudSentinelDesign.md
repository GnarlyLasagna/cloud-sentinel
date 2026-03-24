
# Capstone Project Outline: Multi-Cloud Vulnerable VM Deployment and Security Assessment Framework
## Project Goal:
Design and implement a self-contained, reproducible framework to deploy multiple virtual machines 
in AWS, Azure, and GCP, each with detectable security vulnerabilities, and scan them for high-value misconfigurations. 
The project demonstrates multi-cloud deployment, cloud security awareness, automation, and extensibility.

## Phase 1 – Planning & Architecture

### Objectives:
Define project scope and limitations
Identify cloud providers and resources to use
Define the “core vulnerability set” for each VM
Design system architecture and deployment flow

### Key Features / Decisions:
Terraform as deployment tool for all clouds
Separate VMs (independent) for simplicity
Cloud-init / startup scripts to configure vulnerabilities
Unified command interface: deploy and destroy for all providers
Security checks focus on core domains:
    IAM / access controls
    Storage exposure / encryption
    Network / public access
    Logging / monitoring
    OS-level minimal detectable misconfigurations

### Milestones:
Diagram architecture (local + AWS + Azure + GCP)
List VM types and vulnerabilities per provider
Define Terraform modules and cloud-init scripts
Document commands for deployment & teardown

## Cloud Authentication
The scanner will authenticate to each provider using standard SDK credential mechanisms.
```
AWS
- Access Key and Secret Key via environment variables or shared credentials file.

Azure
- Service Principal authentication.

GCP
- Service account JSON key file.

Credentials will not be stored in the repository and will be provided through environment variables or local configuration.
```

## Phase 2 – Deployment Module Implementation

### Objectives:
Implement Terraform modules for AWS, Azure, and GCP
Configure VMs with vulnerabilities using startup scripts
Ensure reproducible local deployment if desired

### Key Features:
One VM per provider with basic misconfiguration (proof of concept)
Command triggers:
    terraform apply (deploy)
    terraform destroy (teardown)
Optional: single “gateway VM” to demonstrate basic networking awareness (not mandatory)

### Milestones:
Deploy first VM successfully on AWS
Deploy on Azure and GCP using same module pattern
Validate vulnerabilities exist as intended
Verify Terraform destroy works cleanly

## Phase 3 – Vulnerability Scanning Module

### Objectives:
Build a scan module to detect key vulnerabilities across providers
Focus on high-impact security domains, not exhaustive coverage
Ensure modular, expandable design

### Key Features:
Python-based scanner with provider modules: scan_aws(), scan_azure(), scan_gcp()
Detect:
    Public storage                         --missing encryption
    Over-permissive IAM roles               --roles, public access, wildcard permissions
    Open network rules                     --Open ports to 0.0.0.0/0, public IPs on internal VMs
    Logging / encryption misconfigurations  --Audit logs enabled/disabled Data-at-rest encryption enabled
    Optional OS-level misconfigurations    --Default passwords, vulnerable service versions (small, detectable)
Unified output:
    JSON / CSV report
    Risk scoring / severity classification
    Cross-cloud comparison summary

### Optional Impressive Expansions
Comparison mode – output risk scores in a table showing which cloud has “more secure defaults”
Automated cleanup verification – verify VMs/resources are fully deleted
Small web dashboard – even a local Flask dashboard showing deployed VMs and scan results
CI/CD simulation – demonstrate one-click run of deployment + scan from a single script (GitHub Actions, optional)

### Milestones:
Scanner detects vulnerabilities in AWS deployment
Extend scanner to Azure and GCP
Produce unified report
Document logic and scoring methodology

## Intentional Vulnerabilities
Each cloud deployment will include predefined misconfigurations
designed to be detected by the scanner.

### AWS VM Vulnerabilities
- Security group allows SSH (22) from 0.0.0.0/0
- S3 bucket publicly readable
- CloudTrail disabled
- IAM role with "*" permissions
- EBS volume unencrypted
### Azure VM Vulnerabilities
- NSG allows SSH from internet
- Storage account public access enabled
- Logging disabled
- Managed identity with excessive permissions
### GCP VM Vulnerabilities
- Firewall rule allows SSH from 0.0.0.0/0
- Cloud Storage bucket public
- Audit logging disabled
- Service account overly permissive

MVP: ~5–6 checks per cloud
Impressive / portfolio-ready: ~12–15 checks per cloud
Professional-level scanner: 30+ checks per cloud

## Phase 4 – Testing, Evaluation, and Expansion Readiness

### Objectives:
Verify robustness and reproducibility
Demonstrate extensibility for future expansion
Evaluate security findings and provide analysis

### Key Features:
Run full deployment + scan workflow
Compare vulnerability risk scores across providers
Validate reports for accuracy
Optional: small evaluation study (e.g., “AWS defaults vs Azure defaults for IAM”)

### Milestones:
Complete end-to-end deployment + scan cycle
Produce sample cross-cloud report
Document evaluation methodology
Optional: design one expansion idea (extra VM, additional check, or container support)

## Unified Vulnerability Report Format
All scanner modules will return findings using a shared structure to allow
cross-cloud aggregation and comparison.

Example JSON finding:
```
{
  "provider": "aws",
  "resource_type": "security_group",
  "resource_id": "sg-12345",
  "issue": "SSH open to internet",
  "severity": "HIGH",
  "description": "Port 22 is accessible from 0.0.0.0/0"
}
```
Reports will be aggregated into:

- JSON detailed findings
- CSV summary
- Cross-cloud risk comparison table

## Phase 5 – Documentation & Presentation

### Objectives:
Produce complete project documentation
Prepare capstone deliverables: code, diagrams, report, slides

### Key Features:
Architecture diagrams and system flow
Deployment instructions
Vulnerability scan explanation and reporting
Lessons learned and potential extensions
Portfolio-ready documentation

### Milestones:
Complete GitHub repository with README
Create slides summarizing project for presentation
Prepare short demo script showing deployment and scan

## Optional “Polish / High-Impact” Features (Minimal Extra Effort)
Local virtualized deployment using KVM or VirtualBox
Lightweight web dashboard showing VM deployment + scan results
Cross-cloud risk comparison table visualized for clarity
AI-generated Terraform templates as future “vibe code” input for testing
CI/CD workflow demonstrating automated deployment + scan

## Project Success Criteria
Fully automated deployment + teardown across at least AWS and Azure (GCP optional)
Each VM contains at least 1 detectable, meaningful vulnerability
Vulnerability scanner detects the predefined vulnerabilities consistently
Unified risk reporting works and is extensible
Code is modular, documented, and reusable
```
User Commands
(deploy / scan / destroy)
        │
        ▼
Terraform Deployment Layer
(AWS / Azure / GCP Modules)
        │
        ▼
Cloud Infrastructure
VMs + IAM + Networking + Storage
(misconfigurations intentionally created)
        │
        ▼
Python Scanner Engine
        │
 ┌───────────────┬───────────────┬───────────────┐
 ▼               ▼               ▼
AWS Module    Azure Module    GCP Module
(API checks)  (API checks)    (API checks)
        │
        ▼
Security Evaluation Engine
(check rules + scoring)
        │
        ▼
Unified Report
(JSON / CSV / summary table)
```

## Orchestration CLI Interface
To simplify interaction with the framework, a lightweight command-line interface (CLI) will orchestrate the core project workflow.  
This interface will act as a wrapper around Terraform deployment commands and the vulnerability scanning modules, allowing the entire environment lifecycle to be controlled from a single entry point.

The CLI will provide simple commands to deploy infrastructure, run security scans, generate reports, and destroy resources when testing is complete.

### Core Commands
```bash
CloudSentinel deploy
```
Deploys vulnerable infrastructure across the configured cloud providers using Terraform modules.
This includes virtual machines, networking configurations, and intentionally vulnerable settings configured through cloud-init or startup scripts.

```bash
CloudSentinel scan
```
Authenticates to each cloud provider using their APIs and executes the vulnerability scanning modules.
The scanner will gather infrastructure configuration data and evaluate it against predefined security rules.

```bash
CloudSentinel report
```
Generates a unified vulnerability report summarizing findings across AWS, Azure, and GCP.
Reports may be exported as JSON or CSV and include severity ratings and cross-cloud comparisons.

```bash
CloudSentinel destroy
```
Destroys all deployed resources using Terraform to ensure the environment is fully cleaned up and no cloud resources remain active.


Workflow Example
A typical testing workflow for the framework would follow this sequence:
```bash
CloudSentinel deploy
CloudSentinel scan
CloudSentinel report
CloudSentinel destroy
```

## Repository Structure
```
cloudsentinel/
│
├── terraform/
│   ├── aws/
│   ├── azure/
│   └── gcp/
│
├── scanner/
│   ├── aws_scanner.py
│   ├── azure_scanner.py
│   ├── gcp_scanner.py
│   └── engine.py
│
├── cli/
│   └── cloudsentinel.py
│
├── reports/
│
├── docs/
│
└── README.md
```

#### extra ideas
- Risk Scoring

Example:
AWS Risk Score: 7.2
Azure Risk Score: 6.4
GCP Risk Score: 5.8

Instead of raw quantity, add a single cross-cloud feature:
Risk scoring / severity weighting across clouds
Compare cloud “defaults” (e.g., AWS vs Azure vs GCP IAM defaults)
Output a cross-cloud heatmap or table

- Visualization

Even a small dashboard showing:
deployed VMs
vulnerabilities detected
cross-cloud comparison

- CI/CD Demonstration

Use GitHub Actions to run scans automatically.
That shows DevSecOps thinking.
