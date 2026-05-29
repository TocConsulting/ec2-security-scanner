<p align="center">
  <img src="https://raw.githubusercontent.com/TocConsulting/ec2-security-scanner/main/assets/logo.png" alt="EC2 Security Scanner" style="max-width: 100%; height: auto;">
</p>

<p align="center">
  <a href="https://pypi.org/project/ec2-security-scanner/"><img src="https://img.shields.io/pypi/v/ec2-security-scanner.svg" alt="PyPI version"></a>
  <a href="https://pepy.tech/project/ec2-security-scanner"><img src="https://static.pepy.tech/badge/ec2-security-scanner" alt="Downloads"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/ec2-security-scanner"><img src="https://img.shields.io/docker/v/tarekcheikh/ec2-security-scanner?label=docker&logo=docker" alt="Docker"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/ec2-security-scanner"><img src="https://img.shields.io/docker/pulls/tarekcheikh/ec2-security-scanner" alt="Docker Pulls"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
  <a href="https://aws.amazon.com/ec2/"><img src="https://img.shields.io/badge/AWS-EC2-orange.svg" alt="AWS"></a>
</p>

A comprehensive, production-ready AWS EC2 security scanner with 46 security checks across 8 categories and compliance mapping for AWS FSBP, CIS, PCI DSS, HIPAA, SOC 2, ISO 27001/27017/27018, GDPR, and NIST SP 800-53 Rev5 (137 controls total). Features multi-threaded scanning, UserData secret detection, and interactive HTML dashboards.

## Key Features

### **Comprehensive Security Analysis**
- **Instance Security**: IMDSv2 enforcement, public IP detection, IAM profile validation, UserData secret scanning
- **Network Security**: Security group analysis (SSH, RDP, high-risk ports, egress, authorized ports), VPC flow logs, NACLs, VPN IKEv2 enforcement
- **Storage Security**: EBS encryption (per-volume and account default), public snapshots, public AMIs, backup coverage, EBS snapshot Block Public Access
- **Access Control**: IAM role least-privilege analysis, key pair usage, serial console status, EC2 Instance Connect endpoints
- **Logging & Monitoring**: CloudTrail, CloudWatch alarms, SSM-managed status, GuardDuty runtime monitoring
- **Patch & Vulnerability**: SSM patch compliance, AMI age, Amazon Inspector v2 findings
- **Network Exposure**: Unused EIPs, launch template public IPs, subnet auto-assign, VPC Block Public Access, Transit Gateway auto-accept
- **Tagging & Inventory**: Required tags, long-stopped instances, unused security groups

### **Compliance Frameworks**
- **AWS Foundational Security Best Practices (FSBP)**: 32 controls (29 official `EC2.x` controls + 3 custom `BP.*` best-practice controls for UserData secrets, egress, and public AMIs)
- **CIS AWS Foundations Benchmark v5.0**: 7 EC2-applicable controls
- **PCI DSS v4.0.1**: 12 controls
- **HIPAA Security Rule**: 10 controls
- **SOC 2**: 13 controls (Trust Services Criteria)
- **ISO 27001:2022**: 17 controls
- **ISO 27017:2015**: 7 cloud security controls
- **ISO 27018:2019**: 4 PII protection controls
- **GDPR (EU) 2016/679**: 8 controls (Articles 5, 25, 32, 33, 44-49)
- **NIST SP 800-53 Rev5**: 27 controls
- **Scan-level Compliance Scoring**: Automated per-framework compliance percentage where account/region-wide controls (GuardDuty, CloudTrail, VPC BPA, ...) are counted **once**, not duplicated across every instance

### **Performance & Usability**
- **Multi-threaded Scanning**: Parallel instance analysis with ThreadPoolExecutor
- **Three-tier Scanning**: Account → VPC → instance to avoid redundant API calls
- **Rich Console Output**: Progress bars, colored output, and formatted tables
- **Multiple Report Formats**: JSON, CSV, HTML, and compliance-specific reports
- **Beautiful HTML Reports**: Interactive dashboard with Chart.js visualizations
- **Flexible Targeting**: Scan all instances, specific IDs, or filter by tags and state

### **Production Ready**
- **Modular Architecture**: Facade pattern with 8 dedicated checker modules
- **Thread-safe Sessions**: Thread-local boto3 session management
- **Graceful Degradation**: Permission errors (`AccessDenied`, `UnauthorizedOperation`, `AuthFailure`, ...) are surfaced as ERROR-severity findings without crashing the scan
- **Two-tier Scoring**: Per-instance score for instance posture + a separate environment score for account/VPC posture (counted once, never multiplied across instances)
- **Non-stacking Scoring**: Overlapping security-group ingress-exposure penalties (SSH/RDP/high-risk/remote-admin/unauthorized ports) use the highest only
- **Strictly Read-Only**: No AWS API call mutates state — safe to run against production

## Quick Start

### Installation

```bash
# Install from PyPI
pip install ec2-security-scanner

# Or install from source
git clone https://github.com/TocConsulting/ec2-security-scanner.git
cd ec2-security-scanner
pip install .
```

### Docker Installation

```bash
# Pull from Docker Hub
docker pull tarekcheikh/ec2-security-scanner:latest
```

### Basic Usage

```bash
# Scan all running EC2 instances in the default region
ec2-security-scanner security

# Scan with a specific AWS profile
ec2-security-scanner security --profile production

# Scan specific instances only
ec2-security-scanner security -i i-0abc123def456 -i i-0def789abc012

# Include stopped instances
ec2-security-scanner security --state-filter all

# Filter by tags
ec2-security-scanner security --tag-filter Environment=production --tag-filter Team=platform

# Compliance-only report
ec2-security-scanner security --compliance-only
```

## Commands

### Security Command

Scan EC2 instances for security vulnerabilities and compliance issues.

```bash
ec2-security-scanner security [OPTIONS]

Options:
  -i, --instance-id TEXT         Specific instance ID(s) to scan (multiple)
  --exclude-instance TEXT        Instance ID(s) to exclude
  --compliance-only              Print detailed per-framework failed controls
  --tag-filter TEXT              Filter by tag (Key=Value, multiple)
  --state-filter TEXT            Instance state: running, stopped, all (default: running)
  -r, --region TEXT              AWS region (default: us-east-1)
  -p, --profile TEXT             AWS profile name
  -o, --output-dir TEXT          Output directory (default: ./output)
  -f, --output-format TEXT       Report format: json, csv, html, all (default: all)
  -w, --max-workers INTEGER      Worker threads (default: 5)
  -q, --quiet                    Suppress console output except errors
  -d, --debug                    Enable debug logging
  -h, --help                     Show help

# Top-level options:
#   ec2-security-scanner --version
#   ec2-security-scanner --help
```

**Examples:**
```bash
# Scan all running instances with default settings
ec2-security-scanner security

# Exclude specific instances
ec2-security-scanner security --exclude-instance i-0abc123 --exclude-instance i-0def456

# Fast compliance-only scan with HTML output
ec2-security-scanner security --compliance-only -f html -p production

# High-performance scan with more threads
ec2-security-scanner security -w 20 -r eu-west-1

# JSON report only, quiet mode (for CI/CD)
ec2-security-scanner security -f json -q
```

## Docker Usage

Run the scanner using Docker without installing Python dependencies locally.

### Pull the Docker Image

```bash
# Pull the latest version
docker pull tarekcheikh/ec2-security-scanner:latest

# Or pull a specific version
docker pull tarekcheikh/ec2-security-scanner:1.0.0
```

### Basic Docker Commands

```bash
# Show help
docker run --rm tarekcheikh/ec2-security-scanner --help

# Show help for the security command
docker run --rm tarekcheikh/ec2-security-scanner security --help
```

### Security Scanning with Docker

**AWS Credentials:** The examples below mount `~/.aws` to provide credentials. By default the scanner uses the `default` profile. Use `--profile <name>` to specify a different profile.

```bash
# Scan all instances using the default AWS profile
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security

# Scan using a specific AWS profile
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security --profile production

# Scan specific instances only
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security -i i-0abc123def456

# Compliance-only scan
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security --compliance-only
```

### Using Environment Variables for AWS Credentials

Instead of mounting `~/.aws`, you can pass credentials via environment variables:

```bash
# Pass AWS credentials via environment variables
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security

# With session token (temporary credentials / assumed roles)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  tarekcheikh/ec2-security-scanner security
```

### Docker Volume Mounts Explained

| Mount | Purpose |
|-------|---------|
| `-v ~/.aws:/root/.aws:ro` | Mount AWS credentials (read-only). Uses `default` profile unless `--profile` is specified |
| `-v $(pwd)/output:/app/output` | Save reports to your local `./output` directory |

**Important:** Without the output volume mount, report files will not be accessible after the container exits.

## Prerequisites

### Python Requirements
- Python 3.10 or higher
- Required packages (installed automatically):
  - `boto3>=1.34.0`
  - `botocore>=1.34.0`
  - `rich>=13.0.0`
  - `click>=8.1.0`
  - `jinja2>=3.1.0`

### AWS Requirements
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeSubnets",
                "ec2:DescribeAddresses",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeLaunchTemplateVersions",
                "ec2:DescribeImages",
                "ec2:DescribeInstanceConnectEndpoints",
                "ec2:DescribeTransitGateways",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeVpcBlockPublicAccessOptions",
                "ec2:DescribeVpnConnections",
                "ec2:GetEbsEncryptionByDefault",
                "ec2:GetSerialConsoleAccessStatus",
                "ec2:GetSnapshotBlockPublicAccessState",
                "iam:GetInstanceProfile",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "ssm:DescribeInstanceInformation",
                "ssm:DescribeInstancePatchStates",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "cloudwatch:DescribeAlarms",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "inspector2:BatchGetAccountStatus",
                "inspector2:ListCoverage",
                "inspector2:ListFindings",
                "backup:ListProtectedResources",
                "backup:DescribeProtectedResource",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Security Checks

### 46 Checks Across 8 Categories

| # | Category | Checks | Focus |
|---|----------|--------|-------|
| A | Instance Security | 8 | IMDSv2 (instance + launch template), public IP, IAM profile, virtualization, ENIs, detailed monitoring, UserData secrets |
| - | Launch Templates | 1 | Region-level audit of all launch templates: IMDSv2, public IP, EBS encryption |
| B | Network Security | 11 | SG SSH/RDP/high-risk/remote-admin/egress/authorized ports, source-dest check, default SG, VPC flow logs, NACL admin ports, VPN IKEv2 |
| C | Storage Security | 7 | EBS encryption (per-volume + default + launch template), public snapshots, public AMI, backup coverage, EBS Snapshot BPA |
| D | Access Control | 4 | IAM roles (admin + wildcard + `NotAction`/`NotResource`), key pairs, serial console, Instance Connect |
| E | Logging & Monitoring | 4 | CloudTrail, CloudWatch alarms, SSM-managed, GuardDuty EC2 runtime monitoring |
| F | Patch & Vulnerability | 3 | SSM patch compliance, AMI age, Inspector v2 findings |
| G | Network Exposure | 5 | Unused EIPs, launch template public IP, subnet auto-assign, VPC BPA, Transit Gateway auto-accept |
| H | Tagging & Inventory | 3 | Required tags, stopped instances, unused security groups |

### Secret Detection in UserData (A.8)

The scanner decodes and scans EC2 UserData for exposed secrets:

| Pattern | Examples |
|---------|----------|
| AWS Access Keys | `AKIA...`, `ASIA...` |
| AWS Secret Keys | `aws_secret_access_key=...` |
| Passwords | `PASSWORD=`, `DB_PASSWORD=`, `MYSQL_ROOT_PASSWORD=`, `POSTGRES_PASSWORD=`, `REDIS_PASSWORD=` |
| Private Keys | `-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----` |
| API Tokens | `api_key=`, `api_token=`, `AUTH_TOKEN=` |
| Generic Secrets | `SECRET_KEY`, `JWT_SECRET`, `ENCRYPTION_KEY`, `SIGNING_KEY`, Django/Flask secret keys |
| Connection Strings | `postgres://`, `mongodb://`, `mysql://`, `redis://`, `amqp://`, `mssql://` with embedded credentials |
| GitHub / GitLab | `ghp_…`, `github_pat_…`, `glpat-…` |
| OpenAI | Legacy (`sk-…`), project (`sk-proj-…`), service-account (`sk-svcacct-…`) |
| Anthropic | `sk-ant-…` |
| Stripe | `sk_live_…`, `sk_test_…` |
| SendGrid, Slack, Vault | `SG.…`, `xoxb-…`, `hvs.…` |
| Azure, Docker, npm | `AZURE_CLIENT_SECRET=`, `DOCKER_PASSWORD=`, `npm_…` |
| Inline auth | `Authorization: Bearer …`, `sshpass -p …` |

### Detailed Security Analysis

For per-check documentation including attack vectors, exploitation scenarios, boto3 calls, and remediation, see **[security-checks.md](security-checks.md)**.

### Compliance Coverage

For the full mapping of each scanner check to AWS FSBP, CIS, PCI DSS, HIPAA, SOC 2, ISO 27001/27017/27018, GDPR, and NIST 800-53 controls, see **[compliance.md](compliance.md)**.

### Security Remediation Guide

For step-by-step remediation instructions (AWS Console, AWS CLI, boto3 code) for every vulnerability the scanner detects, see **[remediation-guide.md](remediation-guide.md)**.

## Modular Architecture

```
ec2_security_scanner/
├── scanner.py                  # Main scanner orchestration (facade pattern)
├── cli.py                      # Click CLI interface
├── compliance.py               # 137 controls across 10 frameworks
├── html_reporter.py            # Jinja2 HTML report generation
├── utils.py                    # Logging, scoring, formatting
├── checks/
│   ├── base.py                 # BaseChecker (session factory, error handling)
│   ├── instance_security.py    # A.1-A.8: IMDSv2, public IP, secrets
│   ├── network_security.py     # B.1-B.11: SG rules, flow logs, NACLs, VPN
│   ├── storage_security.py     # C.1-C.7: EBS, snapshots, AMIs, snapshot BPA
│   ├── access_control.py       # D.1-D.4: IAM, key pairs, serial console
│   ├── logging_monitoring.py   # E.1-E.4: CloudTrail, CloudWatch, SSM, GuardDuty
│   ├── patch_vulnerability.py  # F.1-F.3: SSM patches, AMI age, Inspector v2
│   ├── network_exposure.py     # G.1-G.5: EIPs, public IP, VPC BPA, TGW
│   └── tagging_inventory.py    # H.1-H.3: Tags, stopped instances, unused SGs
└── templates/
    └── report.html             # Interactive HTML dashboard
```

### Key Benefits
- **Maintainability**: Each security domain has its own dedicated module
- **Testability**: Isolated components enable comprehensive unit testing
- **Scalability**: Easy to add new security checks without affecting existing code
- **Single Responsibility**: Each module focuses on one specific security area
- **Three-tier scanning**: Account-level and VPC-level checks run once per scan instead of per instance

## Security Scoring

The scanner reports **two independent scores** so that account/region-wide
posture is not multiplied across every instance:

- **Instance Score** — per-instance, reflects only what is controllable on
  that instance and its own resources (IMDSv2, public IP, its security
  groups, its EBS volumes, IAM role, UserData, patches, ...). The headline
  **"Avg Instance Score"** is the mean of these.
- **Environment Score** — account- and VPC-wide posture (GuardDuty,
  CloudTrail, VPC Block Public Access, EBS Snapshot BPA, default SG, VPC
  flow logs, ...). Scored **once per scan**, not per instance, so a single
  account-level gap doesn't drag down every instance's score.

### Instance Score Deductions

Each instance starts at **100 points** and loses points for instance-specific issues:

| Security Issue | Points Deducted | Severity |
|----------------|-----------------|----------|
| UserData secrets exposed | -25 | CRITICAL |
| Public EBS snapshots (of this instance's volumes) | -20 | CRITICAL |
| High-risk ports open (non-stacking) | -20 | CRITICAL |
| SSH open to world (non-stacking) | -15 | HIGH |
| RDP open to world (non-stacking) | -15 | HIGH |
| Remote admin ports open (non-stacking) | -15 | HIGH |
| Unauthorized ports open to world (non-stacking) | -10 | HIGH |
| IMDSv2 not enforced | -15 | HIGH |
| Public IP assigned | -15 | HIGH |
| IAM admin / wildcard access | -15 | HIGH |
| Launch template IMDSv2 not enforced | -10 | HIGH |
| Launch template assigns public IP | -10 | HIGH |
| Inspector disabled or critical/high findings | -8 | HIGH |
| EBS volumes unencrypted | -10 | MEDIUM |
| SSM patch non-compliant | -10 | MEDIUM |
| No IAM instance profile | -8 | MEDIUM |
| Launch template EBS unencrypted | -5 | MEDIUM |
| Source/dest check disabled | -5 | MEDIUM |
| Not SSM managed | -5 | MEDIUM |
| Subnet auto-assigns public IP | -5 | MEDIUM |
| No CloudWatch alarms | -5 | MEDIUM |
| Stale AMI (>180 days) | -5 | MEDIUM |
| Detailed monitoring disabled | -5 | MEDIUM |
| Paravirtual (not HVM) | -5 | MEDIUM |
| Key pair without SSM management | -5 | MEDIUM |
| Multiple ENIs | -3 | LOW |
| No EBS backup plan | -3 | LOW |
| Unrestricted egress (opinionated — AWS default, not FSBP-required) | -2 | LOW |
| Missing required tags | -2 | LOW |
| Stopped instance exceeds threshold | -2 | LOW |
| IMDSv2 hop limit > 2 | -2 | LOW |

### Environment Score Deductions

The account/VPC posture starts at **100 points**. VPC-level findings are
counted **once** even when several VPCs are affected:

| Finding | Points Deducted | Severity | Scope |
|---------|-----------------|----------|-------|
| Public AMI sharing | -20 | CRITICAL | account |
| Default SG has rules | -10 | HIGH | per-VPC |
| EBS Snapshot BPA not enabled | -10 | HIGH | account |
| Transit Gateway auto-accept | -10 | HIGH | account |
| No GuardDuty | -10 | HIGH | account |
| No VPC Block Public Access | -10 | HIGH | account |
| No CloudTrail | -10 | HIGH | account |
| VPN not IKEv2-only | -10 | HIGH | account |
| No VPC flow logs | -10 | MEDIUM | per-VPC |
| EBS default encryption disabled | -5 | MEDIUM | account |
| Serial console access enabled | -5 | MEDIUM | account |
| NACL allows admin port access | -5 | MEDIUM | per-VPC |
| Unused security groups | -2 | MEDIUM | account |
| Unused Elastic IPs | -2 | LOW | account |
| No Instance Connect endpoint | -1 | LOW | per-VPC |

### Non-stacking Security Group Penalties

All security-group **ingress exposure** checks (SSH, RDP, high-risk ports,
remote-admin ports, and unauthorized ports open to the world) describe the
same underlying "ports open to 0.0.0.0/0" misconfiguration, so only the
**highest single penalty** is applied — never the sum:

- High-risk ports open = -20, SSH open = -15 → **only -20 applied**
- SSH + RDP both open → **only -15 applied** (not -30)
- SSH open (port 22) trips both the SSH penalty and the "unauthorized port" check → **only -15/-20 applied**, not -25/-30

**Formula**: `Score = max(0, 100 - total_deductions)`

### Score Interpretation

| Score Range | Security Level | Recommendation |
|-------------|----------------|----------------|
| **90-100** | Excellent | Maintain current security posture |
| **70-89**  | Good | Address minor gaps |
| **50-69**  | Needs Improvement | Fix medium-priority issues |
| **0-49**   | Poor | Immediate action required — critical issues present |

### Key Properties

- **No account-level multiplication**: account/VPC findings are scored once (Environment Score), so the per-instance average reflects instance posture
- **Error-Safe**: Checks that fail with a permission error (`AccessDenied`, `UnauthorizedOperation`, ...) are surfaced as ERROR-severity findings and excluded from the score (instead of silently passing)
- **Weighted Fairly**: Each valid instance contributes equally to the average instance score
- **Priority-Based**: Public exposure and secret leakage are penalized most heavily
- **Actionable**: Scores directly correlate with security risk level

## Sample Output

### Console Summary
```
                EC2 Security Scan Summary - us-east-1
┌──────────────────────────────┬─────────────────┐
│ Metric                       │ Value           │
├──────────────────────────────┼─────────────────┤
│ Account                      │ 123456789012    │
│ Total Instances              │ 12              │
│ Running                      │ 10              │
│ Stopped                      │ 2               │
│ Public IP                    │ 4               │
│ With Secrets in UserData     │ 1               │
│ Unencrypted Volumes          │ 3               │
│ Critical Issues              │ 2               │
│ High Issues                  │ 7               │
│ Avg Instance Score           │ 82.6/100        │
│ Environment Score            │ 60/100          │
└──────────────────────────────┴─────────────────┘

                Environment Posture (account + VPC, counted once)
┌──────────┬──────────────────────────────┬─────────────────────────────────┐
│ Severity │ Finding                      │ Description                     │
├──────────┼──────────────────────────────┼─────────────────────────────────┤
│ HIGH     │ NO_GUARDDUTY                 │ GuardDuty not enabled for EC2   │
│ HIGH     │ NO_CLOUDTRAIL                │ No active CloudTrail trail      │
│ HIGH     │ VPC_BPA_NOT_ENABLED          │ VPC Block Public Access off     │
│ MEDIUM   │ NO_VPC_FLOW_LOGS             │ Flow logs disabled in: vpc-abc  │
└──────────┴──────────────────────────────┴─────────────────────────────────┘
```

### Compliance Summary

Compliance is evaluated **at scan level**: each framework control is counted
once. Account/region-wide controls (GuardDuty, CloudTrail, VPC BPA, ...) are
evaluated a single time; instance-level controls (IMDSv2, SSH exposure, ...)
fail once and list the affected instances. A missing-GuardDuty account is one
failed control per region — not one per instance — so the percentage does not
change with fleet size.

```
        Compliance Framework Summary (scan level — account controls counted once)
┌──────────────┬────────┬──────────┬────────┬─────────────────┐
│ Framework    │ Passed │ Controls │  Rate  │     Status      │
├──────────────┼────────┼──────────┼────────┼─────────────────┤
│ AWS-FSBP     │   27   │    32    │ 84.4%  │      Good       │
│ CIS-v5.0     │    5   │     7    │ 71.4%  │   Needs Work    │
│ PCI-DSS-v4.0 │    9   │    12    │ 75.0%  │      Good       │
│ HIPAA        │    7   │    10    │ 70.0%  │   Needs Work    │
│ SOC2         │   11   │    13    │ 84.6%  │      Good       │
│ ISO27001     │   14   │    17    │ 82.4%  │      Good       │
│ NIST-800-53  │   23   │    27    │ 85.2%  │      Good       │
└──────────────┴────────┴──────────┴────────┴─────────────────┘
```

## Output Files

The scanner generates reports in the specified output directory.

### JSON Report (`ec2_scan_region_timestamp.json`)
```json
{
  "summary": {
    "scan_time": "2026-05-15T10:30:45.123456",
    "region": "us-east-1",
    "account_id": "123456789012",
    "total_instances": 12,
    "running_instances": 10,
    "public_instances": 4,
    "average_security_score": 82.6,
    "environment_security_score": 60,
    "environment_findings": [
      {"severity": "HIGH", "issue_type": "NO_GUARDDUTY", "description": "...", "recommendation": "..."}
    ]
  },
  "results": [...]
}
```

### CSV Report (`ec2_scan_region_timestamp.csv`)
Spreadsheet-friendly format with all key metrics per instance and compliance status.

### HTML Report (`ec2_scan_region_timestamp.html`)
Beautiful, interactive dashboard with:
- **Executive Summary**: Key metrics and risk indicators
- **Score Distribution**: Bar chart of instance security scores
- **Compliance Overview**: Bar chart across all 10 frameworks
- **Severity Breakdown**: Doughnut chart of findings by severity
- **Instance Details**: Sortable table with score bars
- **Critical Findings**: Table of high/critical severity issues

### Compliance Report (`ec2_compliance_region_timestamp.json`)
Per-instance compliance evaluation across all 10 frameworks with passed/failed control details.

### Log File (`ec2_scan_timestamp.log`)
Comprehensive execution log with debug information and error details.

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/TocConsulting/ec2-security-scanner.git
cd ec2-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full contributor guide.

## Testing

### Running Tests

The project includes comprehensive unit tests using Python's `unittest` framework and `moto` for AWS service mocking.

```bash
# Install development dependencies including moto
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_compliance.py -v

# Run with coverage
python -m pytest tests/ --cov=ec2_security_scanner --cov-report=html
```

### Test Structure

```
tests/
├── __init__.py
├── test_cli.py                 # CLI option and command tests
├── test_compliance.py          # 137 controls / 10 frameworks validation
├── test_scoring.py             # Non-stacking scoring logic
├── test_instance_security.py   # A.1-A.8 checks (IMDSv2, secrets)
├── test_network_security.py    # B.x checks (SG rules)
├── test_storage_security.py    # C.x checks (EBS, AMI)
└── test_utils.py               # Logging, formatting utilities
```

The tests use `unittest.mock` and `moto` to mock AWS services, allowing comprehensive testing without requiring actual AWS resources or incurring costs.

## Support & Contributing

### Getting Help
- **Documentation**: Check this README and inline help (`--help`)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/TocConsulting/ec2-security-scanner/issues)
- **Discussions**: Join conversations in [GitHub Discussions](https://github.com/TocConsulting/ec2-security-scanner/discussions)

### Contributing
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Development setup

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Security Best Practices**: Based on official AWS security recommendations
- **CIS Benchmarks**: Implements CIS AWS Foundations Benchmark v5.0 controls
- **[s3-security-scanner](https://github.com/TocConsulting/s3-security-scanner)**: Architecture and design patterns

---

**Security Notice**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning AWS resources. The scanner requires read-only permissions and does not modify any AWS resources.

**Performance Note**: The scanner uses three-tier scanning (account → VPC → instance) to minimize redundant API calls. Security group rules are fetched once per instance and reused across 6 checks. Use `-w` to adjust parallelism.
