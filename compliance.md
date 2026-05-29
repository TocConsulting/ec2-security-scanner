# EC2 Security Scanner — Compliance Coverage

This document provides a comprehensive overview of the compliance frameworks and security controls evaluated by the EC2 Security Scanner.

> **Scan-level evaluation.** Each control is counted **once per scan**. Controls are classified as **account-level** (e.g. GuardDuty, CloudTrail, VPC Block Public Access, default SG, EBS Snapshot BPA, VPN IKEv2, public AMIs) — evaluated a single time for the whole account/region — or **instance-level** (e.g. IMDSv2, public IP, SSH exposure, EBS encryption) — evaluated per instance but reported as a single control that fails (listing the affected instances) if any instance fails. This means a missing-GuardDuty account is **one** failed regional control, not one per instance, and a framework's compliance percentage does not change with fleet size.

## Supported Compliance Frameworks

The scanner currently maps EC2 security findings to **10 frameworks / 137 controls**:

| Framework | Version | Controls | Official Documentation |
|-----------|---------|---------:|------------------------|
| **AWS Foundational Security Best Practices (FSBP)** | v1.0.0 | 32 | [AWS FSBP Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html) • [EC2 Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html) |
| **CIS AWS Foundations Benchmark** | v5.0 | 7 | [CIS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services) • [AWS Security Hub CIS](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html) |
| **PCI DSS** | v4.0.1 | 12 | [PCI Security Standards](https://www.pcisecuritystandards.org/document_library/) |
| **HIPAA Security Rule** | 45 CFR Part 164 | 10 | [eCFR §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C) |
| **SOC 2 Type II** | 2017 TSC (2022 Update) | 13 | [AICPA SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) |
| **ISO 27001** | 2022 | 17 | [ISO Official Standard](https://www.iso.org/standard/27001) |
| **ISO 27017** | 2015 | 7 | [ISO Official Standard](https://www.iso.org/standard/43757.html) • [AWS ISO 27017 FAQ](https://aws.amazon.com/compliance/iso-27017-faqs/) |
| **ISO 27018** | 2019 | 4 | [ISO Official Standard](https://www.iso.org/standard/76559.html) |
| **GDPR** | (EU) 2016/679 | 8 | [EUR-Lex Official Text](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) • [GDPR Info](https://gdpr-info.eu/) |
| **NIST SP 800-53** | Rev5 | 27 | [NIST SP 800-53 Rev5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) |

---

## AWS Foundational Security Best Practices (FSBP)

> **Official Documentation:** [FSBP Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html) | [EC2 Controls Reference](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html)

**Coverage: 32 controls — 29 official `EC2.x` controls + 3 custom best-practice controls (`BP.UserData`, `BP.Egress`, `BP.PublicAMI`)**

| Control | Description | Severity |
|---------|-------------|----------|
| EC2.1   | EBS snapshots should not be publicly restorable | CRITICAL |
| EC2.2   | VPC default SG should not allow inbound/outbound traffic | HIGH |
| EC2.3   | Attached EBS volumes should be encrypted | MEDIUM |
| EC2.4   | Stopped instances should be removed after threshold | MEDIUM |
| EC2.6   | VPC flow logging should be enabled | MEDIUM |
| EC2.7   | EBS default encryption should be enabled | MEDIUM |
| EC2.8   | EC2 instances should use IMDSv2 | HIGH |
| EC2.9   | EC2 instances should not have public IPv4 | HIGH |
| EC2.12  | Unused EIPs should be removed | LOW |
| EC2.13  | SGs should not allow ingress from 0.0.0.0/0 to port 22 | HIGH |
| EC2.14  | SGs should not allow ingress from 0.0.0.0/0 to port 3389 | HIGH |
| EC2.15  | Subnets should not auto-assign public IPs | MEDIUM |
| EC2.17  | EC2 instances should not use multiple ENIs | LOW |
| EC2.18  | SGs should only allow authorized ports open to world | HIGH |
| EC2.19  | SGs should not allow unrestricted access to high-risk ports | CRITICAL |
| EC2.21  | NACLs should not allow ingress from 0.0.0.0/0 to admin ports | MEDIUM |
| EC2.22  | Unused SGs should be removed | MEDIUM |
| EC2.23  | Transit Gateways should not auto-accept VPC attachments | HIGH |
| EC2.24  | Paravirtual instance types should not be used | MEDIUM |
| EC2.25  | Launch templates should not assign public IPs | HIGH |
| EC2.28  | EBS volumes should be covered by backup plan | LOW |
| EC2.38  | EC2 instances should have required tags | LOW |
| EC2.53  | SGs should not allow ingress from 0.0.0.0/0 to remote admin ports | HIGH |
| EC2.170 | Launch templates should enforce IMDSv2 | HIGH |
| EC2.172 | VPC Block Public Access should block IGW traffic | HIGH |
| EC2.180 | EC2 network interfaces should have source/destination check enabled | MEDIUM |
| EC2.181 | Launch template EBS volumes should be encrypted | MEDIUM |
| EC2.182 | Block public access settings should be enabled for Amazon EBS snapshots | HIGH |
| EC2.183 | EC2 VPN connections should use IKEv2 protocol | HIGH |
| BP.UserData | No secrets/credentials in UserData | CRITICAL |
| BP.Egress   | SG egress should be restricted | MEDIUM |
| BP.PublicAMI | No public AMI sharing | CRITICAL |

---

## CIS AWS Foundations Benchmark v5.0

> **Official Documentation:** [CIS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services) | [AWS Security Hub CIS](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)

**Coverage: 7 EC2-applicable controls (Section 3 logging + Section 5 networking)**

| Control | Description | Severity |
|---------|-------------|----------|
| 3.7   | Ensure VPC flow logging is enabled in all VPCs | MEDIUM |
| 5.1.1 | Ensure EBS volume encryption is enabled by default | MEDIUM |
| 5.2   | Ensure NACLs do not allow ingress from 0.0.0.0/0 to admin ports | MEDIUM |
| 5.3   | Ensure no SGs allow ingress from 0.0.0.0/0 to remote admin ports | HIGH |
| 5.4   | Ensure no SGs allow ingress from ::/0 to remote admin ports | HIGH |
| 5.5   | Ensure the default SG restricts all traffic | HIGH |
| 5.7   | Ensure EC2 instances use IMDSv2 | HIGH |

> **Note:** CIS v5.0 control 5.6 ("Ensure routing tables for VPC peering are 'least access'") is a manual control and not implemented in this automated scanner.

---

## PCI DSS v4.0.1

> **Official Documentation:** [PCI Security Standards](https://www.pcisecuritystandards.org/document_library/)

**Coverage: 12 EC2-applicable PCI DSS requirements**

| Control | Description | Severity |
|---------|-------------|----------|
| 1.2.1  | Network security controls — SG and NACL restrictions | HIGH |
| 1.3.1  | Restrict inbound traffic — no public IP | HIGH |
| 1.3.2  | Restrict outbound traffic from CDE | HIGH |
| 2.2.1  | System configuration standards — IMDSv2, HVM | MEDIUM |
| 3.4.1  | Render PAN unreadable — EBS encryption | HIGH |
| 6.3.3  | Security patches installed timely | HIGH |
| 7.2.1  | Restrict access by business need — IAM least privilege | HIGH |
| 8.6.1  | Interactive use of system/application accounts prevented unless needed | HIGH |
| 8.6.2  | Passwords/passphrases for system/application accounts not hard coded | CRITICAL |
| 10.2.1 | Audit log implementation | HIGH |
| 11.3.1 | Internal vulnerability scans — Inspector v2 | HIGH |
| 11.5.1 | Intrusion-detection / intrusion-prevention techniques — GuardDuty | HIGH |

---

## HIPAA Security Rule

> **Official Documentation:** [eCFR §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)

**Coverage: 10 HIPAA Security Rule citations (Administrative, Physical, Technical Safeguards)**

| Control | Description | Severity |
|---------|-------------|----------|
| §164.312(a)(1)      | Access Control — unique user ID, role-based access | HIGH |
| §164.312(a)(2)(iv)  | Encryption of ePHI — EBS encryption | HIGH |
| §164.312(b)         | Audit Controls — audit mechanisms | HIGH |
| §164.312(c)(1)      | Integrity — protect ePHI from improper alteration | MEDIUM |
| §164.312(d)         | Authentication — verify identity | HIGH |
| §164.312(e)(1)      | Transmission Security — guard against unauthorized access | HIGH |
| §164.312(e)(2)(ii)  | Encryption in Transit — SG egress control | MEDIUM |
| §164.308(a)(1)      | Security Management — risk analysis | HIGH |
| §164.308(a)(6)      | Security Incident Procedures — response and reporting | HIGH |
| §164.310(d)(1)      | Device and Media Controls — ePHI not public | CRITICAL |

---

## SOC 2 Type II — AWS EC2 Controls Supporting Trust Service Criteria

> **Official Documentation:** [AICPA SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) | [Trust Services Criteria](https://www.aicpa-cima.com/resources/download/get-description-criteria-for-your-organizations-soc-2-r-report)

**Coverage: 13 controls aligned with TSC criteria**

| Control | Description | Severity |
|---------|-------------|----------|
| CC6.1 | Logical Access Security | HIGH |
| CC6.2 | User Credential Management | MEDIUM |
| CC6.3 | Access Authorization | HIGH |
| CC6.6 | Security Against External Threats | HIGH |
| CC6.7 | Restrict Data Movement | HIGH |
| CC6.8 | Prevent/Detect Unauthorized Software | MEDIUM |
| CC7.1 | Detect and Monitor Anomalies | HIGH |
| CC7.2 | Monitor System Components | MEDIUM |
| CC7.3 | Evaluate Identified Events | HIGH |
| CC8.1 | Change Management | MEDIUM |
| A1.2  | Environmental Protections (Availability) | MEDIUM |
| C1.1  | Confidentiality of Information | HIGH |
| P6.1  | Privacy Criteria — encryption of PII | MEDIUM |

> **Note:** SOC 2 is a flexible framework — organizations select which Trust Service Criteria to implement. Security (CC) is mandatory, while Availability (A), Confidentiality (C), Processing Integrity (PI), and Privacy (P) are optional.

---

## ISO 27001:2022

> **Official Documentation:** [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)

**Coverage: 17 Annex A controls (2022 edition, 93-control set)**

| Control | Description | Severity |
|---------|-------------|----------|
| A.5.15 | Access Control | HIGH |
| A.5.18 | Access Rights — least privilege | HIGH |
| A.8.1  | User Endpoint Devices | MEDIUM |
| A.8.5  | Secure Authentication | HIGH |
| A.8.9  | Configuration Management | MEDIUM |
| A.8.10 | Information Deletion | MEDIUM |
| A.8.11 | Data Masking — no secrets in UserData | CRITICAL |
| A.8.12 | Data Leakage Prevention | HIGH |
| A.8.15 | Logging | MEDIUM |
| A.8.16 | Monitoring Activities | HIGH |
| A.8.20 | Network Security | HIGH |
| A.8.21 | Security of Network Services | HIGH |
| A.8.22 | Segregation of Networks | HIGH |
| A.8.24 | Use of Cryptography | HIGH |
| A.8.25 | SDLC Security | MEDIUM |
| A.8.26 | Application Security Requirements | MEDIUM |
| A.8.28 | Secure Coding — patch compliance | HIGH |

---

## ISO 27017 (Cloud-Specific)

> **Official Documentation:** [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html) | [AWS ISO 27017 FAQ](https://aws.amazon.com/compliance/iso-27017-faqs/)

**Coverage: 7 cloud-specific (CLD.*) controls**

| Control | Description | Severity |
|---------|-------------|----------|
| CLD.6.3.1  | Shared Responsibility — customer-managed IAM | HIGH |
| CLD.8.1.5  | Removal of Cloud Assets | MEDIUM |
| CLD.9.5.1  | Virtual Computing Segregation | HIGH |
| CLD.9.5.2  | Virtual Machine Hardening | HIGH |
| CLD.12.1.5 | Administrator Operational Security | HIGH |
| CLD.12.4.5 | Monitoring of Cloud Services | MEDIUM |
| CLD.13.1.4 | Virtual Network Security | HIGH |

---

## ISO 27018 (PII in Cloud)

> **Official Documentation:** [ISO/IEC 27018:2019](https://www.iso.org/standard/76559.html)

**Coverage: 4 PII processor controls**

| Control | Description | Severity |
|---------|-------------|----------|
| A.11.6 | Encryption of PII transmitted over public data-transmission networks | HIGH |
| A.5.1  | Secure erasure of temporary files | MEDIUM |
| A.12.1 | Geographical location of PII | MEDIUM |
| A.10.1 | Notification of a data breach involving PII | HIGH |

---

## GDPR (EU) 2016/679

> **Official Documentation:** [EUR-Lex Regulation](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | [GDPR Info](https://gdpr-info.eu/)

**Coverage: 8 Articles**

| Control | Description | Severity |
|---------|-------------|----------|
| Art.25      | Data Protection by Design | HIGH |
| Art.32(1)(a)| Pseudonymisation & Encryption | HIGH |
| Art.32(1)(b)| Confidentiality & Integrity | HIGH |
| Art.32(1)(c)| Availability & Resilience | MEDIUM |
| Art.32(1)(d)| Testing & Evaluation | HIGH |
| Art.33      | Breach Notification | HIGH |
| Art.44-49   | International Transfers — data governance tagging | MEDIUM |
| Art.5(1)(f) | Integrity & Confidentiality | HIGH |

---

## NIST SP 800-53 Rev5

> **Official Documentation:** [NIST SP 800-53 Rev5 (final)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

**Coverage: 27 controls across AC, AU, CA, CM, CP, IA, IR, MP, RA, SC, SI families**

| Control | Description | Severity |
|---------|-------------|----------|
| AC-2      | Account Management | HIGH |
| AC-3      | Access Enforcement | HIGH |
| AC-4      | Information Flow Enforcement | HIGH |
| AC-4(21)  | Physical/Logical Separation | HIGH |
| AC-6      | Least Privilege | HIGH |
| AC-17     | Remote Access | HIGH |
| AU-2      | Event Logging | MEDIUM |
| AU-3      | Content of Audit Records | MEDIUM |
| AU-6      | Audit Review | MEDIUM |
| AU-12     | Audit Record Generation | MEDIUM |
| CA-7      | Continuous Monitoring | HIGH |
| CM-2      | Baseline Configuration | MEDIUM |
| CM-6      | Configuration Settings | MEDIUM |
| CM-7      | Least Functionality | MEDIUM |
| CP-9      | System Backup | MEDIUM |
| IA-2      | Identification and Authentication | HIGH |
| IA-5      | Authenticator Management | HIGH |
| IR-4      | Incident Handling | HIGH |
| MP-6      | Media Sanitization | MEDIUM |
| RA-5      | Vulnerability Monitoring | HIGH |
| SC-7      | Boundary Protection | HIGH |
| SC-8      | Transmission Confidentiality | MEDIUM |
| SC-13     | Cryptographic Protection | HIGH |
| SC-28     | Protection of Information at Rest | HIGH |
| SI-2      | Flaw Remediation | HIGH |
| SI-4      | System Monitoring | MEDIUM |
| SI-7      | Software Integrity | MEDIUM |

---

## How Compliance is Evaluated

Each control maps to one or more scanner checks. An instance is **compliant** with a control when all of its underlying checks pass. Aggregation is per-framework:

```
framework_compliance_percentage =
    sum(passed_controls_per_instance) /
    (sum(passed_controls_per_instance) + sum(failed_controls_per_instance))
    × 100
```

The scanner emits a `compliance_status` field per instance and per framework in the JSON output, with `passed_controls`, `failed_controls`, `compliance_percentage`, and `is_compliant` (a boolean: `True` only when `failed_controls == 0`).

For check-to-control mapping details, see [`compliance.py`](ec2_security_scanner/compliance.py). For attack-vector documentation of each individual check, see [security-checks.md](security-checks.md). For remediation steps, see [remediation-guide.md](remediation-guide.md).
