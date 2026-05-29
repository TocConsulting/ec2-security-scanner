"""Compliance Engine - 10 frameworks, 137 lambda-based controls.

Evaluates instance check results against compliance framework controls.
Each control is a lambda that reads from the checks dict built during
scan_instance(). The checks dict key names are the contract between
checkers and compliance.

Frameworks: AWS-FSBP, CIS v5.0, PCI DSS v4.0.1, HIPAA, SOC 2,
            ISO 27001:2022, ISO 27017, ISO 27018, GDPR, NIST 800-53 Rev5
"""

import inspect
import re
from typing import Dict, Any


# Matches top-level `r.get("key"` accesses in a control lambda's source. Only
# the receiver `r` is matched, so chained `.get("subkey"` calls are ignored.
_RESULT_KEY_RE = re.compile(r'r\.get\(\s*["\']([^"\']+)["\']')


# Result-dict keys whose findings are account- or VPC-wide. A control that
# reads ONLY from these keys is account-level and is evaluated ONCE per scan
# (e.g. "GuardDuty enabled" is a single regional control), instead of being
# re-counted against every instance. Keep this in sync with
# scanner.ACCOUNT_CHECK_KEYS / scanner.VPC_CHECK_KEYS.
ACCOUNT_LEVEL_KEYS = frozenset({
    # account/region-wide
    "ebs_default_encryption", "ebs_snapshot_bpa", "public_ami",
    "serial_console", "cloudtrail", "guardduty", "unused_eips",
    "vpc_bpa", "transit_gateway", "vpn_connections", "unused_sgs",
    # VPC-wide (shared by every instance in the VPC)
    "default_sg", "vpc_flow_logs", "nacl_admin_ports", "instance_connect",
    # Launch templates are region-level resources, audited once per region.
    "launch_template_imdsv2", "launch_template_public_ip",
    "launch_template_ebs_encryption",
})


class _KeyTracker(dict):
    """A dict-like probe that records which top-level keys a control reads.

    Used to classify each control's scope without hand-tagging 137 controls:
    we call the control's lambda with this probe and inspect which result
    keys it touched. Every level returns an empty dict so chained
    ``.get(...).get(...)`` and comparisons evaluate harmlessly.
    """

    def __init__(self):
        super().__init__()
        self.accessed = set()

    def get(self, key, default=None):
        self.accessed.add(key)
        return {}

    def __getitem__(self, key):
        self.accessed.add(key)
        return {}


class ComplianceChecker:
    """Evaluate security checks against 10 compliance frameworks.

    Controls are classified as **account-level** (evaluated once per scan) or
    **instance-level** (evaluated per instance) so that account/region-wide
    controls such as GuardDuty or CloudTrail are not duplicated across every
    instance in the compliance math.
    """

    def __init__(self):
        self.frameworks = {}
        self._define_frameworks()
        self._classify_control_scopes()

    def _classify_control_scopes(self):
        """Tag each control with scope = 'account' or 'instance'.

        A control is account-level iff every result key it reads is in
        ACCOUNT_LEVEL_KEYS. A control that reads any instance-specific key
        (or no key at all) is instance-level. A composite control reading
        BOTH an account key and an instance key is instance-level — it
        genuinely varies per instance.
        """
        for framework in self.frameworks.values():
            for control in framework["controls"].values():
                keys = self._control_result_keys(control["check"])
                control["scope"] = (
                    "account"
                    if keys and keys <= ACCOUNT_LEVEL_KEYS
                    else "instance"
                )

    @staticmethod
    def _control_result_keys(check_fn) -> set:
        """Return the set of top-level result keys a control reads.

        Prefers static source analysis (immune to short-circuit `and`/`or`
        evaluation, which would otherwise hide keys). Falls back to a dynamic
        probe if source is unavailable (e.g. frozen/zipped deployments).
        """
        try:
            source = inspect.getsource(check_fn)
            keys = set(_RESULT_KEY_RE.findall(source))
            if keys:
                return keys
        except (OSError, TypeError):
            pass
        probe = _KeyTracker()
        try:
            check_fn(probe)
        except Exception:
            pass
        return probe.accessed

    def _define_frameworks(self):
        """Define all 10 compliance frameworks with lambda-based controls."""

        self.frameworks = {
            # ================================================================
            # AWS Foundational Security Best Practices (32 controls)
            # ================================================================
            "AWS-FSBP": {
                "name": "AWS Foundational Security Best Practices",
                "controls": {
                    "EC2.1": {
                        "description": "EBS snapshots should not be publicly restorable",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True),
                    },
                    "EC2.2": {
                        "description": "VPC default SG should not allow inbound/outbound traffic",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("default_sg", {}).get("has_rules", True),
                    },
                    "EC2.3": {
                        "description": "Attached EBS volumes should be encrypted",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ebs_encryption", {}).get("all_encrypted", False),
                    },
                    "EC2.4": {
                        "description": "Stopped instances should be removed after threshold",
                        "severity": "MEDIUM",
                        "check": lambda r: not r.get("stopped_instance", {}).get("exceeds_threshold", False),
                    },
                    "EC2.6": {
                        "description": "VPC flow logging should be enabled",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("vpc_flow_logs", {}).get("enabled", False),
                    },
                    "EC2.7": {
                        "description": "EBS default encryption should be enabled",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ebs_default_encryption", {}).get("enabled", False),
                    },
                    "EC2.8": {
                        "description": "EC2 instances should use IMDSv2",
                        "severity": "HIGH",
                        "check": lambda r: r.get("imdsv2", {}).get("enforced", False),
                    },
                    "EC2.9": {
                        "description": "EC2 instances should not have public IPv4",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("public_ip", {}).get("has_public_ip", True),
                    },
                    "EC2.12": {
                        "description": "Unused EIPs should be removed",
                        "severity": "LOW",
                        "check": lambda r: r.get("unused_eips", {}).get("count", 1) == 0,
                    },
                    "EC2.13": {
                        "description": "SGs should not allow ingress from 0.0.0.0/0 or ::/0 to port 22",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_ssh", {}).get("open_to_world", True),
                    },
                    "EC2.14": {
                        "description": "SGs should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_rdp", {}).get("open_to_world", True),
                    },
                    "EC2.15": {
                        "description": "Subnets should not auto-assign public IPs",
                        "severity": "MEDIUM",
                        "check": lambda r: not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True),
                    },
                    "EC2.17": {
                        "description": "EC2 instances should not use multiple ENIs",
                        "severity": "LOW",
                        "check": lambda r: not r.get("network_interfaces", {}).get("has_multiple", False),
                    },
                    "EC2.18": {
                        "description": "SGs should only allow authorized ports open to world",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_authorized_ports", {}).get("has_violations", True),
                    },
                    "EC2.19": {
                        "description": "SGs should not allow unrestricted access to high-risk ports",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("sg_high_risk_ports", {}).get("has_violations", True),
                    },
                    "EC2.21": {
                        "description": "NACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389",
                        "severity": "MEDIUM",
                        "check": lambda r: not r.get("nacl_admin_ports", {}).get("open_to_world", True),
                    },
                    "EC2.22": {
                        "description": "Unused SGs should be removed",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("unused_sgs", {}).get("count", 1) == 0,
                    },
                    "EC2.23": {
                        "description": "Transit Gateways should not auto-accept VPC attachments",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("transit_gateway", {}).get("auto_accept_enabled", True),
                    },
                    "EC2.24": {
                        "description": "Paravirtual instance types should not be used",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("virtualization", {}).get("is_hvm", False),
                    },
                    "EC2.25": {
                        "description": "Launch templates should not assign public IPs",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("launch_template_public_ip", {}).get("assigns_public_ip", True),
                    },
                    "EC2.28": {
                        "description": "EBS volumes should be covered by backup plan",
                        "severity": "LOW",
                        "check": lambda r: r.get("ebs_backup", {}).get("covered", False),
                    },
                    "EC2.38": {
                        "description": "EC2 instances should have required tags",
                        "severity": "LOW",
                        "check": lambda r: r.get("tags", {}).get("has_required_tags", False),
                    },
                    "EC2.53": {
                        "description": "SGs should not allow ingress from 0.0.0.0/0 to remote admin ports",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_remote_admin", {}).get("open_to_world", True),
                    },
                    "EC2.170": {
                        "description": "Launch templates should enforce IMDSv2",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("launch_template_imdsv2", {}).get("checked", False)
                            or r.get("launch_template_imdsv2", {}).get("enforced", False)
                        ),
                    },
                    "EC2.172": {
                        "description": "VPC Block Public Access should block IGW traffic",
                        "severity": "HIGH",
                        "check": lambda r: r.get("vpc_bpa", {}).get("blocks_igw", False),
                    },
                    "EC2.180": {
                        "description": "EC2 network interfaces should have source/dest check enabled",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("source_dest_check", {}).get("enabled", False),
                    },
                    "EC2.181": {
                        "description": "Launch template EBS volumes should be encrypted",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                            or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                        ),
                    },
                    "EC2.182": {
                        "description": "Block public access settings should be enabled for Amazon EBS snapshots",
                        "severity": "HIGH",
                        "check": lambda r: r.get("ebs_snapshot_bpa", {}).get("blocked", False),
                    },
                    "EC2.183": {
                        "description": "EC2 VPN connections should use IKEv2 protocol",
                        "severity": "HIGH",
                        "check": lambda r: r.get("vpn_connections", {}).get("all_ikev2", True),
                    },
                    "BP.UserData": {
                        "description": "No secrets/credentials in UserData",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("userdata_secrets", {}).get("has_secrets", True),
                    },
                    "BP.Egress": {
                        "description": "SG egress should be restricted "
                                       "(opinionated hardening; AWS default "
                                       "is allow-all, not FSBP-required)",
                        "severity": "LOW",
                        "check": lambda r: not r.get("sg_egress", {}).get("unrestricted", True),
                    },
                    "BP.PublicAMI": {
                        "description": "No public AMI sharing",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("public_ami", {}).get("has_public_amis", True),
                    },
                },
            },

            # ================================================================
            # CIS AWS Foundations Benchmark v5.0 (7 controls)
            # ================================================================
            "CIS-v5.0": {
                "name": "CIS AWS Foundations Benchmark v5.0",
                "controls": {
                    "3.7": {
                        "description": "Ensure VPC flow logging is enabled in all VPCs",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("vpc_flow_logs", {}).get("enabled", False),
                    },
                    "5.1.1": {
                        "description": "Ensure EBS volume encryption is enabled by default",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ebs_default_encryption", {}).get("enabled", False),
                    },
                    "5.2": {
                        "description": "Ensure NACLs do not allow ingress from 0.0.0.0/0 to admin ports",
                        "severity": "MEDIUM",
                        "check": lambda r: not r.get("nacl_admin_ports", {}).get("open_to_world", True),
                    },
                    "5.3": {
                        "description": "Ensure no SGs allow ingress from 0.0.0.0/0 to remote admin ports",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_remote_admin", {}).get("open_to_ipv4", True),
                    },
                    "5.4": {
                        "description": "Ensure no SGs allow ingress from ::/0 to remote admin ports",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("sg_remote_admin", {}).get("open_to_ipv6", True),
                    },
                    "5.5": {
                        "description": "Ensure the default SG restricts all traffic",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("default_sg", {}).get("has_rules", True),
                    },
                    "5.7": {
                        "description": "Ensure EC2 instances use IMDSv2",
                        "severity": "HIGH",
                        "check": lambda r: r.get("imdsv2", {}).get("enforced", False),
                    },
                },
            },

            # ================================================================
            # PCI DSS v4.0.1 (12 controls)
            # ================================================================
            "PCI-DSS-v4.0": {
                "name": "PCI DSS v4.0.1",
                "controls": {
                    "1.2.1": {
                        "description": "Network security controls - SG and NACL restrictions",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_authorized_ports", {}).get("has_violations", True)
                        ),
                    },
                    "1.3.1": {
                        "description": "Restrict inbound traffic - no public IP",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("public_ip", {}).get("has_public_ip", True)
                            and not r.get("launch_template_public_ip", {}).get("assigns_public_ip", True)
                            and not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True)
                        ),
                    },
                    "1.3.2": {
                        "description": "Restrict outbound traffic from CDE",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_egress", {}).get("unrestricted", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_remote_admin", {}).get("open_to_world", True)
                        ),
                    },
                    "2.2.1": {
                        "description": "System configuration standards - IMDSv2, HVM",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("virtualization", {}).get("is_hvm", False)
                        ),
                    },
                    "8.6.2": {
                        "description": "Passwords/passphrases for system/application accounts not hard coded",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("userdata_secrets", {}).get("has_secrets", True),
                    },
                    "3.4.1": {
                        "description": "Render PAN unreadable - EBS encryption",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                        ),
                    },
                    "6.3.3": {
                        "description": "Security patches installed timely",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and not r.get("ami_age", {}).get("is_stale", True)
                        ),
                    },
                    "7.2.1": {
                        "description": "Restrict access by business need - IAM least privilege",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("iam_profile", {}).get("attached", False)
                        ),
                    },
                    "8.6.1": {
                        "description": "Interactive use of system/application accounts is prevented unless needed",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("userdata_secrets", {}).get("has_secrets", True)
                            and not r.get("iam_role", {}).get("has_admin_access", True)
                        ),
                    },
                    "10.2.1": {
                        "description": "Audit log implementation",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "11.3.1": {
                        "description": "Internal vulnerability scans - Inspector v2",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                            and r.get("inspector_v2", {}).get("critical_findings", 1) == 0
                        ),
                    },
                    "11.5.1": {
                        "description": "Intrusion-detection / intrusion-prevention techniques in use - GuardDuty",
                        "severity": "HIGH",
                        "check": lambda r: r.get("guardduty", {}).get("enabled", False),
                    },
                },
            },

            # ================================================================
            # HIPAA (10 controls)
            # ================================================================
            "HIPAA": {
                "name": "HIPAA Security Rule",
                "controls": {
                    "164.312(a)(1)": {
                        "description": "Access Control - unique user ID, role-based access",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("iam_profile", {}).get("attached", False)
                            and r.get("imdsv2", {}).get("enforced", False)
                        ),
                    },
                    "164.312(a)(2)(iv)": {
                        "description": "Encryption of ePHI - EBS encryption",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                        ),
                    },
                    "164.312(b)": {
                        "description": "Audit Controls - audit mechanisms",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "164.312(c)(1)": {
                        "description": "Integrity - protect ePHI from improper alteration",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and not r.get("ami_age", {}).get("is_stale", True)
                            and r.get("source_dest_check", {}).get("enabled", False)
                        ),
                    },
                    "164.312(d)": {
                        "description": "Authentication - verify identity",
                        "severity": "HIGH",
                        "check": lambda r: r.get("imdsv2", {}).get("enforced", False),
                    },
                    "164.312(e)(1)": {
                        "description": "Transmission Security - guard against unauthorized access",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("vpc_flow_logs", {}).get("enabled", False)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                        ),
                    },
                    "164.312(e)(2)(ii)": {
                        "description": "Encryption in Transit - SG egress control",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("sg_egress", {}).get("unrestricted", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                        ),
                    },
                    "164.308(a)(1)": {
                        "description": "Security Management - risk analysis",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                            and r.get("guardduty", {}).get("enabled", False)
                        ),
                    },
                    "164.308(a)(6)": {
                        "description": "Security Incident Procedures - response and reporting",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "164.310(d)(1)": {
                        "description": "Device and Media - ePHI not public",
                        "severity": "CRITICAL",
                        "check": lambda r: (
                            not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                            and not r.get("public_ami", {}).get("has_public_amis", True)
                        ),
                    },
                },
            },

            # ================================================================
            # SOC 2 Trust Service Criteria (13 controls)
            # ================================================================
            "SOC2": {
                "name": "SOC 2 Trust Service Criteria",
                "controls": {
                    "CC6.1": {
                        "description": "Logical Access Security",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("imdsv2", {}).get("enforced", False)
                            and r.get("iam_profile", {}).get("attached", False)
                            and not r.get("userdata_secrets", {}).get("has_secrets", True)
                        ),
                    },
                    "CC6.2": {
                        "description": "User Credential Management",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("serial_console", {}).get("enabled", True)
                            and not (
                                r.get("key_pair", {}).get("has_key_pair", False)
                                and not r.get("key_pair", {}).get("ssm_managed", False)
                            )
                        ),
                    },
                    "CC6.3": {
                        "description": "Access Authorization",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and not r.get("iam_role", {}).get("has_wildcard_actions", True)
                            and not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_authorized_ports", {}).get("has_violations", True)
                        ),
                    },
                    "CC6.6": {
                        "description": "Security Against External Threats",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_remote_admin", {}).get("open_to_world", True)
                        ),
                    },
                    "CC6.7": {
                        "description": "Restrict Data Movement",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("public_ip", {}).get("has_public_ip", True)
                            and not r.get("sg_egress", {}).get("unrestricted", True)
                            and not r.get("launch_template_public_ip", {}).get("assigns_public_ip", True)
                            and not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True)
                            and r.get("vpc_bpa", {}).get("blocks_igw", False)
                            and not r.get("transit_gateway", {}).get("auto_accept_enabled", True)
                        ),
                    },
                    "CC6.8": {
                        "description": "Prevent/Detect Unauthorized Software",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and not r.get("ami_age", {}).get("is_stale", True)
                            and r.get("ssm_managed", {}).get("is_managed", False)
                        ),
                    },
                    "CC7.1": {
                        "description": "Detect and Monitor Anomalies",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("cloudwatch_alarms", {}).get("has_alarms", False)
                            and r.get("guardduty", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "CC7.2": {
                        "description": "Monitor System Components",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ssm_managed", {}).get("is_managed", False)
                            and r.get("monitoring", {}).get("detailed_enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "CC7.3": {
                        "description": "Evaluate Identified Events",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "CC8.1": {
                        "description": "Change Management",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            (
                                not r.get("launch_template_imdsv2", {}).get("checked", False)
                                or r.get("launch_template_imdsv2", {}).get("enforced", False)
                            )
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                            and not r.get("launch_template_public_ip", {}).get("assigns_public_ip", True)
                        ),
                    },
                    "A1.2": {
                        "description": "Environmental Protections (Availability)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ebs_backup", {}).get("covered", False),
                    },
                    "C1.1": {
                        "description": "Confidentiality of Information",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                            and not r.get("public_ami", {}).get("has_public_amis", True)
                        ),
                    },
                    "P6.1": {
                        "description": "Privacy Criteria - encryption of PII",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("tags", {}).get("has_required_tags", False)
                        ),
                    },
                },
            },

            # ================================================================
            # ISO 27001:2022 (17 controls)
            # ================================================================
            "ISO27001": {
                "name": "ISO 27001:2022",
                "controls": {
                    "A.5.15": {
                        "description": "Access Control",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("iam_profile", {}).get("attached", False)
                            and r.get("imdsv2", {}).get("enforced", False)
                        ),
                    },
                    "A.5.18": {
                        "description": "Access Rights - least privilege",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("iam_role", {}).get("has_admin_access", True),
                    },
                    "A.8.1": {
                        "description": "User Endpoint Devices",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("virtualization", {}).get("is_hvm", False)
                            and r.get("monitoring", {}).get("detailed_enabled", False)
                        ),
                    },
                    "A.8.5": {
                        "description": "Secure Authentication",
                        "severity": "HIGH",
                        "check": lambda r: r.get("imdsv2", {}).get("enforced", False),
                    },
                    "A.8.9": {
                        "description": "Configuration Management",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ssm_managed", {}).get("is_managed", False)
                            and (
                                not r.get("launch_template_imdsv2", {}).get("checked", False)
                                or r.get("launch_template_imdsv2", {}).get("enforced", False)
                            )
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                        ),
                    },
                    "A.8.10": {
                        "description": "Information Deletion",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("stopped_instance", {}).get("exceeds_threshold", False)
                            and not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                        ),
                    },
                    "A.8.11": {
                        "description": "Data Masking - no secrets in UserData",
                        "severity": "CRITICAL",
                        "check": lambda r: not r.get("userdata_secrets", {}).get("has_secrets", True),
                    },
                    "A.8.12": {
                        "description": "Data Leakage Prevention",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                            and not r.get("public_ami", {}).get("has_public_amis", True)
                            and not r.get("sg_egress", {}).get("unrestricted", True)
                        ),
                    },
                    "A.8.15": {
                        "description": "Logging",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "A.8.16": {
                        "description": "Monitoring Activities",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("ssm_managed", {}).get("is_managed", False)
                        ),
                    },
                    "A.8.20": {
                        "description": "Network Security",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                        ),
                    },
                    "A.8.21": {
                        "description": "Security of Network Services",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_remote_admin", {}).get("open_to_world", True)
                            and not r.get("sg_authorized_ports", {}).get("has_violations", True)
                        ),
                    },
                    "A.8.22": {
                        "description": "Segregation of Networks",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("public_ip", {}).get("has_public_ip", True)
                            and not r.get("launch_template_public_ip", {}).get("assigns_public_ip", True)
                            and not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True)
                            and r.get("vpc_bpa", {}).get("blocks_igw", False)
                            and not r.get("transit_gateway", {}).get("auto_accept_enabled", True)
                        ),
                    },
                    "A.8.24": {
                        "description": "Use of Cryptography",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                        ),
                    },
                    "A.8.25": {
                        "description": "SDLC Security",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("ami_age", {}).get("is_stale", True)
                            and (
                                not r.get("launch_template_imdsv2", {}).get("checked", False)
                                or r.get("launch_template_imdsv2", {}).get("enforced", False)
                            )
                        ),
                    },
                    "A.8.26": {
                        "description": "Application Security Requirements",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("source_dest_check", {}).get("enabled", False)
                        ),
                    },
                    "A.8.28": {
                        "description": "Secure Coding - patch compliance",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                },
            },

            # ================================================================
            # ISO 27017 Cloud-Specific (7 controls)
            # ================================================================
            "ISO27017": {
                "name": "ISO 27017 (Cloud-Specific)",
                "controls": {
                    "CLD.6.3.1": {
                        "description": "Shared Responsibility - customer-managed IAM",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("iam_profile", {}).get("attached", False)
                        ),
                    },
                    "CLD.8.1.5": {
                        "description": "Removal of Cloud Assets",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("stopped_instance", {}).get("exceeds_threshold", False)
                            and r.get("unused_eips", {}).get("count", 1) == 0
                            and r.get("unused_sgs", {}).get("count", 1) == 0
                        ),
                    },
                    "CLD.9.5.1": {
                        "description": "Virtual Computing Segregation",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("public_ip", {}).get("has_public_ip", True)
                            and not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True)
                        ),
                    },
                    "CLD.9.5.2": {
                        "description": "Virtual Machine Hardening",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("virtualization", {}).get("is_hvm", False)
                            and r.get("ssm_patch", {}).get("is_compliant", False)
                        ),
                    },
                    "CLD.12.1.5": {
                        "description": "Administrator Operational Security",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and not r.get("serial_console", {}).get("enabled", True)
                            and r.get("cloudtrail", {}).get("enabled", False)
                        ),
                    },
                    "CLD.12.4.5": {
                        "description": "Monitoring of Cloud Services",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("cloudwatch_alarms", {}).get("has_alarms", False)
                            and r.get("guardduty", {}).get("enabled", False)
                            and r.get("monitoring", {}).get("detailed_enabled", False)
                        ),
                    },
                    "CLD.13.1.4": {
                        "description": "Virtual Network Security",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                },
            },

            # ================================================================
            # ISO 27018 PII in Cloud (4 controls)
            # ================================================================
            "ISO27018": {
                "name": "ISO 27018 (PII in Cloud)",
                "controls": {
                    "A.11.6": {
                        "description": "Encryption of PII transmitted over public data-transmission networks",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                        ),
                    },
                    "A.5.1": {
                        "description": "Secure erasure of temporary files",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("stopped_instance", {}).get("exceeds_threshold", False)
                            and not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                        ),
                    },
                    "A.12.1": {
                        "description": "Geographical location of PII",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("tags", {}).get("has_required_tags", False)
                            and not r.get("stopped_instance", {}).get("exceeds_threshold", False)
                        ),
                    },
                    "A.10.1": {
                        "description": "Notification of a data breach involving PII",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                },
            },

            # ================================================================
            # GDPR (8 articles)
            # ================================================================
            "GDPR": {
                "name": "GDPR (EU) 2016/679",
                "controls": {
                    "Art.25": {
                        "description": "Data Protection by Design",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and not r.get("default_sg", {}).get("has_rules", True)
                        ),
                    },
                    "Art.32(1)(a)": {
                        "description": "Pseudonymisation & Encryption",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                        ),
                    },
                    "Art.32(1)(b)": {
                        "description": "Confidentiality & Integrity",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_remote_admin", {}).get("open_to_world", True)
                            and not r.get("userdata_secrets", {}).get("has_secrets", True)
                            and not r.get("public_ami", {}).get("has_public_amis", True)
                        ),
                    },
                    "Art.32(1)(c)": {
                        "description": "Availability & Resilience",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("ebs_backup", {}).get("covered", False)
                            and r.get("monitoring", {}).get("detailed_enabled", False)
                            and r.get("cloudwatch_alarms", {}).get("has_alarms", False)
                        ),
                    },
                    "Art.32(1)(d)": {
                        "description": "Testing & Evaluation",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                            and r.get("guardduty", {}).get("enabled", False)
                            and r.get("ssm_patch", {}).get("is_compliant", False)
                        ),
                    },
                    "Art.33": {
                        "description": "Breach Notification",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("guardduty", {}).get("enabled", False)
                        ),
                    },
                    "Art.44-49": {
                        "description": "International Transfers - data governance tagging",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("tags", {}).get("has_required_tags", False),
                    },
                    "Art.5(1)(f)": {
                        "description": "Integrity & Confidentiality",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and not r.get("iam_role", {}).get("has_admin_access", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                        ),
                    },
                },
            },

            # ================================================================
            # NIST SP 800-53 Rev5 (27 controls)
            # ================================================================
            "NIST-800-53": {
                "name": "NIST SP 800-53 Rev5",
                "controls": {
                    "AC-2": {
                        "description": "Account Management",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and r.get("iam_profile", {}).get("attached", False)
                            and not r.get("userdata_secrets", {}).get("has_secrets", True)
                        ),
                    },
                    "AC-3": {
                        "description": "Access Enforcement",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("iam_role", {}).get("has_admin_access", True)
                            and not r.get("default_sg", {}).get("has_rules", True)
                            and not r.get("sg_authorized_ports", {}).get("has_violations", True)
                        ),
                    },
                    "AC-4": {
                        "description": "Information Flow Enforcement",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("nacl_admin_ports", {}).get("open_to_world", True)
                            and not r.get("sg_egress", {}).get("unrestricted", True)
                        ),
                    },
                    "AC-4(21)": {
                        "description": "Physical/Logical Separation",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("public_ip", {}).get("has_public_ip", True)
                            and not r.get("subnet_auto_assign_public_ip", {}).get("enabled", True)
                            and r.get("vpc_bpa", {}).get("blocks_igw", False)
                            and not r.get("transit_gateway", {}).get("auto_accept_enabled", True)
                        ),
                    },
                    "AC-6": {
                        "description": "Least Privilege",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("iam_role", {}).get("has_admin_access", True),
                    },
                    "AC-17": {
                        "description": "Remote Access",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and not r.get("sg_remote_admin", {}).get("open_to_world", True)
                            and not (
                                r.get("key_pair", {}).get("has_key_pair", False)
                                and not r.get("key_pair", {}).get("ssm_managed", False)
                            )
                            and r.get("instance_connect", {}).get("endpoints_configured", False)
                        ),
                    },
                    "AU-2": {
                        "description": "Event Logging",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "AU-3": {
                        "description": "Content of Audit Records",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("cloudtrail", {}).get("enabled", False),
                    },
                    "AU-6": {
                        "description": "Audit Review",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "AU-12": {
                        "description": "Audit Record Generation",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("cloudtrail", {}).get("enabled", False)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "CA-7": {
                        "description": "Continuous Monitoring",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                            and r.get("ssm_managed", {}).get("is_managed", False)
                        ),
                    },
                    "CM-2": {
                        "description": "Baseline Configuration",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ssm_managed", {}).get("is_managed", False),
                    },
                    "CM-6": {
                        "description": "Configuration Settings",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("imdsv2", {}).get("enforced", False)
                            and r.get("virtualization", {}).get("is_hvm", False)
                            and not r.get("default_sg", {}).get("has_rules", True)
                        ),
                    },
                    "CM-7": {
                        "description": "Least Functionality",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and r.get("unused_sgs", {}).get("count", 1) == 0
                            and r.get("unused_eips", {}).get("count", 1) == 0
                        ),
                    },
                    "CP-9": {
                        "description": "System Backup",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ebs_backup", {}).get("covered", False),
                    },
                    "IA-2": {
                        "description": "Identification and Authentication",
                        "severity": "HIGH",
                        "check": lambda r: r.get("imdsv2", {}).get("enforced", False),
                    },
                    "IA-5": {
                        "description": "Authenticator Management",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("userdata_secrets", {}).get("has_secrets", True),
                    },
                    "IR-4": {
                        "description": "Incident Handling",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("guardduty", {}).get("enabled", False)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "MP-6": {
                        "description": "Media Sanitization",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("stopped_instance", {}).get("exceeds_threshold", False)
                            and not r.get("ebs_snapshot_public", {}).get("has_public_snapshots", True)
                            and not r.get("public_ami", {}).get("has_public_amis", True)
                        ),
                    },
                    "RA-5": {
                        "description": "Vulnerability Monitoring",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and not r.get("ami_age", {}).get("is_stale", True)
                            and r.get("inspector_v2", {}).get("ec2_scanning_enabled", False)
                        ),
                    },
                    "SC-7": {
                        "description": "Boundary Protection",
                        "severity": "HIGH",
                        "check": lambda r: (
                            not r.get("sg_ssh", {}).get("open_to_world", True)
                            and not r.get("sg_rdp", {}).get("open_to_world", True)
                            and not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("nacl_admin_ports", {}).get("open_to_world", True)
                            and not r.get("sg_egress", {}).get("unrestricted", True)
                            and r.get("vpc_bpa", {}).get("blocks_igw", False)
                        ),
                    },
                    "SC-8": {
                        "description": "Transmission Confidentiality",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            not r.get("sg_high_risk_ports", {}).get("has_violations", True)
                            and not r.get("sg_egress", {}).get("unrestricted", True)
                            and r.get("vpc_flow_logs", {}).get("enabled", False)
                        ),
                    },
                    "SC-13": {
                        "description": "Cryptographic Protection",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ebs_encryption", {}).get("all_encrypted", False)
                            and r.get("ebs_default_encryption", {}).get("enabled", False)
                            and (
                                not r.get("launch_template_ebs_encryption", {}).get("checked", False)
                                or r.get("launch_template_ebs_encryption", {}).get("all_encrypted", False)
                            )
                        ),
                    },
                    "SC-28": {
                        "description": "Protection of Information at Rest",
                        "severity": "HIGH",
                        "check": lambda r: r.get("ebs_encryption", {}).get("all_encrypted", False),
                    },
                    "SI-2": {
                        "description": "Flaw Remediation",
                        "severity": "HIGH",
                        "check": lambda r: (
                            r.get("ssm_patch", {}).get("is_compliant", False)
                            and not r.get("ami_age", {}).get("is_stale", True)
                        ),
                    },
                    "SI-4": {
                        "description": "System Monitoring",
                        "severity": "MEDIUM",
                        "check": lambda r: (
                            r.get("cloudwatch_alarms", {}).get("has_alarms", False)
                            and r.get("guardduty", {}).get("enabled", False)
                            and r.get("monitoring", {}).get("detailed_enabled", False)
                        ),
                    },
                    "SI-7": {
                        "description": "Software Integrity",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("ssm_patch", {}).get("is_compliant", False),
                    },
                },
            },
        }

    @staticmethod
    def _evaluate_control(control: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Run one control's check, treating any exception as a failure."""
        try:
            return bool(control["check"](data))
        except Exception:
            return False

    def check_instance_compliance(
        self, instance_checks: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Evaluate the **instance-level** controls against one instance.

        Account-level controls (GuardDuty, CloudTrail, VPC BPA, ...) are NOT
        evaluated here — they are scored once per scan via
        :meth:`evaluate_scan` — so a single account-wide gap is never
        multiplied across every instance.

        Returns a dict mapping framework name to per-instance results over
        that framework's instance-level controls only.
        """
        compliance = {}
        for fw_id, framework in self.frameworks.items():
            controls = {
                cid: c for cid, c in framework["controls"].items()
                if c.get("scope") == "instance"
            }
            passed, failed = [], []
            for control_id, control in controls.items():
                entry = {
                    "control_id": control_id,
                    "description": control["description"],
                }
                if self._evaluate_control(control, instance_checks):
                    passed.append(entry)
                else:
                    entry["severity"] = control.get("severity", "MEDIUM")
                    failed.append(entry)
            total = len(passed) + len(failed)
            compliance[fw_id] = {
                "framework_name": framework["name"],
                "scope": "instance",
                "total_controls": total,
                "passed_controls": len(passed),
                "failed_controls": len(failed),
                "compliance_percentage": (
                    round(len(passed) / total * 100, 1) if total else 100.0
                ),
                "is_compliant": len(failed) == 0,
                "passed": passed,
                "failed": failed,
            }
        return compliance

    def evaluate_scan(
        self,
        account_result: Dict[str, Any],
        instance_results: list,
    ) -> Dict[str, Dict[str, Any]]:
        """Evaluate every framework **at scan level** (the accurate view).

        Each control is counted once per scan:

        - **Account-level** controls are evaluated a single time against
          ``account_result`` (the merged account + aggregated-VPC state).
        - **Instance-level** controls are evaluated against every instance
          and counted as a single control that *passes only if all
          instances pass*; the affected instance IDs are recorded.

        So "GuardDuty enabled" is one regional control, and "IMDSv2 enforced"
        is one control that fails (listing offenders) if any instance fails.
        """
        out = {}
        for fw_id, framework in self.frameworks.items():
            controls = framework["controls"]
            passed_controls = 0
            failed = []

            for control_id, control in controls.items():
                desc = control["description"]
                sev = control.get("severity", "MEDIUM")

                if control.get("scope") == "account":
                    if self._evaluate_control(control, account_result):
                        passed_controls += 1
                    else:
                        failed.append({
                            "control_id": control_id,
                            "description": desc,
                            "severity": sev,
                            "scope": "account",
                            "instances": [],
                        })
                else:
                    offenders = [
                        r.get("instance_id", "")
                        for r in instance_results
                        if not self._evaluate_control(control, r)
                    ]
                    if offenders:
                        failed.append({
                            "control_id": control_id,
                            "description": desc,
                            "severity": sev,
                            "scope": "instance",
                            "instances": offenders,
                        })
                    else:
                        passed_controls += 1

            total = len(controls)
            out[fw_id] = {
                "framework_name": framework["name"],
                "total_controls": total,
                "passed_controls": passed_controls,
                "failed_controls": len(failed),
                "compliance_percentage": (
                    round(passed_controls / total * 100, 1)
                    if total else 100.0
                ),
                "is_compliant": len(failed) == 0,
                "failed": failed,
            }
        return out
