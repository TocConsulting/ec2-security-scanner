"""Instance Security Checker - Checks A.1 through A.8.

Covers: IMDSv2 enforcement, launch template IMDSv2, public IP,
IAM instance profile, virtualization type, multiple ENIs,
detailed monitoring, and UserData secrets detection.
"""

import base64
import logging
import re
from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")

# Secret detection patterns for UserData scanning (A.8)
SECRET_PATTERNS = [
    # AWS Access Keys
    ("AWS_ACCESS_KEY", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    # AWS Secret Keys
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)"
            r"\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
            re.IGNORECASE,
        ),
    ),
    # Passwords
    (
        "PASSWORD",
        re.compile(
            r"(?:password|passwd|DB_PASSWORD|MYSQL_ROOT_PASSWORD|"
            r"POSTGRES_PASSWORD|REDIS_PASSWORD|DATABASE_PASSWORD)"
            r"\s*[=:]\s*['\"]?\S+",
            re.IGNORECASE,
        ),
    ),
    # API Tokens/Keys
    (
        "API_TOKEN",
        re.compile(
            r"(?:api_key|api_token|auth_token|AUTH_TOKEN|API_KEY|API_TOKEN)"
            r"\s*[=:]\s*['\"]?\S+",
            re.IGNORECASE,
        ),
    ),
    # Private Keys
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
        ),
    ),
    # Database Connection Strings
    (
        "CONNECTION_STRING",
        re.compile(
            r"(?:mongodb|postgres|mysql|redis|amqp|mssql)"
            r"(?:\+\w+)?://[^:]+:[^@]+@",
            re.IGNORECASE,
        ),
    ),
    # Generic Secrets
    (
        "SECRET_KEY",
        re.compile(
            r"(?:DJANGO_SECRET_KEY|SECRET_KEY|JWT_SECRET|"
            r"ENCRYPTION_KEY|SIGNING_KEY)"
            r"\s*[=:]\s*['\"]?\S+",
            re.IGNORECASE,
        ),
    ),
    # GitHub/GitLab Tokens
    ("GITHUB_TOKEN", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("GITHUB_PAT", re.compile(r"github_pat_[a-zA-Z0-9_]{82}")),
    ("GITLAB_TOKEN", re.compile(r"glpat-[a-zA-Z0-9\-]{20,}")),
    # SaaS API Keys
    ("STRIPE_LIVE_KEY", re.compile(r"sk_live_[a-zA-Z0-9]{24,}")),
    ("STRIPE_TEST_KEY", re.compile(r"sk_test_[a-zA-Z0-9]{24,}")),
    ("SENDGRID_KEY", re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}")),
    ("SLACK_TOKEN", re.compile(r"xox[bpors]-[a-zA-Z0-9\-]+")),
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[a-zA-Z0-9\-]{40,}")),
    # OpenAI: legacy (sk-…48+), project-scoped (sk-proj-…), service accts (sk-svcacct-…)
    ("OPENAI_PROJECT_KEY", re.compile(r"sk-proj-[a-zA-Z0-9_\-]{20,}")),
    ("OPENAI_SVCACCT_KEY", re.compile(r"sk-svcacct-[a-zA-Z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9]{48,}")),
    # Cloud Credentials
    (
        "AZURE_SECRET",
        re.compile(
            r"AZURE_CLIENT_SECRET\s*[=:]\s*['\"]?\S+", re.IGNORECASE
        ),
    ),
    (
        "VAULT_TOKEN",
        re.compile(r"(?:VAULT_TOKEN\s*[=:]\s*['\"]?\S+|hvs\.[a-zA-Z0-9]{24,})"),
    ),
    # Docker/CI
    (
        "DOCKER_PASSWORD",
        re.compile(
            r"(?:DOCKER_PASSWORD|REGISTRY_PASSWORD)\s*[=:]\s*['\"]?\S+",
            re.IGNORECASE,
        ),
    ),
    ("NPM_TOKEN", re.compile(r"npm_[a-zA-Z0-9]{36}")),
    # Inline Auth
    (
        "BEARER_TOKEN",
        re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ),
    ("SSHPASS", re.compile(r"sshpass\s+-p\s+\S+")),
]


def _mask_secret(value: str) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= 12:
        return "****"
    return value[:4] + "****" + value[-4:]


class InstanceSecurityChecker(BaseChecker):
    """Checks A.1-A.8: Instance-level security configuration."""

    def check_imdsv2(self, instance: Dict) -> Dict[str, Any]:
        """A.1 - Check IMDSv2 enforcement and hop limit.

        IMDSv1 is vulnerable to SSRF attacks. HttpTokens must be 'required'.
        HttpPutResponseHopLimit > 2 weakens IMDSv2 against token forwarding
        (AWS default as of 2025 is 2 to support sidecar container patterns).
        Extracts data directly from describe_instances response (no API call).
        """
        metadata_options = instance.get("MetadataOptions", {})
        http_tokens = metadata_options.get("HttpTokens", "optional")
        http_endpoint = metadata_options.get("HttpEndpoint", "enabled")
        hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)

        return {
            "enforced": http_tokens == "required",
            "http_tokens": http_tokens,
            "http_endpoint": http_endpoint,
            "hop_limit": hop_limit,
            # AWS default is 2; flag only values > 2 as unsafe
            "hop_limit_safe": hop_limit <= 2,
        }

    def check_launch_template_imdsv2(
        self, instance: Dict, region: str
    ) -> Dict[str, Any]:
        """A.2 - Check launch template IMDSv2 enforcement.

        If instance was launched from a template, verify the template
        also enforces IMDSv2.
        """
        # Check if instance was launched from a launch template
        lt_info = instance.get("LaunchTemplate")
        if not lt_info:
            return {
                "checked": False,
                "enforced": True,  # No template = not applicable
                "template_id": None,
            }

        template_id = lt_info.get("LaunchTemplateId")
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_launch_template_versions(
                LaunchTemplateId=template_id,
                Versions=["$Default"],
            )
            versions = response.get("LaunchTemplateVersions", [])
            if not versions:
                return {
                    "checked": True,
                    "enforced": False,
                    "template_id": template_id,
                }

            lt_data = versions[0].get("LaunchTemplateData", {})
            metadata = lt_data.get("MetadataOptions", {})
            http_tokens = metadata.get("HttpTokens", "optional")

            return {
                "checked": True,
                "enforced": http_tokens == "required",
                "template_id": template_id,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "checked": False,
                "enforced": False,
                "template_id": template_id,
            })

    def check_all_launch_templates(self, region: str) -> Dict[str, Any]:
        """A.2/C.5/G.2 - Audit EVERY launch template in the region.

        describe_instances does not expose which launch template an instance
        was created from, so per-instance launch-template checks can never
        fire. AWS FSBP evaluates launch templates as standalone resources, so
        we do the same: scan the default version of every template and flag
        those that don't enforce IMDSv2, assign public IPs, or leave EBS
        unencrypted. Reported once per region (account/region scope).
        """
        result = {
            "checked": True,
            "template_count": 0,
            "imdsv2_not_enforced": [],
            "assigns_public_ip": [],
            "ebs_unencrypted": [],
        }
        try:
            ec2 = self.get_client("ec2", region)
            templates = []
            paginator = ec2.get_paginator("describe_launch_templates")
            for page in paginator.paginate():
                templates.extend(page.get("LaunchTemplates", []))
            result["template_count"] = len(templates)

            for tmpl in templates:
                tid = tmpl["LaunchTemplateId"]
                tname = tmpl.get("LaunchTemplateName", tid)
                label = f"{tname} ({tid})"
                try:
                    vresp = ec2.describe_launch_template_versions(
                        LaunchTemplateId=tid, Versions=["$Default"],
                    )
                except ClientError:
                    continue
                versions = vresp.get("LaunchTemplateVersions", [])
                if not versions:
                    continue
                data = versions[0].get("LaunchTemplateData", {})

                # IMDSv2: only flag when MetadataOptions present but not
                # required. Absent MetadataOptions inherits the instance/AMI
                # default and cannot be asserted here.
                md = data.get("MetadataOptions")
                if md is not None and md.get("HttpTokens", "optional") != "required":
                    result["imdsv2_not_enforced"].append(label)

                # Public IP on any network interface
                if any(
                    ni.get("AssociatePublicIpAddress")
                    for ni in data.get("NetworkInterfaces", [])
                ):
                    result["assigns_public_ip"].append(label)

                # Any EBS block device explicitly unencrypted
                for bdm in data.get("BlockDeviceMappings", []):
                    ebs = bdm.get("Ebs")
                    if ebs is not None and ebs.get("Encrypted") is False:
                        result["ebs_unencrypted"].append(label)
                        break

            return result
        except ClientError as e:
            return self.handle_client_error(e, result)

    def check_public_ip(self, instance: Dict) -> Dict[str, Any]:
        """A.3 - Check for public IPv4 address.

        EC2 instances should not have public IPs unless necessary.
        Extracts from describe_instances response.
        """
        public_ip = instance.get("PublicIpAddress")

        # Also check network interfaces for EIP associations
        eip_associated = False
        for eni in instance.get("NetworkInterfaces", []):
            association = eni.get("Association", {})
            if association.get("PublicIp"):
                eip_associated = True
                if not public_ip:
                    public_ip = association.get("PublicIp")

        return {
            "has_public_ip": public_ip is not None,
            "public_ip_address": public_ip,
            "eip_associated": eip_associated,
        }

    def check_iam_profile(self, instance: Dict) -> Dict[str, Any]:
        """A.4 - Check IAM instance profile attachment.

        Instances should use IAM profiles instead of long-term access keys.
        """
        iam_profile = instance.get("IamInstanceProfile")

        if iam_profile:
            profile_arn = iam_profile.get("Arn", "")
            # Extract profile name from ARN
            profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else profile_arn
            return {
                "attached": True,
                "profile_name": profile_name,
                "role_name": None,  # Would need IAM API to get role name
            }

        return {
            "attached": False,
            "profile_name": None,
            "role_name": None,
        }

    def check_virtualization(self, instance: Dict) -> Dict[str, Any]:
        """A.5 - Check virtualization type.

        Paravirtual instances have weaker security than HVM.
        """
        virt_type = instance.get("VirtualizationType", "hvm")
        return {
            "type": virt_type,
            "is_hvm": virt_type == "hvm",
        }

    def check_network_interfaces(self, instance: Dict) -> Dict[str, Any]:
        """A.6 - Check for multiple ENIs.

        Multiple ENIs may indicate dual-homed config bridging networks.
        """
        enis = instance.get("NetworkInterfaces", [])
        count = len(enis)
        return {
            "count": count,
            "has_multiple": count > 1,
        }

    def check_monitoring(self, instance: Dict) -> Dict[str, Any]:
        """A.7 - Check detailed monitoring status."""
        monitoring = instance.get("Monitoring", {})
        state = monitoring.get("State", "disabled")
        return {
            "state": state,
            "detailed_enabled": state == "enabled",
        }

    def check_userdata_secrets(
        self, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """A.8 - Scan UserData for exposed secrets.

        Retrieves UserData, base64-decodes it, and scans for
        secret patterns (AWS keys, passwords, tokens, private keys, etc.).
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_instance_attribute(
                InstanceId=instance_id, Attribute="userData"
            )

            userdata_value = response.get("UserData", {}).get("Value")
            if not userdata_value:
                return {
                    "has_userdata": False,
                    "has_secrets": False,
                    "findings": [],
                    "finding_count": 0,
                }

            # Base64 decode UserData
            try:
                decoded = base64.b64decode(userdata_value).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                return {
                    "has_userdata": True,
                    "has_secrets": False,
                    "findings": [],
                    "finding_count": 0,
                }

            # Scan for secret patterns
            findings = []
            lines = decoded.split("\n")
            for line_num, line in enumerate(lines, 1):
                for secret_type, pattern in SECRET_PATTERNS:
                    matches = pattern.findall(line)
                    for match in matches:
                        findings.append({
                            "type": secret_type,
                            "line": line_num,
                            "masked_value": _mask_secret(
                                match if isinstance(match, str) else str(match)
                            ),
                        })

            return {
                "has_userdata": True,
                "has_secrets": len(findings) > 0,
                "findings": findings,
                "finding_count": len(findings),
            }

        except ClientError as e:
            return self.handle_client_error(e, {
                "has_userdata": False,
                "has_secrets": False,
                "findings": [],
                "finding_count": 0,
            })
