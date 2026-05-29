#!/usr/bin/env python3
"""EC2 Security Scanner - Main orchestrator with multi-threading,
compliance mapping, and three-tier scanning architecture."""

import csv
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import NoCredentialsError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .compliance import ComplianceChecker
from .html_reporter import HTMLReporter
from .utils import (
    setup_logging,
    calculate_security_score,
    calculate_environment_score,
)

from .checks.instance_security import InstanceSecurityChecker
from .checks.network_security import NetworkSecurityChecker
from .checks.storage_security import StorageSecurityChecker
from .checks.access_control import AccessControlChecker
from .checks.logging_monitoring import LoggingMonitoringChecker
from .checks.patch_vulnerability import PatchVulnerabilityChecker
from .checks.network_exposure import NetworkExposureChecker
from .checks.tagging_inventory import TaggingInventoryChecker


# Result keys whose findings are account/region-wide. They are evaluated
# once per scan (environment posture) instead of being deducted from every
# instance, so a single account-level gap does not dominate the average.
ACCOUNT_CHECK_KEYS = {
    "ebs_default_encryption", "ebs_snapshot_bpa", "public_ami",
    "serial_console", "cloudtrail", "guardduty", "unused_eips",
    "vpc_bpa", "transit_gateway", "vpn_connections", "unused_sgs",
    # Launch templates are region-level resources (describe_instances does
    # not link an instance to its template), audited once per region.
    "launch_templates", "launch_template_imdsv2",
    "launch_template_public_ip", "launch_template_ebs_encryption",
}

# Result keys whose findings are shared by every instance in a VPC.
VPC_CHECK_KEYS = {
    "default_sg", "vpc_flow_logs", "nacl_admin_ports", "instance_connect",
}


class EC2SecurityScanner:
    """EC2 Security Scanner driving all security checks.

    Facade pattern: orchestrates scanning across 8 checker modules,
    manages thread pool, progress display, and report generation.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        output_dir: str = "./output",
        max_workers: int = 5,
    ):
        """Initialize the EC2 Security Scanner.

        Args:
            region: AWS region for API calls
            profile: AWS profile name
            output_dir: Directory for reports and logs
            max_workers: Maximum parallel threads for scanning
        """
        self.region = region
        self.profile = profile
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.console = Console()

        os.makedirs(output_dir, exist_ok=True)
        self.logger = setup_logging(output_dir)

        # Thread safety
        self._thread_local = threading.local()

        # Setup AWS session for main thread
        try:
            self._session = self._create_session()
            self.ec2_client = self._session.client(
                "ec2", region_name=region
            )
            self.account_id = self._get_account_id()
        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. "
                "Please configure your credentials."
            )
            raise

        # Initialize 8 checker modules with session factory
        self.instance_checker = InstanceSecurityChecker(
            self._get_thread_session
        )
        self.network_checker = NetworkSecurityChecker(
            self._get_thread_session
        )
        self.storage_checker = StorageSecurityChecker(
            self._get_thread_session
        )
        self.access_checker = AccessControlChecker(
            self._get_thread_session
        )
        self.logging_checker = LoggingMonitoringChecker(
            self._get_thread_session
        )
        self.patch_checker = PatchVulnerabilityChecker(
            self._get_thread_session
        )
        self.exposure_checker = NetworkExposureChecker(
            self._get_thread_session
        )
        self.tagging_checker = TaggingInventoryChecker(
            self._get_thread_session
        )

        # Compliance & reporting
        self.compliance_checker = ComplianceChecker()
        self.html_reporter = HTMLReporter()

        # Environment (account + VPC) posture, computed once per scan.
        self.environment_score = 100
        self.environment_findings: List[Dict[str, Any]] = []

        # Scan-level compliance (account controls counted once), computed
        # once per scan. Maps framework -> control-level results.
        self.scan_compliance: Dict[str, Dict[str, Any]] = {}

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with profile if specified."""
        if self.profile:
            return boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def _get_thread_session(self) -> boto3.Session:
        """Get or create a session for the current thread.

        Thread-local storage ensures each thread gets its own session.
        """
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = self._create_session()
        return self._thread_local.session

    def _get_account_id(self) -> str:
        """Get the AWS account ID."""
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            self.logger.debug(
                f"Could not determine AWS account ID: {e}"
            )
            return "unknown"

    # ================================================================
    # Instance Enumeration
    # ================================================================

    def get_all_instances(
        self, state_filter: str = "running",
    ) -> List[Dict[str, Any]]:
        """Retrieve all EC2 instances using pagination.

        Args:
            state_filter: Filter by state: 'running', 'stopped', or 'all'

        Returns:
            Flat list of instance dicts from describe_instances
        """
        try:
            filters = []
            if state_filter != "all":
                filters.append({
                    "Name": "instance-state-name",
                    "Values": [state_filter],
                })

            paginator = self.ec2_client.get_paginator(
                "describe_instances"
            )
            instances = []
            page_kwargs = {}
            if filters:
                page_kwargs["Filters"] = filters

            for page in paginator.paginate(**page_kwargs):
                for reservation in page.get("Reservations", []):
                    instances.extend(
                        reservation.get("Instances", [])
                    )

            self.logger.info(
                f"Found {len(instances)} EC2 instances "
                f"(filter: {state_filter}) in account {self.account_id}"
            )
            return instances
        except Exception as e:
            self.logger.error(f"Error retrieving EC2 instances: {e}")
            return []

    # ================================================================
    # Account-Level Checks (run once)
    # ================================================================

    def scan_account_security(self) -> Dict[str, Any]:
        """Run account-level checks that don't need per-instance execution.

        Covers: C.2, C.7, D.3, E.4, C.6, G.1, G.5, E.1, G.4, B.11
        """
        self.logger.info("Running account-level security checks...")
        account_results = {}

        try:
            account_results["ebs_default_encryption"] = (
                self.storage_checker.check_ebs_default_encryption(
                    self.region
                )
            )
        except Exception as e:
            self.logger.warning(
                f"EBS default encryption check failed: {e}"
            )
            account_results["ebs_default_encryption"] = {"enabled": False}

        try:
            account_results["ebs_snapshot_bpa"] = (
                self.storage_checker.check_ebs_snapshot_bpa(self.region)
            )
        except Exception as e:
            self.logger.warning(
                f"EBS snapshot BPA check failed: {e}"
            )
            account_results["ebs_snapshot_bpa"] = {
                "state": "unblocked", "blocked": False,
                "managed_by": "account",
            }

        try:
            account_results["serial_console_access"] = (
                self.access_checker.check_serial_console(self.region)
            )
        except Exception as e:
            self.logger.warning(f"Serial console check failed: {e}")
            account_results["serial_console_access"] = {"enabled": False}

        try:
            account_results["guardduty_ec2_protection"] = (
                self.logging_checker.check_guardduty(self.region)
            )
        except Exception as e:
            self.logger.warning(f"GuardDuty check failed: {e}")
            account_results["guardduty_ec2_protection"] = {
                "enabled": False,
                "runtime_monitoring": False,
                "ec2_agent_management": False,
                "ebs_malware_protection": False,
            }

        try:
            account_results["cloudtrail"] = (
                self.logging_checker.check_cloudtrail(self.region)
            )
        except Exception as e:
            self.logger.warning(f"CloudTrail check failed: {e}")
            account_results["cloudtrail"] = {
                "enabled": False,
                "active_trails": 0,
                "multi_region": False,
                "management_events": False,
            }

        try:
            account_results["public_amis"] = (
                self.storage_checker.check_public_ami(self.region)
            )
        except Exception as e:
            self.logger.warning(f"Public AMI check failed: {e}")
            account_results["public_amis"] = {
                "has_public_amis": False, "public_ami_ids": [],
            }

        try:
            account_results["unused_eips"] = (
                self.exposure_checker.check_unused_eips(self.region)
            )
        except Exception as e:
            self.logger.warning(f"Unused EIPs check failed: {e}")
            account_results["unused_eips"] = {
                "count": 0, "eip_allocations": [],
            }

        try:
            # H.3 unused SGs is an account-wide check; run once.
            account_results["unused_sgs"] = (
                self.tagging_checker.check_unused_sgs([], self.region)
            )
        except Exception as e:
            self.logger.warning(f"Unused SGs check failed: {e}")
            account_results["unused_sgs"] = {
                "count": 0, "unused_sg_ids": [],
            }

        try:
            account_results["transit_gateway"] = (
                self.exposure_checker.check_transit_gateway(self.region)
            )
        except Exception as e:
            self.logger.warning(
                f"Transit Gateway check failed: {e}"
            )
            account_results["transit_gateway"] = {
                "auto_accept_enabled": False, "tgw_ids": [],
            }

        try:
            account_results["vpc_bpa"] = (
                self.exposure_checker.check_vpc_bpa(self.region)
            )
        except Exception as e:
            self.logger.warning(f"VPC BPA check failed: {e}")
            account_results["vpc_bpa"] = {"blocks_igw": False}

        try:
            account_results["vpn_connections"] = (
                self.network_checker.check_vpn_ikev2(self.region)
            )
        except Exception as e:
            self.logger.warning(f"VPN IKEv2 check failed: {e}")
            account_results["vpn_connections"] = {
                "all_ikev2": True,
                "non_ikev2_connections": [],
            }

        try:
            # Region-level audit of ALL launch templates (describe_instances
            # cannot link an instance to its template, so this is the only
            # way the launch-template checks can actually fire).
            account_results["launch_templates"] = (
                self.instance_checker.check_all_launch_templates(self.region)
            )
        except Exception as e:
            self.logger.warning(f"Launch template audit failed: {e}")
            account_results["launch_templates"] = {
                "checked": False, "template_count": 0,
                "imdsv2_not_enforced": [], "assigns_public_ip": [],
                "ebs_unencrypted": [],
            }

        return account_results

    # ================================================================
    # VPC-Level Checks (run once per unique VPC)
    # ================================================================

    def scan_vpc_security(
        self, vpc_ids: List[str],
    ) -> Dict[str, Dict[str, Any]]:
        """Run VPC-level checks once per unique VPC.

        Covers: B.1 (default SG), B.6 (flow logs), B.7 (NACLs),
                G.3 (subnet auto-assign)
        """
        self.logger.info(
            f"Running VPC-level checks for {len(vpc_ids)} VPCs..."
        )
        vpc_results = {}

        for vpc_id in vpc_ids:
            vpc_checks = {}

            try:
                vpc_checks["default_sg"] = (
                    self.network_checker.check_default_sg(
                        vpc_id, self.region
                    )
                )
            except Exception as e:
                self.logger.warning(
                    f"Default SG check failed for {vpc_id}: {e}"
                )
                vpc_checks["default_sg"] = {
                    "has_rules": False,
                    "inbound_rule_count": 0,
                    "outbound_rule_count": 0,
                }

            try:
                vpc_checks["vpc_flow_logs"] = (
                    self.network_checker.check_vpc_flow_logs(
                        vpc_id, self.region
                    )
                )
            except Exception as e:
                self.logger.warning(
                    f"Flow logs check failed for {vpc_id}: {e}"
                )
                vpc_checks["vpc_flow_logs"] = {
                    "enabled": False, "flow_log_ids": [],
                }

            try:
                vpc_checks["nacl_admin_ports"] = (
                    self.network_checker.check_nacl_admin_ports(
                        vpc_id, self.region
                    )
                )
            except Exception as e:
                self.logger.warning(
                    f"NACL check failed for {vpc_id}: {e}"
                )
                vpc_checks["nacl_admin_ports"] = {
                    "open_to_world": False, "offending_nacls": [],
                }

            try:
                vpc_checks["instance_connect"] = (
                    self.access_checker.check_instance_connect(
                        vpc_id, self.region
                    )
                )
            except Exception as e:
                self.logger.warning(
                    f"Instance Connect check failed for {vpc_id}: {e}"
                )
                vpc_checks["instance_connect"] = {
                    "endpoints_configured": False,
                }

            vpc_results[vpc_id] = vpc_checks

        return vpc_results

    # ================================================================
    # Instance-Level Scanning
    # ================================================================

    def scan_instance(
        self,
        instance: Dict[str, Any],
        account_security: Dict[str, Any],
        vpc_security: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run all checks for one instance.

        Builds the checks dict, computes issues, score, and compliance.
        """
        instance_id = instance["InstanceId"]
        region = self.region
        vpc_id = instance.get("VpcId", "")
        subnet_id = instance.get("SubnetId", "")

        try:
            # === Instance metadata ===
            tags = instance.get("Tags", [])
            name_tag = next(
                (t["Value"] for t in tags if t["Key"] == "Name"),
                "",
            )

            result = {
                "instance_id": instance_id,
                "instance_type": instance.get("InstanceType", ""),
                "region": region,
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "state": instance.get("State", {}).get("Name", ""),
                "launch_time": str(instance.get("LaunchTime", "")),
                "platform": instance.get("PlatformDetails", "Linux/UNIX"),
                "name": name_tag,
            }

            # === A. Instance Security Checks ===
            result["imdsv2"] = (
                self.instance_checker.check_imdsv2(instance)
            )
            result["launch_template_imdsv2"] = (
                self.instance_checker.check_launch_template_imdsv2(
                    instance, region
                )
            )
            result["public_ip"] = (
                self.instance_checker.check_public_ip(instance)
            )
            result["iam_profile"] = (
                self.instance_checker.check_iam_profile(instance)
            )
            result["virtualization"] = (
                self.instance_checker.check_virtualization(instance)
            )
            result["network_interfaces"] = (
                self.instance_checker.check_network_interfaces(instance)
            )
            result["monitoring"] = (
                self.instance_checker.check_monitoring(instance)
            )
            result["userdata_secrets"] = (
                self.instance_checker.check_userdata_secrets(
                    instance_id, region
                )
            )

            # === B. Network Security Checks ===
            sg_ids = [
                sg["GroupId"]
                for sg in instance.get("SecurityGroups", [])
            ]

            # Fetch SG rules ONCE, reuse across B.2-B.5, B.9-B.10
            sg_rules = (
                self.network_checker._get_security_group_rules(
                    sg_ids, region
                )
            )

            result["sg_ssh"] = self.network_checker.check_sg_ssh(
                sg_ids, region, sg_rules
            )
            result["sg_rdp"] = self.network_checker.check_sg_rdp(
                sg_ids, region, sg_rules
            )
            result["sg_high_risk_ports"] = (
                self.network_checker.check_sg_high_risk_ports(
                    sg_ids, region, sg_rules
                )
            )
            result["sg_remote_admin"] = (
                self.network_checker.check_sg_remote_admin(
                    sg_ids, region, sg_rules
                )
            )
            result["sg_egress"] = self.network_checker.check_sg_egress(
                sg_ids, region, sg_rules
            )
            result["sg_authorized_ports"] = (
                self.network_checker.check_sg_authorized_ports(
                    sg_ids, region, sg_rules
                )
            )
            result["source_dest_check"] = (
                self.network_checker.check_source_dest(instance)
            )

            # Merge VPC-level results
            vpc_checks = vpc_security.get(vpc_id, {})
            result["default_sg"] = vpc_checks.get("default_sg", {
                "has_rules": False,
                "inbound_rule_count": 0,
                "outbound_rule_count": 0,
            })
            result["vpc_flow_logs"] = vpc_checks.get("vpc_flow_logs", {
                "enabled": False, "flow_log_ids": [],
            })
            result["nacl_admin_ports"] = vpc_checks.get(
                "nacl_admin_ports", {
                    "open_to_world": False, "offending_nacls": [],
                }
            )
            result["instance_connect"] = vpc_checks.get(
                "instance_connect",
                {"endpoints_configured": False},
            )

            # === C. Storage Security Checks ===
            result["ebs_encryption"] = (
                self.storage_checker.check_ebs_encryption(
                    instance_id, region
                )
            )
            result["ebs_snapshot_public"] = (
                self.storage_checker.check_ebs_snapshot_public(
                    instance_id, region
                )
            )
            result["ebs_backup"] = (
                self.storage_checker.check_ebs_backup(
                    instance_id, region, self.account_id
                )
            )
            result["launch_template_ebs_encryption"] = (
                self.storage_checker.check_launch_template_ebs(
                    instance, region
                )
            )

            # Merge account-level storage results
            result["ebs_default_encryption"] = (
                account_security.get(
                    "ebs_default_encryption", {"enabled": False}
                )
            )
            result["ebs_snapshot_bpa"] = account_security.get(
                "ebs_snapshot_bpa",
                {"state": "unblocked", "blocked": False,
                 "managed_by": "account"},
            )
            result["public_ami"] = account_security.get(
                "public_amis",
                {"has_public_amis": False, "public_ami_ids": []},
            )

            # === D. Access Control Checks ===
            result["iam_role"] = self.access_checker.check_iam_role(
                instance, region
            )
            result["key_pair"] = self.access_checker.check_key_pair(
                instance, instance_id, region
            )
            result["serial_console"] = account_security.get(
                "serial_console_access", {"enabled": False}
            )

            # === E. Logging & Monitoring Checks ===
            result["cloudtrail"] = account_security.get(
                "cloudtrail",
                {"enabled": False, "active_trails": 0},
            )
            result["cloudwatch_alarms"] = (
                self.logging_checker.check_cloudwatch_alarms(
                    instance_id, region
                )
            )
            result["ssm_managed"] = (
                self.logging_checker.check_ssm_managed(
                    instance_id, region
                )
            )
            result["guardduty"] = account_security.get(
                "guardduty_ec2_protection",
                {
                    "enabled": False,
                    "runtime_monitoring": False,
                    "ec2_agent_management": False,
                    "ebs_malware_protection": False,
                },
            )

            # === F. Patch & Vulnerability Checks ===
            result["ssm_patch"] = (
                self.patch_checker.check_ssm_patch_compliance(
                    instance_id, region
                )
            )
            result["ami_age"] = self.patch_checker.check_ami_age(
                instance.get("ImageId", ""), region
            )
            result["inspector_v2"] = (
                self.patch_checker.check_inspector_v2(
                    instance_id, region
                )
            )

            # === G. Network Exposure Checks ===
            result["unused_eips"] = account_security.get(
                "unused_eips",
                {"count": 0, "eip_allocations": []},
            )
            result["launch_template_public_ip"] = (
                self.exposure_checker.check_launch_template_public_ip(
                    instance, region
                )
            )
            result["subnet_auto_assign_public_ip"] = (
                self.exposure_checker.check_subnet_auto_assign(
                    subnet_id, region
                )
                if subnet_id
                else {"enabled": False}
            )
            result["vpc_bpa"] = account_security.get(
                "vpc_bpa", {"blocks_igw": False}
            )
            result["transit_gateway"] = account_security.get(
                "transit_gateway",
                {"auto_accept_enabled": False, "tgw_ids": []},
            )
            result["vpn_connections"] = account_security.get(
                "vpn_connections",
                {"all_ikev2": True, "non_ikev2_connections": []},
            )

            # === H. Tagging & Inventory Checks ===
            result["tags"] = (
                self.tagging_checker.check_required_tags(instance)
            )
            result["stopped_instance"] = (
                self.tagging_checker.check_stopped_instance(instance)
            )
            result["unused_sgs"] = account_security.get(
                "unused_sgs", {"count": 0, "unused_sg_ids": []}
            )

            # === Computed fields ===
            # Only instance-specific issues are attributed to the instance;
            # account/VPC-wide findings live in environment_findings so they
            # are not multiplied across every instance.
            result["issues"] = self._analyze_instance_issues(result)
            result["issue_count"] = len(result["issues"])
            result["has_critical_severity"] = any(
                i["severity"] == "CRITICAL" for i in result["issues"]
            )
            result["has_high_severity"] = any(
                i["severity"] == "HIGH" for i in result["issues"]
            )
            result["has_medium_severity"] = any(
                i["severity"] == "MEDIUM" for i in result["issues"]
            )
            result["security_score"] = calculate_security_score(result)
            result["compliance_status"] = (
                self.compliance_checker.check_instance_compliance(result)
            )
            result["scan_error"] = False

            return result

        except Exception as e:
            self.logger.error(
                f"Error scanning instance {instance_id}: {e}"
            )
            return self._error_result(instance, str(e))

    def scan_all_instances(
        self,
        instances: Optional[List[Dict]] = None,
        state_filter: str = "running",
    ) -> List[Dict[str, Any]]:
        """Scan all instances in parallel with progress display.

        Args:
            instances: Pre-fetched instance list, or None to auto-fetch
            state_filter: Instance state filter (if auto-fetching)

        Returns:
            List of result dicts sorted by security_score ascending
        """
        if instances is None:
            instances = self.get_all_instances(state_filter)

        if not instances:
            self.logger.warning("No instances found to scan")
            return []

        # Collect unique VPC IDs
        vpc_ids = list(set(
            inst.get("VpcId", "")
            for inst in instances
            if inst.get("VpcId")
        ))

        # Run account-level checks (sequential, main thread)
        account_security = self.scan_account_security()

        # Run VPC-level checks (sequential, main thread)
        vpc_security = self.scan_vpc_security(vpc_ids)

        # Score account + VPC posture ONCE (not per instance).
        self.environment_score = calculate_environment_score(
            account_security, vpc_security
        )
        self.environment_findings = self._analyze_environment_issues(
            account_security, vpc_security
        )

        # Build the account-level result used to evaluate account/VPC
        # compliance controls exactly once for the whole scan.
        self._compliance_account_result = (
            self._build_compliance_account_result(
                account_security, vpc_security
            )
        )

        # Parallel instance scanning
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                f"Scanning {len(instances)} instances...",
                total=len(instances),
            )

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                future_to_instance = {
                    executor.submit(
                        self.scan_instance,
                        inst,
                        account_security,
                        vpc_security,
                    ): inst
                    for inst in instances
                }

                for future in as_completed(future_to_instance):
                    instance = future_to_instance[future]
                    instance_id = instance.get("InstanceId", "unknown")
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        self.logger.error(
                            f"Scan failed for {instance_id}: {e}"
                        )
                        results.append(
                            self._error_result(instance, str(e))
                        )
                    progress.advance(task)

        # Sort by security score ascending (worst first)
        results.sort(
            key=lambda r: (
                r.get("security_score") if r.get("security_score")
                is not None else 101
            )
        )

        # Evaluate compliance at scan level: account controls counted once,
        # instance controls counted once each (failing if any instance fails).
        valid_results = [
            r for r in results if not r.get("scan_error", False)
        ]
        self.scan_compliance = self.compliance_checker.evaluate_scan(
            self._compliance_account_result, valid_results
        )

        return results

    def _build_compliance_account_result(
        self,
        account_security: Dict[str, Any],
        vpc_security: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build the single result dict used to evaluate account/VPC controls.

        Account checks map to their per-instance result key names; VPC checks
        are aggregated worst-case across all VPCs (fail if any VPC fails), so
        a shared finding counts once for the whole scan.
        """
        result = {
            "ebs_default_encryption": account_security.get(
                "ebs_default_encryption", {"enabled": False}),
            "ebs_snapshot_bpa": account_security.get(
                "ebs_snapshot_bpa", {"blocked": False}),
            "public_ami": account_security.get(
                "public_amis", {"has_public_amis": False}),
            "serial_console": account_security.get(
                "serial_console_access", {"enabled": False}),
            "cloudtrail": account_security.get(
                "cloudtrail", {"enabled": False}),
            "guardduty": account_security.get(
                "guardduty_ec2_protection", {"enabled": False}),
            "unused_eips": account_security.get(
                "unused_eips", {"count": 0}),
            "vpc_bpa": account_security.get(
                "vpc_bpa", {"blocks_igw": False}),
            "transit_gateway": account_security.get(
                "transit_gateway", {"auto_accept_enabled": False}),
            "vpn_connections": account_security.get(
                "vpn_connections", {"all_ikev2": True}),
            "unused_sgs": account_security.get(
                "unused_sgs", {"count": 0}),
        }

        # Aggregate VPC-level state worst-case across all VPCs.
        def any_vpc(key, subkey, want_true):
            for vpc in vpc_security.values():
                chk = vpc.get(key, {})
                if not isinstance(chk, dict) or "error" in chk:
                    continue
                if bool(chk.get(subkey, not want_true)) == want_true:
                    return True
            return False

        result["default_sg"] = {
            "has_rules": any_vpc("default_sg", "has_rules", True)
        }
        result["vpc_flow_logs"] = {
            "enabled": not any_vpc("vpc_flow_logs", "enabled", False)
        }
        result["nacl_admin_ports"] = {
            "open_to_world": any_vpc(
                "nacl_admin_ports", "open_to_world", True)
        }
        result["instance_connect"] = {
            "endpoints_configured": not any_vpc(
                "instance_connect", "endpoints_configured", False)
        }

        # Launch-template audit -> representative per-key state so the
        # standalone FSBP launch-template controls evaluate once at region
        # level against real templates.
        lt = account_security.get("launch_templates", {})
        result["launch_template_imdsv2"] = {
            "checked": True,
            "enforced": not lt.get("imdsv2_not_enforced"),
        }
        result["launch_template_public_ip"] = {
            "assigns_public_ip": bool(lt.get("assigns_public_ip")),
        }
        result["launch_template_ebs_encryption"] = {
            "checked": True,
            "all_encrypted": not lt.get("ebs_unencrypted"),
        }
        return result

    # ================================================================
    # Issue Analysis
    # ================================================================

    def _analyze_instance_issues(
        self, checks: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate the instance-specific issue list from a result dict.

        Account- and VPC-wide findings are intentionally excluded here —
        see :meth:`_analyze_environment_issues` — so they are reported once
        rather than once per instance.
        """
        issues = []

        def add(severity, issue_type, description, recommendation):
            issues.append({
                "severity": severity,
                "issue_type": issue_type,
                "description": description,
                "recommendation": recommendation,
            })

        # A.1 IMDSv2
        if not checks.get("imdsv2", {}).get("enforced", False):
            add("HIGH", "IMDSV2_NOT_ENFORCED",
                "Instance does not enforce IMDSv2 (HttpTokens=optional). "
                "IMDSv1 is vulnerable to SSRF attacks.",
                "Set HttpTokens to 'required' via modify-instance-metadata-options")

        # A.2 Launch Template IMDSv2 is audited at region level
        # (_analyze_environment_issues), since describe_instances does not
        # link an instance to its launch template.

        # A.3 Public IP
        if checks.get("public_ip", {}).get("has_public_ip", False):
            ip = checks["public_ip"].get("public_ip_address", "")
            add("HIGH", "PUBLIC_IP_ASSIGNED",
                f"Instance has public IPv4 address: {ip}",
                "Remove public IP or use private subnet with NAT gateway")

        # A.4 IAM Profile
        if not checks.get("iam_profile", {}).get("attached", False):
            add("MEDIUM", "NO_IAM_PROFILE",
                "No IAM instance profile attached.",
                "Attach an IAM instance profile with least privilege role")

        # A.5 Paravirtual
        if not checks.get("virtualization", {}).get("is_hvm", True):
            add("MEDIUM", "PARAVIRTUAL_INSTANCE",
                "Instance uses paravirtual virtualization.",
                "Migrate to HVM instance type for better security")

        # A.6 Multiple ENIs
        if checks.get("network_interfaces", {}).get("has_multiple", False):
            add("LOW", "MULTIPLE_ENIS",
                f"Instance has {checks['network_interfaces']['count']} ENIs attached.",
                "Review if multiple ENIs are necessary")

        # A.7 Monitoring
        if not checks.get("monitoring", {}).get("detailed_enabled", False):
            add("MEDIUM", "DETAILED_MONITORING_DISABLED",
                "Detailed monitoring is not enabled.",
                "Enable detailed monitoring for 1-minute CloudWatch metrics")

        # A.1 IMDSv2 HopLimit (> 2 weakens token protection)
        imds = checks.get("imdsv2", {})
        if (imds.get("enforced", False)
                and not imds.get("hop_limit_safe", True)):
            hl = imds.get("hop_limit", 1)
            add("LOW", "IMDSV2_HOP_LIMIT_TOO_HIGH",
                f"IMDSv2 HttpPutResponseHopLimit is {hl} (max recommended: 2).",
                "Set HttpPutResponseHopLimit to 1 or 2 to limit token forwarding")

        # A.8 UserData Secrets
        ud = checks.get("userdata_secrets", {})
        if ud.get("has_secrets", False):
            add("CRITICAL", "USERDATA_SECRETS_EXPOSED",
                f"Found {ud.get('finding_count', 0)} hardcoded secret(s) in UserData.",
                "Replace with Secrets Manager, SSM Parameter Store, or IAM profiles")

        # B.2 SSH
        if checks.get("sg_ssh", {}).get("open_to_world", False):
            add("HIGH", "SSH_OPEN_TO_WORLD",
                "Security group allows SSH (port 22) from 0.0.0.0/0.",
                "Restrict SSH to specific IP ranges or use SSM Session Manager")

        # B.3 RDP
        if checks.get("sg_rdp", {}).get("open_to_world", False):
            add("HIGH", "RDP_OPEN_TO_WORLD",
                "Security group allows RDP (port 3389) from 0.0.0.0/0.",
                "Restrict RDP to specific IP ranges or use VPN")

        # B.4 High-risk ports
        hrp = checks.get("sg_high_risk_ports", {})
        if hrp.get("has_violations", False):
            ports = hrp.get("open_ports", [])
            add("CRITICAL", "HIGH_RISK_PORTS_OPEN",
                f"High-risk ports open to world: {ports}",
                "Restrict access to specific IP ranges")

        # B.5 Remote admin
        ra = checks.get("sg_remote_admin", {})
        if ra.get("open_to_world", False):
            add("HIGH", "REMOTE_ADMIN_PORTS_OPEN",
                f"Remote admin ports open to world: {ra.get('open_ports', [])}",
                "Use SSM, VPN, or IP whitelisting for admin access")

        # B.8 Source/Dest Check
        if not checks.get("source_dest_check", {}).get("enabled", True):
            add("MEDIUM", "SOURCE_DEST_CHECK_DISABLED",
                "Source/destination check is disabled.",
                "Enable unless instance is NAT/VPN/firewall")

        # B.9 SG Egress — opinionated hardening nudge (LOW), not an FSBP
        # requirement. AWS attaches an allow-all egress rule to every SG by
        # default, so this would otherwise flag nearly every instance.
        if checks.get("sg_egress", {}).get("unrestricted", False):
            add("LOW", "UNRESTRICTED_EGRESS",
                "Security group keeps unrestricted outbound traffic "
                "(AWS default). Restricting egress is defense-in-depth, "
                "not an FSBP requirement.",
                "Optionally restrict egress to necessary destinations "
                "and ports for data-exfiltration defense-in-depth")

        # B.10 Authorized Ports
        ap = checks.get("sg_authorized_ports", {})
        if ap.get("has_violations", False):
            add("HIGH", "UNAUTHORIZED_PORTS_OPEN",
                f"Unauthorized ports open to world: {ap.get('unauthorized_ports', [])}",
                "Only allow ports 80 and 443 open to the internet")

        # C.1 EBS Encryption
        ebs = checks.get("ebs_encryption", {})
        if not ebs.get("all_encrypted", True):
            add("MEDIUM", "EBS_NOT_ENCRYPTED",
                f"Unencrypted EBS volumes: {ebs.get('unencrypted_volumes', [])}",
                "Enable encryption on all EBS volumes")

        # C.3 Public Snapshots
        snap = checks.get("ebs_snapshot_public", {})
        if snap.get("has_public_snapshots", False):
            add("CRITICAL", "PUBLIC_EBS_SNAPSHOTS",
                f"Public EBS snapshots: {snap.get('public_snapshot_ids', [])}",
                "Remove public access from EBS snapshots")

        # C.4 Backup
        if not checks.get("ebs_backup", {}).get("covered", False):
            add("LOW", "NO_EBS_BACKUP",
                "EBS volumes are not covered by a backup plan.",
                "Add volumes to an AWS Backup plan")

        # C.5 Launch Template EBS encryption is audited at region level
        # (_analyze_environment_issues).

        # D.1 IAM Role
        iam = checks.get("iam_role", {})
        if iam.get("has_admin_access", False) or iam.get("has_wildcard_actions", False):
            add("HIGH", "IAM_ADMIN_ACCESS",
                f"IAM role has admin/wildcard access: {iam.get('overly_permissive_policies', [])}",
                "Apply least privilege principle to IAM roles")

        # D.2 Key Pair
        kp = checks.get("key_pair", {})
        if kp.get("has_key_pair", False) and not kp.get("ssm_managed", False):
            add("MEDIUM", "KEY_PAIR_WITHOUT_SSM",
                f"Instance uses key pair '{kp.get('key_name')}' without SSM management.",
                "Use SSM Session Manager or Instance Connect instead")

        # E.2 CloudWatch
        if not checks.get("cloudwatch_alarms", {}).get("has_alarms", False):
            add("MEDIUM", "NO_CLOUDWATCH_ALARMS",
                "No CloudWatch alarms configured for instance.",
                "Add alarms for CPU, status checks, and other metrics")

        # E.3 SSM
        if not checks.get("ssm_managed", {}).get("is_managed", False):
            add("MEDIUM", "NOT_SSM_MANAGED",
                "Instance is not managed by Systems Manager.",
                "Install SSM agent and register with SSM")

        # F.1 SSM Patch
        patch = checks.get("ssm_patch", {})
        if not patch.get("is_compliant", True):
            add("HIGH", "SSM_PATCH_NONCOMPLIANT",
                f"Missing patches: {patch.get('missing_count', 0)}, "
                f"Failed: {patch.get('failed_count', 0)}",
                "Apply pending patches via SSM Patch Manager")

        # F.2 AMI Age
        if checks.get("ami_age", {}).get("is_stale", False):
            add("MEDIUM", "STALE_AMI",
                f"AMI is {checks['ami_age'].get('age_days', 0)} days old (threshold: 180).",
                "Update to a recent AMI with latest security patches")

        # F.3 Inspector v2
        insp = checks.get("inspector_v2", {})
        if not insp.get("ec2_scanning_enabled", False):
            add("HIGH", "INSPECTOR_V2_DISABLED",
                "Amazon Inspector v2 EC2 scanning is not enabled.",
                "Enable Inspector v2 for automated vulnerability scanning")
        elif insp.get("critical_findings", 0) > 0:
            add("HIGH", "INSPECTOR_CRITICAL_FINDINGS",
                f"Inspector v2: {insp['critical_findings']} CRITICAL findings.",
                "Remediate critical vulnerabilities immediately")

        # G.2 Launch Template public IP is audited at region level
        # (_analyze_environment_issues).

        # G.3 Subnet Auto-Assign
        if checks.get("subnet_auto_assign_public_ip", {}).get("enabled", False):
            add("MEDIUM", "SUBNET_AUTO_ASSIGN_PUBLIC_IP",
                "Subnet auto-assigns public IP addresses.",
                "Disable MapPublicIpOnLaunch on subnet")

        # H.1 Tags
        tags = checks.get("tags", {})
        if not tags.get("has_required_tags", True):
            add("LOW", "MISSING_REQUIRED_TAGS",
                f"Missing tags: {tags.get('missing_tags', [])}",
                "Add required tags (Name, Environment, Owner)")

        # H.2 Stopped Instance
        si = checks.get("stopped_instance", {})
        if si.get("exceeds_threshold", False):
            add("MEDIUM", "STOPPED_INSTANCE_STALE",
                f"Instance stopped for {si.get('stopped_days')} days.",
                "Terminate or document reason for keeping stopped instance")

        # Surface instance-level checks that errored (e.g. AccessDenied) so
        # the user knows the finding is "not detected" rather than "confirmed
        # clean". Account/VPC checks are handled in the environment analyzer.
        skip_meta_keys = {
            "instance_id", "instance_type", "region", "vpc_id",
            "subnet_id", "state", "launch_time", "platform", "name",
            "issues", "issue_count", "has_critical_severity",
            "has_high_severity", "has_medium_severity",
            "security_score", "compliance_status", "scan_error",
            "error_message",
        }
        for check_name, check_val in checks.items():
            if check_name in skip_meta_keys:
                continue
            if check_name in ACCOUNT_CHECK_KEYS or check_name in VPC_CHECK_KEYS:
                continue
            if isinstance(check_val, dict) and check_val.get("error"):
                add("ERROR", "CHECK_FAILED",
                    f"Check '{check_name}' could not run: "
                    f"{check_val['error']}",
                    "Grant the scanning role the missing permission "
                    "or scope the scan to instances/regions you can "
                    "audit.")

        return issues

    def _analyze_environment_issues(
        self,
        account_security: Dict[str, Any],
        vpc_security: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate account- and VPC-wide findings, reported once per scan.

        These mirror the deductions in :func:`calculate_environment_score`.
        VPC-level findings are aggregated across VPCs and reported once,
        listing the affected VPC IDs.
        """
        issues = []

        def add(severity, issue_type, description, recommendation):
            issues.append({
                "severity": severity,
                "issue_type": issue_type,
                "description": description,
                "recommendation": recommendation,
            })

        def acc(name, key, default=False):
            v = account_security.get(name, {})
            if isinstance(v, dict) and "error" not in v:
                return v.get(key, default)
            return default

        # === Account-wide findings ===
        if acc("public_amis", "has_public_amis"):
            add("CRITICAL", "PUBLIC_AMI_SHARING",
                "Account has publicly shared AMIs: "
                f"{account_security.get('public_amis', {}).get('public_ami_ids', [])}",
                "Make AMIs private unless intentionally public")

        snap_bpa = account_security.get("ebs_snapshot_bpa", {})
        if isinstance(snap_bpa, dict) and "error" not in snap_bpa \
                and not snap_bpa.get("blocked", False):
            state = snap_bpa.get("state", "unblocked")
            add("HIGH", "EBS_SNAPSHOT_BPA_NOT_ENABLED",
                f"Account-level EBS Snapshot Block Public Access is "
                f"'{state}' (must be 'block-all-sharing'). [FSBP EC2.182]",
                "Enable EBS Snapshot Block Public Access: "
                "ec2.enable_snapshot_block_public_access("
                "State='block-all-sharing')")

        if acc("transit_gateway", "auto_accept_enabled"):
            add("HIGH", "TGW_AUTO_ACCEPT",
                "Transit Gateway auto-accepts VPC attachments.",
                "Disable auto-accept on Transit Gateways")

        if not acc("guardduty_ec2_protection", "enabled"):
            add("HIGH", "NO_GUARDDUTY",
                "GuardDuty is not enabled for EC2 protection.",
                "Enable GuardDuty with EC2 runtime monitoring")

        if not acc("vpc_bpa", "blocks_igw"):
            add("HIGH", "VPC_BPA_NOT_ENABLED",
                "VPC Block Public Access is not blocking IGW traffic.",
                "Enable VPC Block Public Access")

        if not acc("cloudtrail", "enabled"):
            add("HIGH", "NO_CLOUDTRAIL",
                "No active CloudTrail trail found.",
                "Enable CloudTrail for EC2 API logging")

        vpn = account_security.get("vpn_connections", {})
        if isinstance(vpn, dict) and "error" not in vpn \
                and not vpn.get("all_ikev2", True):
            add("HIGH", "VPN_NOT_IKEV2",
                "VPN connections permitting IKEv1: "
                f"{vpn.get('non_ikev2_connections', [])}. [FSBP EC2.183]",
                "Modify VPN tunnel options to use IKEv2 only")

        if not acc("ebs_default_encryption", "enabled"):
            add("MEDIUM", "EBS_DEFAULT_ENCRYPTION_DISABLED",
                "EBS default encryption is not enabled.",
                "Enable EBS encryption by default in account settings")

        if acc("serial_console_access", "enabled"):
            add("MEDIUM", "SERIAL_CONSOLE_ENABLED",
                "EC2 serial console access is enabled at account level.",
                "Disable serial console access unless needed")

        if acc("unused_eips", "count", 0) > 0:
            add("LOW", "UNUSED_ELASTIC_IPS",
                "Unused Elastic IPs: "
                f"{account_security.get('unused_eips', {}).get('eip_allocations', [])}",
                "Release unused Elastic IP addresses")

        if acc("unused_sgs", "count", 0) > 0:
            add("MEDIUM", "UNUSED_SECURITY_GROUPS",
                "Unused security groups: "
                f"{account_security.get('unused_sgs', {}).get('unused_sg_ids', [])}",
                "Remove unused security groups")

        # === VPC-level findings (aggregated across VPCs) ===
        def affected_vpcs(key, subkey, want_true):
            out = []
            for vpc_id, vpc in vpc_security.items():
                chk = vpc.get(key, {})
                if not isinstance(chk, dict) or "error" in chk:
                    continue
                val = chk.get(subkey, not want_true)
                if bool(val) == want_true:
                    out.append(vpc_id)
            return out

        bad = affected_vpcs("default_sg", "has_rules", True)
        if bad:
            add("HIGH", "DEFAULT_SG_HAS_RULES",
                f"VPC default security group allows traffic in: {bad}",
                "Remove all rules from the default security group")

        bad = affected_vpcs("vpc_flow_logs", "enabled", False)
        if bad:
            add("MEDIUM", "NO_VPC_FLOW_LOGS",
                f"VPC flow logging is not enabled in: {bad}",
                "Enable VPC flow logs for network traffic analysis")

        bad = affected_vpcs("nacl_admin_ports", "open_to_world", True)
        if bad:
            add("MEDIUM", "NACL_ADMIN_PORTS_OPEN",
                f"Network ACLs allow admin ports from 0.0.0.0/0 in: {bad}",
                "Restrict NACL entries for ports 22 and 3389")

        bad = affected_vpcs("instance_connect", "endpoints_configured", False)
        if bad:
            add("LOW", "NO_INSTANCE_CONNECT_ENDPOINT",
                f"No EC2 Instance Connect Endpoint in VPC(s): {bad}",
                "Create an Instance Connect Endpoint for secure SSH access")

        # === Launch-template audit (region-level) ===
        lt = account_security.get("launch_templates", {})
        if isinstance(lt, dict) and "error" not in lt:
            if lt.get("imdsv2_not_enforced"):
                add("HIGH", "LAUNCH_TEMPLATE_IMDSV2_NOT_ENFORCED",
                    "Launch templates do not enforce IMDSv2: "
                    f"{lt['imdsv2_not_enforced']}",
                    "Set MetadataOptions.HttpTokens='required' in the "
                    "launch template")
            if lt.get("assigns_public_ip"):
                add("HIGH", "LAUNCH_TEMPLATE_PUBLIC_IP",
                    "Launch templates assign public IPs: "
                    f"{lt['assigns_public_ip']}",
                    "Set AssociatePublicIpAddress=false in the launch "
                    "template network interfaces")
            if lt.get("ebs_unencrypted"):
                add("MEDIUM", "LAUNCH_TEMPLATE_EBS_NOT_ENCRYPTED",
                    "Launch templates have unencrypted EBS mappings: "
                    f"{lt['ebs_unencrypted']}",
                    "Set Ebs.Encrypted=true in launch template block "
                    "device mappings")

        # Surface account/VPC checks that errored (e.g. AccessDenied).
        for check_name, check_val in account_security.items():
            if isinstance(check_val, dict) and check_val.get("error"):
                add("ERROR", "CHECK_FAILED",
                    f"Account check '{check_name}' could not run: "
                    f"{check_val['error']}",
                    "Grant the scanning role the missing permission.")
        for vpc_id, vpc in vpc_security.items():
            for check_name, check_val in vpc.items():
                if isinstance(check_val, dict) and check_val.get("error"):
                    add("ERROR", "CHECK_FAILED",
                        f"VPC check '{check_name}' could not run for "
                        f"{vpc_id}: {check_val['error']}",
                        "Grant the scanning role the missing permission.")

        return issues

    def _error_result(
        self, instance: Dict, error_msg: str
    ) -> Dict[str, Any]:
        """Generate safe error result dict for a failed instance scan."""
        return {
            "instance_id": instance.get("InstanceId", "unknown"),
            "instance_type": instance.get("InstanceType", ""),
            "region": self.region,
            "name": next(
                (
                    t["Value"]
                    for t in instance.get("Tags", [])
                    if t["Key"] == "Name"
                ),
                "",
            ),
            "state": instance.get("State", {}).get("Name", ""),
            "scan_error": True,
            "error_message": error_msg,
            "security_score": None,
            "compliance_status": {},
            "issues": [{
                "severity": "ERROR",
                "issue_type": "SCAN_ERROR",
                "description": error_msg,
                "recommendation": "Check permissions and retry",
            }],
            "issue_count": 1,
        }

    # ================================================================
    # Report Generation
    # ================================================================

    def generate_reports(
        self,
        results: List[Dict[str, Any]],
        output_format: str = "all",
        compliance_only: bool = False,
    ) -> Dict[str, str]:
        """Generate reports in requested format(s).

        When ``compliance_only`` is True, only the compliance JSON report is
        written — the JSON/CSV/HTML security reports are skipped.

        Returns dict of {format_name: file_path}.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_files = {}

        if compliance_only:
            report_files["compliance"] = self._export_compliance(
                results, timestamp
            )
            return report_files

        # Build summary
        summary = self._build_summary(results)

        if output_format in ("json", "all"):
            path = self._export_json(results, summary, timestamp)
            report_files["json"] = path

        if output_format in ("csv", "all"):
            path = self._export_csv(results, timestamp)
            report_files["csv"] = path

        if output_format in ("html", "all"):
            path = self._export_html(results, summary, timestamp)
            report_files["html"] = path

        # Always generate compliance report
        path = self._export_compliance(results, timestamp)
        report_files["compliance"] = path

        return report_files

    def _build_summary(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build summary statistics from scan results."""
        valid = [r for r in results if not r.get("scan_error", False)]
        scores = [
            r["security_score"] for r in valid
            if r.get("security_score") is not None
        ]

        return {
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "total_instances": len(results),
            "error_instances": len(results) - len(valid),
            "running_instances": sum(
                1 for r in valid if r.get("state") == "running"
            ),
            "stopped_instances": sum(
                1 for r in valid if r.get("state") == "stopped"
            ),
            "public_instances": sum(
                1 for r in valid
                if r.get("public_ip", {}).get("has_public_ip", False)
            ),
            "instances_with_secrets": sum(
                1 for r in valid
                if r.get("userdata_secrets", {}).get("has_secrets", False)
            ),
            "unencrypted_volume_instances": sum(
                1 for r in valid
                if not r.get("ebs_encryption", {}).get(
                    "all_encrypted", True
                )
            ),
            "critical_severity_instances": sum(
                1 for r in valid
                if r.get("has_critical_severity", False)
            ),
            "high_severity_instances": sum(
                1 for r in valid
                if r.get("has_high_severity", False)
            ),
            "average_security_score": (
                round(sum(scores) / len(scores), 1) if scores else 0
            ),
            "environment_security_score": self.environment_score,
            "environment_findings": self.environment_findings,
            "environment_critical_findings": sum(
                1 for f in self.environment_findings
                if f["severity"] == "CRITICAL"
            ),
            "environment_high_findings": sum(
                1 for f in self.environment_findings
                if f["severity"] == "HIGH"
            ),
        }

    def _export_json(
        self, results: List[Dict], summary: Dict, timestamp: str,
    ) -> str:
        """Export results as JSON."""
        path = os.path.join(
            self.output_dir,
            f"ec2_scan_{self.region}_{timestamp}.json",
        )
        with open(path, "w") as f:
            json.dump(
                {"summary": summary, "results": results},
                f, indent=2, default=str,
            )
        return path

    def _export_csv(
        self, results: List[Dict], timestamp: str,
    ) -> str:
        """Export results as CSV."""
        path = os.path.join(
            self.output_dir,
            f"ec2_scan_{self.region}_{timestamp}.csv",
        )

        fieldnames = [
            "instance_id", "instance_type", "name", "region",
            "vpc_id", "state", "public_ip", "imdsv2_enforced",
            "has_iam_profile", "ebs_all_encrypted",
            "has_userdata_secrets", "sg_ssh_open", "sg_rdp_open",
            "sg_high_risk_open", "sg_egress_unrestricted",
            "vpc_flow_logs", "detailed_monitoring", "ssm_managed",
            "ssm_patch_compliant", "ami_age_days",
            "inspector_v2_critical", "inspector_v2_high",
            "security_score", "issue_count", "critical_issues",
            "high_issues",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()

            for r in results:
                if r.get("scan_error"):
                    continue
                row = {
                    "instance_id": r.get("instance_id"),
                    "instance_type": r.get("instance_type"),
                    "name": r.get("name"),
                    "region": r.get("region"),
                    "vpc_id": r.get("vpc_id"),
                    "state": r.get("state"),
                    "public_ip": r.get("public_ip", {}).get(
                        "public_ip_address", ""
                    ),
                    "imdsv2_enforced": r.get("imdsv2", {}).get(
                        "enforced", False
                    ),
                    "has_iam_profile": r.get("iam_profile", {}).get(
                        "attached", False
                    ),
                    "ebs_all_encrypted": r.get(
                        "ebs_encryption", {}
                    ).get("all_encrypted", True),
                    "has_userdata_secrets": r.get(
                        "userdata_secrets", {}
                    ).get("has_secrets", False),
                    "sg_ssh_open": r.get("sg_ssh", {}).get(
                        "open_to_world", False
                    ),
                    "sg_rdp_open": r.get("sg_rdp", {}).get(
                        "open_to_world", False
                    ),
                    "sg_high_risk_open": r.get(
                        "sg_high_risk_ports", {}
                    ).get("has_violations", False),
                    "sg_egress_unrestricted": r.get(
                        "sg_egress", {}
                    ).get("unrestricted", False),
                    "vpc_flow_logs": r.get("vpc_flow_logs", {}).get(
                        "enabled", False
                    ),
                    "detailed_monitoring": r.get(
                        "monitoring", {}
                    ).get("detailed_enabled", False),
                    "ssm_managed": r.get("ssm_managed", {}).get(
                        "is_managed", False
                    ),
                    "ssm_patch_compliant": r.get(
                        "ssm_patch", {}
                    ).get("is_compliant", True),
                    "ami_age_days": r.get("ami_age", {}).get(
                        "age_days", 0
                    ),
                    "inspector_v2_critical": r.get(
                        "inspector_v2", {}
                    ).get("critical_findings", 0),
                    "inspector_v2_high": r.get(
                        "inspector_v2", {}
                    ).get("high_findings", 0),
                    "security_score": r.get("security_score", 0),
                    "issue_count": r.get("issue_count", 0),
                    "critical_issues": sum(
                        1 for i in r.get("issues", [])
                        if i["severity"] == "CRITICAL"
                    ),
                    "high_issues": sum(
                        1 for i in r.get("issues", [])
                        if i["severity"] == "HIGH"
                    ),
                }
                writer.writerow(row)

        return path

    def _export_html(
        self, results: List[Dict], summary: Dict, timestamp: str,
    ) -> str:
        """Export results as HTML dashboard."""
        path = os.path.join(
            self.output_dir,
            f"ec2_scan_{self.region}_{timestamp}.html",
        )
        self.html_reporter.generate_report(
            results, summary, path, compliance=self.scan_compliance
        )
        return path

    def _export_compliance(
        self, results: List[Dict], timestamp: str,
    ) -> str:
        """Export compliance-focused JSON report."""
        path = os.path.join(
            self.output_dir,
            f"ec2_compliance_{self.region}_{timestamp}.json",
        )

        valid = [r for r in results if not r.get("scan_error", False)]
        compliance_data = {
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "total_instances": len(results),
            "scanned_instances": len(valid),
            "note": (
                "Compliance is evaluated at scan level: account/region-wide "
                "controls (e.g. GuardDuty, CloudTrail, VPC BPA) are counted "
                "once, not per instance. Instance-level controls fail once "
                "and list the affected instance IDs."
            ),
            "frameworks": self.scan_compliance,
        }

        with open(path, "w") as f:
            json.dump(compliance_data, f, indent=2, default=str)
        return path

    # ================================================================
    # Console Summary
    # ================================================================

    def print_summary(self, results: List[Dict[str, Any]]) -> None:
        """Print Rich-formatted console summary."""
        summary = self._build_summary(results)
        valid = [r for r in results if not r.get("scan_error", False)]

        # Overall metrics table
        metrics_table = Table(title="EC2 Security Scan Summary")
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", justify="right")

        metrics_table.add_row(
            "Region", summary["region"]
        )
        metrics_table.add_row(
            "Account", summary["account_id"]
        )
        metrics_table.add_row(
            "Total Instances", str(summary["total_instances"])
        )
        metrics_table.add_row(
            "Running", str(summary["running_instances"])
        )
        metrics_table.add_row(
            "Stopped", str(summary["stopped_instances"])
        )
        metrics_table.add_row(
            "Public IP", str(summary["public_instances"])
        )
        metrics_table.add_row(
            "With Secrets in UserData",
            str(summary["instances_with_secrets"]),
        )
        metrics_table.add_row(
            "Unencrypted Volumes",
            str(summary["unencrypted_volume_instances"]),
        )
        metrics_table.add_row(
            "Critical Issues",
            str(summary["critical_severity_instances"]),
        )
        metrics_table.add_row(
            "High Issues",
            str(summary["high_severity_instances"]),
        )
        metrics_table.add_row(
            "Avg Instance Score",
            f"{summary['average_security_score']:.1f}/100",
        )
        metrics_table.add_row(
            "Environment Score",
            f"{summary['environment_security_score']}/100",
        )

        self.console.print(metrics_table)

        # Environment (account + VPC) posture findings — reported once.
        env_findings = summary.get("environment_findings", [])
        if env_findings:
            env_table = Table(
                title="Environment Posture (account + VPC, counted once)"
            )
            env_table.add_column("Severity", width=10)
            env_table.add_column("Finding", style="cyan")
            env_table.add_column("Description")
            sev_order = {
                "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                "LOW": 3, "ERROR": 4,
            }
            for f in sorted(
                env_findings,
                key=lambda x: sev_order.get(x["severity"], 9),
            ):
                color = {
                    "CRITICAL": "bold red", "HIGH": "red",
                    "MEDIUM": "yellow", "LOW": "blue",
                    "ERROR": "magenta",
                }.get(f["severity"], "white")
                env_table.add_row(
                    f"[{color}]{f['severity']}[/{color}]",
                    f["issue_type"],
                    f["description"],
                )
            self.console.print(env_table)

        # Lowest scoring instances
        if valid:
            worst = sorted(
                valid,
                key=lambda r: r.get("security_score", 0) or 0,
            )[:5]
            score_table = Table(
                title="Lowest Scoring Instances (Top 5)"
            )
            score_table.add_column("Instance ID", style="cyan")
            score_table.add_column("Name")
            score_table.add_column("Score", justify="right")
            score_table.add_column("Issues", justify="right")
            score_table.add_column("State")

            for r in worst:
                score = r.get("security_score", 0)
                color = (
                    "green" if score >= 90
                    else "yellow" if score >= 70
                    else "red" if score >= 50
                    else "bold red"
                )
                score_table.add_row(
                    r.get("instance_id", ""),
                    r.get("name", ""),
                    f"[{color}]{score}[/{color}]",
                    str(r.get("issue_count", 0)),
                    r.get("state", ""),
                )

            self.console.print(score_table)

        # Compliance summary — scan level (account controls counted once).
        compliance_table = Table(
            title="Compliance Framework Summary "
                  "(scan level — account controls counted once)"
        )
        compliance_table.add_column(
            "Framework", style="cyan", width=15
        )
        compliance_table.add_column(
            "Passed", justify="center", width=10
        )
        compliance_table.add_column(
            "Controls", justify="center", width=10
        )
        compliance_table.add_column(
            "Rate", justify="center", width=10
        )
        compliance_table.add_column("Status", justify="center")

        frameworks = [
            "AWS-FSBP", "CIS-v5.0", "PCI-DSS-v4.0", "HIPAA",
            "SOC2", "ISO27001", "ISO27017", "ISO27018",
            "GDPR", "NIST-800-53",
        ]

        for fw in frameworks:
            fw_status = self.scan_compliance.get(fw, {})
            if not fw_status:
                continue

            total = fw_status.get("total_controls", 0)
            passed = fw_status.get("passed_controls", 0)
            pct = fw_status.get("compliance_percentage", 0)
            if pct >= 90:
                status = "[green]Excellent[/green]"
            elif pct >= 75:
                status = "[yellow]Good[/yellow]"
            elif pct >= 50:
                status = "[orange1]Needs Work[/orange1]"
            else:
                status = "[red]Poor[/red]"

            compliance_table.add_row(
                fw, str(passed), str(total),
                f"{pct}%", status,
            )

        self.console.print(compliance_table)
