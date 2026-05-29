"""Utility functions for EC2 Security Scanner."""

import logging
import os
from datetime import datetime
from typing import Dict, Any


def setup_logging(output_dir: str) -> logging.Logger:
    """Setup logging configuration with console and file handlers."""
    logger = logging.getLogger("ec2_security_scanner")
    logger.setLevel(logging.INFO)

    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_file = os.path.join(
        output_dir,
        f'ec2_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def _safe_get(checks: Dict[str, Any], check_name: str, key: str,
              default=False):
    """Safely read a key from a check result, ignoring errored checks.

    A check dict carrying an ``error`` key (e.g. AccessDenied) is treated
    as "unknown" and returns ``default`` so a missing permission never
    silently improves a score.
    """
    check = checks.get(check_name, {})
    if isinstance(check, dict) and "error" not in check:
        return check.get(key, default)
    return default


def calculate_security_score(checks: Dict[str, Any]) -> int:
    """Calculate the **instance** security score (0-100).

    Only instance-specific findings are scored here. Account- and
    VPC-wide findings (GuardDuty, CloudTrail, VPC BPA, EBS snapshot BPA,
    default SG, flow logs, ...) are scored once for the whole scan by
    :func:`calculate_environment_score` so a single account-level gap does
    not get multiplied across every instance and dominate the average.

    Implements a non-stacking rule for overlapping security-group ingress
    exposure: B.2 (SSH), B.3 (RDP), B.4 (high-risk ports), B.5 (remote
    admin) and B.10 (unauthorized ports open to the world) all describe the
    same underlying "ports exposed to 0.0.0.0/0" misconfiguration, so only
    the single highest penalty is applied — never the sum.

    Score is clamped to minimum 0 (never negative).
    """
    score = 100

    def get(check_name: str, key: str, default=False):
        return _safe_get(checks, check_name, key, default)

    # === CRITICAL deductions ===
    if get("userdata_secrets", "has_secrets"):
        score -= 25
    if get("ebs_snapshot_public", "has_public_snapshots"):
        score -= 20

    # === SG ingress exposure: NON-STACKING (take highest penalty only) ===
    # B.2 SSH, B.3 RDP, B.4 high-risk, B.5 remote-admin and B.10 authorized
    # ports all overlap on "ports open to the world" — apply highest only.
    sg_penalty = 0
    if get("sg_high_risk_ports", "has_violations"):
        sg_penalty = max(sg_penalty, 20)  # CRITICAL
    if get("sg_ssh", "open_to_world"):
        sg_penalty = max(sg_penalty, 15)  # HIGH
    if get("sg_rdp", "open_to_world"):
        sg_penalty = max(sg_penalty, 15)  # HIGH
    if get("sg_remote_admin", "open_to_world"):
        sg_penalty = max(sg_penalty, 15)  # HIGH
    if get("sg_authorized_ports", "has_violations"):
        sg_penalty = max(sg_penalty, 10)  # HIGH
    score -= sg_penalty

    # === HIGH deductions (independent, all apply) ===
    # NOTE: launch-template findings are scored at environment level
    # (calculate_environment_score), since templates are region resources
    # that describe_instances cannot tie to a specific instance.
    if not get("imdsv2", "enforced"):
        score -= 15
    if get("public_ip", "has_public_ip"):
        score -= 15
    if (get("iam_role", "has_admin_access")
            or get("iam_role", "has_wildcard_actions")):
        score -= 15
    inspector = checks.get("inspector_v2", {})
    if isinstance(inspector, dict) and "error" not in inspector:
        if not inspector.get("ec2_scanning_enabled", False):
            score -= 8
        elif (inspector.get("critical_findings", 0) > 0
                or inspector.get("high_findings", 0) > 0):
            score -= 8

    # === MEDIUM deductions ===
    if not get("ebs_encryption", "all_encrypted", True):
        score -= 10
    if not get("ssm_patch", "is_compliant", True):
        score -= 10
    if not get("iam_profile", "attached"):
        score -= 8
    if not get("source_dest_check", "enabled", True):
        score -= 5
    if not get("ssm_managed", "is_managed"):
        score -= 5
    if get("subnet_auto_assign_public_ip", "enabled"):
        score -= 5
    if not get("cloudwatch_alarms", "has_alarms"):
        score -= 5
    if get("ami_age", "is_stale"):
        score -= 5
    if not get("monitoring", "detailed_enabled"):
        score -= 5
    if not get("virtualization", "is_hvm", True):
        score -= 5
    if get("key_pair", "has_key_pair") and not get("key_pair", "ssm_managed"):
        score -= 5

    # === LOW deductions ===
    if get("network_interfaces", "has_multiple"):
        score -= 3
    if not get("ebs_backup", "covered"):
        score -= 3
    # Unrestricted egress is an opinionated hardening nudge, not an FSBP
    # requirement — most SGs keep AWS's default allow-all egress — so it is
    # scored LOW to avoid dinging nearly every instance.
    if get("sg_egress", "unrestricted"):
        score -= 2
    if not get("tags", "has_required_tags", True):
        score -= 2
    if get("stopped_instance", "exceeds_threshold"):
        score -= 2
    imds = checks.get("imdsv2", {})
    if (isinstance(imds, dict) and "error" not in imds
            and imds.get("enforced") and not imds.get("hop_limit_safe", True)):
        score -= 2

    # Clamp to minimum 0
    return max(0, score)


def calculate_environment_score(
    account_security: Dict[str, Any],
    vpc_security: Dict[str, Dict[str, Any]] = None,
) -> int:
    """Calculate the **environment** (account + VPC) posture score (0-100).

    These findings are global to the account/region (or shared by every
    instance in a VPC), so they are scored once here instead of being
    deducted from every instance. Each VPC-level finding is deducted at
    most once even if several VPCs are affected, keeping the score bounded.

    Score is clamped to minimum 0 (never negative).
    """
    vpc_security = vpc_security or {}
    score = 100

    def get(check_name: str, key: str, default=False):
        return _safe_get(account_security, check_name, key, default)

    # === Account-wide deductions ===
    if get("public_amis", "has_public_amis"):
        score -= 20  # CRITICAL
    if not get("ebs_snapshot_bpa", "blocked"):
        score -= 10  # HIGH
    if get("transit_gateway", "auto_accept_enabled"):
        score -= 10  # HIGH
    if not get("guardduty_ec2_protection", "enabled"):
        score -= 10  # HIGH
    if not get("vpc_bpa", "blocks_igw"):
        score -= 10  # HIGH
    if not get("cloudtrail", "enabled"):
        score -= 10  # HIGH
    if not get("vpn_connections", "all_ikev2", True):
        score -= 10  # HIGH
    if not get("ebs_default_encryption", "enabled"):
        score -= 5   # MEDIUM
    if get("serial_console_access", "enabled"):
        score -= 5   # MEDIUM
    if get("unused_eips", "count", 0) > 0:
        score -= 2   # LOW
    if get("unused_sgs", "count", 0) > 0:
        score -= 2   # LOW

    # === VPC-level deductions (counted once if ANY VPC is affected) ===
    def any_vpc(key: str, subkey: str, want_true: bool) -> bool:
        for vpc in vpc_security.values():
            chk = vpc.get(key, {})
            if not isinstance(chk, dict) or "error" in chk:
                continue
            val = chk.get(subkey, not want_true)
            if bool(val) == want_true:
                return True
        return False

    if any_vpc("default_sg", "has_rules", True):
        score -= 10  # HIGH
    if any_vpc("vpc_flow_logs", "enabled", False):
        score -= 10  # MEDIUM
    if any_vpc("nacl_admin_ports", "open_to_world", True):
        score -= 5   # MEDIUM
    if any_vpc("instance_connect", "endpoints_configured", False):
        score -= 1   # LOW

    # === Launch-template audit (region-level) ===
    lt = account_security.get("launch_templates", {})
    if isinstance(lt, dict) and "error" not in lt:
        if lt.get("imdsv2_not_enforced"):
            score -= 10  # HIGH
        if lt.get("assigns_public_ip"):
            score -= 10  # HIGH
        if lt.get("ebs_unencrypted"):
            score -= 5   # MEDIUM

    return max(0, score)


def get_severity_color(severity: str) -> str:
    """Map severity level to Rich color string."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "ERROR": "magenta",
    }
    return colors.get(severity, "white")


def format_datetime(dt) -> str:
    """Format datetime for display."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt

    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    return str(dt)
