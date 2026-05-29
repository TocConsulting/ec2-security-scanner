"""Tests for security score calculation.

Pure logic tests — no AWS mocking needed.
"""

import unittest

from ec2_security_scanner.utils import (
    calculate_security_score,
    calculate_environment_score,
)


class TestSecurityScore(unittest.TestCase):
    """Test score calculation with non-stacking and clamping."""

    def _base_checks(self, **overrides):
        """Create a base checks dict with all-safe defaults."""
        checks = {
            "imdsv2": {"enforced": True},
            "public_ip": {"has_public_ip": False},
            "iam_profile": {"attached": True},
            "virtualization": {"is_hvm": True},
            "network_interfaces": {"has_multiple": False},
            "monitoring": {"detailed_enabled": True},
            "userdata_secrets": {"has_secrets": False},
            "default_sg": {"has_rules": False},
            "sg_ssh": {"open_to_world": False},
            "sg_rdp": {"open_to_world": False},
            "sg_high_risk_ports": {"has_violations": False},
            "sg_remote_admin": {"open_to_world": False},
            "vpc_flow_logs": {"enabled": True},
            "nacl_admin_ports": {"open_to_world": False},
            "source_dest_check": {"enabled": True},
            "sg_egress": {"unrestricted": False},
            "sg_authorized_ports": {"has_violations": False},
            "ebs_encryption": {"all_encrypted": True},
            "ebs_default_encryption": {"enabled": True},
            "ebs_snapshot_public": {"has_public_snapshots": False},
            "ebs_backup": {"covered": True},
            "public_ami": {"has_public_amis": False},
            "iam_role": {"has_admin_access": False},
            "key_pair": {"has_key_pair": False},
            "serial_console": {"enabled": False},
            "cloudtrail": {"enabled": True},
            "cloudwatch_alarms": {"has_alarms": True},
            "ssm_managed": {"is_managed": True},
            "guardduty": {"enabled": True},
            "ssm_patch": {"is_compliant": True},
            "ami_age": {"is_stale": False},
            "inspector_v2": {
                "ec2_scanning_enabled": True,
                "critical_findings": 0,
                "high_findings": 0,
            },
            "unused_eips": {"count": 0},
            "launch_template_public_ip": {"assigns_public_ip": False},
            "subnet_auto_assign_public_ip": {"enabled": False},
            "vpc_bpa": {"blocks_igw": True},
            "transit_gateway": {"auto_accept_enabled": False},
            "tags": {"has_required_tags": True},
            "stopped_instance": {"is_stopped": False, "exceeds_threshold": False},
            "unused_sgs": {"count": 0},
            "ebs_snapshot_bpa": {"state": "block-all-sharing", "blocked": True},
            "vpn_connections": {"all_ikev2": True, "non_ikev2_connections": []},
        }
        checks.update(overrides)
        return checks

    def test_perfect_score(self):
        """All checks passing should yield 100."""
        checks = self._base_checks()
        self.assertEqual(calculate_security_score(checks), 100)

    def test_imdsv2_not_enforced(self):
        checks = self._base_checks(imdsv2={"enforced": False})
        self.assertEqual(calculate_security_score(checks), 85)

    def test_userdata_secrets(self):
        checks = self._base_checks(
            userdata_secrets={"has_secrets": True}
        )
        self.assertEqual(calculate_security_score(checks), 75)

    def test_account_findings_do_not_affect_instance_score(self):
        """Account-wide findings (public AMI, GuardDuty, CloudTrail, VPC BPA,
        TGW, snapshot BPA, serial console) must NOT lower the instance score —
        they belong to the environment score."""
        checks = self._base_checks(
            public_ami={"has_public_amis": True},
            guardduty={"enabled": False},
            cloudtrail={"enabled": False},
            vpc_bpa={"blocks_igw": False},
            transit_gateway={"auto_accept_enabled": True},
            ebs_snapshot_bpa={"state": "unblocked", "blocked": False},
            serial_console={"enabled": True},
            ebs_default_encryption={"enabled": False},
            default_sg={"has_rules": True},
            vpc_flow_logs={"enabled": False},
            nacl_admin_ports={"open_to_world": True},
            unused_eips={"count": 5},
            unused_sgs={"count": 5},
        )
        self.assertEqual(calculate_security_score(checks), 100)

    def test_non_stacking_sg_ports(self):
        """SSH + high-risk ports should NOT stack — take highest penalty (20)."""
        checks = self._base_checks(
            sg_ssh={"open_to_world": True},
            sg_high_risk_ports={"has_violations": True},
        )
        score = calculate_security_score(checks)
        # Only -20 (highest penalty), not -20 + -15
        self.assertEqual(score, 80)

    def test_authorized_ports_do_not_double_count_with_ssh(self):
        """SSH open (port 22) trips both the SSH/high-risk penalty and the
        'unauthorized port open' check, but the non-stacking rule must apply
        the highest single penalty only — not 20 + 10."""
        checks = self._base_checks(
            sg_ssh={"open_to_world": True},
            sg_high_risk_ports={"has_violations": True},
            sg_authorized_ports={"has_violations": True},
        )
        # max(20, 15, 10) = 20, never 30+
        self.assertEqual(calculate_security_score(checks), 80)

    def test_authorized_ports_alone(self):
        """An unauthorized non-admin port open to world alone is -10."""
        checks = self._base_checks(
            sg_authorized_ports={"has_violations": True},
        )
        self.assertEqual(calculate_security_score(checks), 90)

    def test_unrestricted_egress_is_low(self):
        """Unrestricted egress is an opinionated nudge — only -2 (LOW)."""
        checks = self._base_checks(
            sg_egress={"unrestricted": True},
        )
        self.assertEqual(calculate_security_score(checks), 98)

    def test_ssh_only_penalty(self):
        """SSH alone is -15."""
        checks = self._base_checks(
            sg_ssh={"open_to_world": True},
        )
        self.assertEqual(calculate_security_score(checks), 85)

    def test_rdp_only_penalty(self):
        """RDP alone is -15."""
        checks = self._base_checks(
            sg_rdp={"open_to_world": True},
        )
        self.assertEqual(calculate_security_score(checks), 85)

    def test_ssh_and_rdp_non_stacking(self):
        """SSH + RDP should take highest penalty (15), not 15+15."""
        checks = self._base_checks(
            sg_ssh={"open_to_world": True},
            sg_rdp={"open_to_world": True},
        )
        self.assertEqual(calculate_security_score(checks), 85)

    def test_score_clamped_to_zero(self):
        """Worst case should clamp to 0, never go negative."""
        checks = self._base_checks(
            userdata_secrets={"has_secrets": True},       # -25
            public_ami={"has_public_amis": True},          # -20
            ebs_snapshot_public={"has_public_snapshots": True},  # -20
            sg_high_risk_ports={"has_violations": True},   # -20
            imdsv2={"enforced": False},                    # -15
            public_ip={"has_public_ip": True},             # -15
            iam_role={"has_admin_access": True},           # -15
            transit_gateway={"auto_accept_enabled": True}, # -10
            sg_authorized_ports={"has_violations": True},  # -10
            guardduty={"enabled": False},                  # -10
            default_sg={"has_rules": True},                # -10
            vpc_bpa={"blocks_igw": False},                 # -10
            sg_egress={"unrestricted": True},              # -10
            ebs_encryption={"all_encrypted": False},       # -10
            vpc_flow_logs={"enabled": False},              # -10
            ssm_patch={"is_compliant": False},             # -10
            iam_profile={"attached": False},               # -8
            inspector_v2={"critical_findings": 1, "high_findings": 0},  # -8
            cloudwatch_alarms={"has_alarms": False},       # -5
            ami_age={"is_stale": True},                    # -5
            monitoring={"detailed_enabled": False},        # -5
            virtualization={"is_hvm": False},              # -5
            network_interfaces={"has_multiple": True},     # -3
            ebs_backup={"covered": False},                 # -3
            tags={"has_required_tags": False},             # -2
            unused_eips={"count": 3},                      # -2
        )
        score = calculate_security_score(checks)
        self.assertEqual(score, 0)
        self.assertGreaterEqual(score, 0)

    def test_empty_checks(self):
        """Empty checks dict should not crash and use safe defaults."""
        score = calculate_security_score({})
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_error_in_check_uses_default(self):
        """Check with error key should use safe default."""
        checks = self._base_checks(
            imdsv2={"error": "AccessDenied"},
        )
        score = calculate_security_score(checks)
        # Should deduct for imdsv2 not enforced (error = False default)
        self.assertLess(score, 100)


class TestEnvironmentScore(unittest.TestCase):
    """Test account + VPC posture scoring (scored once per scan)."""

    def _clean_account(self, **overrides):
        account = {
            "public_amis": {"has_public_amis": False},
            "ebs_snapshot_bpa": {"blocked": True},
            "transit_gateway": {"auto_accept_enabled": False},
            "guardduty_ec2_protection": {"enabled": True},
            "vpc_bpa": {"blocks_igw": True},
            "cloudtrail": {"enabled": True},
            "vpn_connections": {"all_ikev2": True},
            "ebs_default_encryption": {"enabled": True},
            "serial_console_access": {"enabled": False},
            "unused_eips": {"count": 0},
            "unused_sgs": {"count": 0},
        }
        account.update(overrides)
        return account

    def test_clean_environment_is_100(self):
        self.assertEqual(
            calculate_environment_score(self._clean_account(), {}), 100
        )

    def test_public_ami_is_environment_level(self):
        account = self._clean_account(
            public_amis={"has_public_amis": True}
        )
        self.assertEqual(calculate_environment_score(account, {}), 80)

    def test_account_gaps_counted_once(self):
        """No GuardDuty + no CloudTrail + no VPC BPA = -30 total, ONCE."""
        account = self._clean_account(
            guardduty_ec2_protection={"enabled": False},
            cloudtrail={"enabled": False},
            vpc_bpa={"blocks_igw": False},
        )
        self.assertEqual(calculate_environment_score(account, {}), 70)

    def test_vpc_findings_counted_once_across_vpcs(self):
        """Two VPCs both missing flow logs deduct only once (-10)."""
        account = self._clean_account()
        vpcs = {
            "vpc-1": {"vpc_flow_logs": {"enabled": False}},
            "vpc-2": {"vpc_flow_logs": {"enabled": False}},
        }
        self.assertEqual(calculate_environment_score(account, vpcs), 90)

    def test_errored_account_check_does_not_improve_score(self):
        """An AccessDenied account check must not silently pass."""
        account = self._clean_account(
            guardduty_ec2_protection={"error": "AccessDenied"},
        )
        # error => treated as not-enabled => -10
        self.assertEqual(calculate_environment_score(account, {}), 90)


if __name__ == "__main__":
    unittest.main()
