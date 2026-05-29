"""Tests for compliance engine.

Pure logic tests — no AWS mocking needed.
"""

import unittest

from ec2_security_scanner.compliance import ComplianceChecker


class TestFrameworkCounts(unittest.TestCase):
    """Lock the framework/control/check counts advertised in the README.

    These guard against silent drift between the docs and the code — if a
    control or check is added/removed, update both the code and the README,
    then update the expected number here so the change is deliberate.
    """

    # Per-framework control counts (must match README compliance table).
    EXPECTED_PER_FRAMEWORK = {
        "AWS-FSBP": 32,
        "CIS-v5.0": 7,
        "PCI-DSS-v4.0": 12,
        "HIPAA": 10,
        "SOC2": 13,
        "ISO27001": 17,
        "ISO27017": 7,
        "ISO27018": 4,
        "GDPR": 8,
        "NIST-800-53": 27,
    }
    EXPECTED_TOTAL_CONTROLS = 137
    EXPECTED_FRAMEWORK_COUNT = 10
    EXPECTED_CHECK_METHODS = 46

    def test_framework_count(self):
        checker = ComplianceChecker()
        self.assertEqual(
            len(checker.frameworks), self.EXPECTED_FRAMEWORK_COUNT
        )

    def test_per_framework_control_counts(self):
        checker = ComplianceChecker()
        actual = {
            fw: len(data["controls"])
            for fw, data in checker.frameworks.items()
        }
        self.assertEqual(actual, self.EXPECTED_PER_FRAMEWORK)

    def test_total_control_count(self):
        checker = ComplianceChecker()
        total = sum(
            len(d["controls"]) for d in checker.frameworks.values()
        )
        self.assertEqual(total, self.EXPECTED_TOTAL_CONTROLS)

    def test_check_method_count(self):
        """Count distinct check_* methods across all checker modules."""
        import inspect
        from ec2_security_scanner import checks as checks_pkg
        import pkgutil
        import importlib

        names = set()
        for mod in pkgutil.iter_modules(checks_pkg.__path__):
            module = importlib.import_module(
                f"ec2_security_scanner.checks.{mod.name}"
            )
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ != module.__name__:
                    continue
                for attr in dir(obj):
                    if attr.startswith("check_"):
                        names.add(attr)
        self.assertEqual(len(names), self.EXPECTED_CHECK_METHODS)


class TestComplianceChecker(unittest.TestCase):
    """Test compliance framework evaluation."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def _all_pass_checks(self):
        """Create a checks dict where all controls should pass."""
        return {
            "imdsv2": {"enforced": True},
            "launch_template_imdsv2": {"checked": True, "enforced": True},
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
            "sg_remote_admin": {"open_to_world": False, "open_to_ipv4": False, "open_to_ipv6": False},
            "vpc_flow_logs": {"enabled": True},
            "nacl_admin_ports": {"open_to_world": False},
            "source_dest_check": {"enabled": True},
            "sg_egress": {"unrestricted": False},
            "sg_authorized_ports": {"has_violations": False},
            "ebs_encryption": {"all_encrypted": True},
            "ebs_default_encryption": {"enabled": True},
            "ebs_snapshot_public": {"has_public_snapshots": False},
            "ebs_backup": {"covered": True},
            "launch_template_ebs_encryption": {"checked": True, "all_encrypted": True},
            "public_ami": {"has_public_amis": False},
            "iam_role": {"has_admin_access": False, "has_wildcard_actions": False},
            "key_pair": {"has_key_pair": False},
            "serial_console": {"enabled": False},
            "instance_connect": {"endpoints_configured": True},
            "cloudtrail": {"enabled": True, "active_trails": 1},
            "cloudwatch_alarms": {"has_alarms": True, "alarm_count": 2},
            "ssm_managed": {"is_managed": True},
            "guardduty": {"enabled": True, "runtime_monitoring": True, "ebs_malware_protection": True},
            "ssm_patch": {"is_compliant": True, "missing_count": 0},
            "ami_age": {"is_stale": False, "age_days": 30},
            "inspector_v2": {"ec2_scanning_enabled": True, "has_coverage": True, "critical_findings": 0, "high_findings": 0},
            "unused_eips": {"count": 0},
            "launch_template_public_ip": {"assigns_public_ip": False},
            "subnet_auto_assign_public_ip": {"enabled": False},
            "vpc_bpa": {"blocks_igw": True},
            "transit_gateway": {"auto_accept_enabled": False},
            "tags": {"has_required_tags": True, "missing_tags": []},
            "stopped_instance": {"is_stopped": False, "exceeds_threshold": False},
            "unused_sgs": {"count": 0},
            "ebs_snapshot_bpa": {"state": "block-all-sharing", "blocked": True},
            "vpn_connections": {"all_ikev2": True, "non_ikev2_connections": []},
        }

    def test_all_frameworks_defined(self):
        """All 10 frameworks should be defined."""
        expected = [
            "AWS-FSBP", "CIS-v5.0", "PCI-DSS-v4.0", "HIPAA",
            "SOC2", "ISO27001", "ISO27017", "ISO27018",
            "GDPR", "NIST-800-53",
        ]
        for fw in expected:
            self.assertIn(fw, self.checker.frameworks, f"Missing framework: {fw}")

    def test_total_control_count(self):
        """Total control count should be 137."""
        total = sum(
            len(fw["controls"])
            for fw in self.checker.frameworks.values()
        )
        self.assertEqual(total, 137)

    def test_fsbp_control_count(self):
        """FSBP should have 32 controls."""
        self.assertEqual(
            len(self.checker.frameworks["AWS-FSBP"]["controls"]), 32
        )

    def test_cis_control_count(self):
        """CIS v5.0 should have 7 controls.

        Note: dropped mis-mapped 5.6 (launch template IMDSv2 is not in CIS v5.0;
        actual CIS 5.6 is VPC peering least access). See audit 2026-05-15.
        """
        self.assertEqual(
            len(self.checker.frameworks["CIS-v5.0"]["controls"]), 7
        )

    def test_pci_control_count(self):
        """PCI DSS v4.0 should have 12 controls."""
        self.assertEqual(
            len(self.checker.frameworks["PCI-DSS-v4.0"]["controls"]), 12
        )

    def test_nist_control_count(self):
        """NIST 800-53 should have 27 controls."""
        self.assertEqual(
            len(self.checker.frameworks["NIST-800-53"]["controls"]), 27
        )

    def test_all_pass_100_percent(self):
        """All checks passing should give 100% compliance on every framework."""
        checks = self._all_pass_checks()
        compliance = self.checker.check_instance_compliance(checks)

        for fw_id, result in compliance.items():
            self.assertTrue(
                result["is_compliant"],
                f"{fw_id}: expected 100% compliant but got "
                f"{result['compliance_percentage']}% "
                f"(failed: {[c['control_id'] for c in result['failed']]})"
            )
            self.assertEqual(
                result["compliance_percentage"], 100.0,
                f"{fw_id}: expected 100% but got {result['compliance_percentage']}%"
            )

    def test_imdsv2_failure_affects_fsbp(self):
        """IMDSv2 not enforced should fail FSBP EC2.8."""
        checks = self._all_pass_checks()
        checks["imdsv2"] = {"enforced": False}
        compliance = self.checker.check_instance_compliance(checks)

        fsbp = compliance["AWS-FSBP"]
        failed_ids = [c["control_id"] for c in fsbp["failed"]]
        self.assertIn("EC2.8", failed_ids)

    def test_ssh_open_affects_multiple_frameworks(self):
        """Open SSH should affect FSBP, CIS, NIST, SOC2, ISO."""
        checks = self._all_pass_checks()
        checks["sg_ssh"] = {"open_to_world": True}
        compliance = self.checker.check_instance_compliance(checks)

        # FSBP EC2.13
        fsbp_failed = [c["control_id"] for c in compliance["AWS-FSBP"]["failed"]]
        self.assertIn("EC2.13", fsbp_failed)

        # NIST AC-17
        nist_failed = [c["control_id"] for c in compliance["NIST-800-53"]["failed"]]
        self.assertIn("AC-17", nist_failed)

    def test_compliance_result_structure(self):
        """Verify compliance result dict has expected keys."""
        checks = self._all_pass_checks()
        compliance = self.checker.check_instance_compliance(checks)

        for fw_id, result in compliance.items():
            self.assertIn("framework_name", result)
            self.assertIn("total_controls", result)
            self.assertIn("passed_controls", result)
            self.assertIn("failed_controls", result)
            self.assertIn("compliance_percentage", result)
            self.assertIn("is_compliant", result)
            self.assertIn("passed", result)
            self.assertIn("failed", result)
            self.assertEqual(
                result["total_controls"],
                result["passed_controls"] + result["failed_controls"],
            )

    def test_empty_checks_does_not_crash(self):
        """Empty checks should not crash compliance evaluation."""
        compliance = self.checker.check_instance_compliance({})
        self.assertIsInstance(compliance, dict)
        for fw_id, result in compliance.items():
            self.assertIsInstance(result["compliance_percentage"], float)


class TestControlScopeClassification(unittest.TestCase):
    """Lock the account-vs-instance scope classification of controls.

    Account-level controls (GuardDuty, CloudTrail, default SG, ...) must be
    evaluated ONCE per scan, never multiplied across instances.
    """

    def setUp(self):
        self.checker = ComplianceChecker()

    def test_known_account_controls(self):
        fsbp = self.checker.frameworks["AWS-FSBP"]["controls"]
        for cid in ("EC2.2", "EC2.7", "EC2.182", "EC2.183", "BP.PublicAMI"):
            self.assertEqual(
                fsbp[cid]["scope"], "account",
                f"FSBP {cid} should be account-level"
            )

    def test_known_instance_controls(self):
        fsbp = self.checker.frameworks["AWS-FSBP"]["controls"]
        for cid in ("EC2.8", "EC2.13", "EC2.1", "BP.UserData"):
            self.assertEqual(
                fsbp[cid]["scope"], "instance",
                f"FSBP {cid} should be instance-level"
            )

    def test_every_control_has_a_scope(self):
        for fw, data in self.checker.frameworks.items():
            for cid, ctrl in data["controls"].items():
                self.assertIn(
                    ctrl["scope"], ("account", "instance"),
                    f"{fw}/{cid} has invalid scope {ctrl.get('scope')}"
                )


class TestScanCompliance(unittest.TestCase):
    """Test scan-level compliance: account controls counted once."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def _clean_account_result(self, **overrides):
        r = {
            "ebs_default_encryption": {"enabled": True},
            "ebs_snapshot_bpa": {"blocked": True},
            "public_ami": {"has_public_amis": False},
            "serial_console": {"enabled": False},
            "cloudtrail": {"enabled": True},
            "guardduty": {"enabled": True},
            "unused_eips": {"count": 0},
            "vpc_bpa": {"blocks_igw": True},
            "transit_gateway": {"auto_accept_enabled": False},
            "vpn_connections": {"all_ikev2": True},
            "unused_sgs": {"count": 0},
            "default_sg": {"has_rules": False},
            "vpc_flow_logs": {"enabled": True},
            "nacl_admin_ports": {"open_to_world": False},
            "instance_connect": {"endpoints_configured": True},
            "launch_template_imdsv2": {"checked": True, "enforced": True},
            "launch_template_public_ip": {"assigns_public_ip": False},
            "launch_template_ebs_encryption": {"checked": True,
                                               "all_encrypted": True},
        }
        r.update(overrides)
        return r

    def _clean_instance(self, iid, **overrides):
        # Reuse the all-pass instance checks and tag with an id.
        base = TestComplianceChecker()._all_pass_checks()
        base["instance_id"] = iid
        base.update(overrides)
        return base

    def test_all_pass_is_100(self):
        account = self._clean_account_result()
        instances = [self._clean_instance("i-1"), self._clean_instance("i-2")]
        scan = self.checker.evaluate_scan(account, instances)
        for fw, status in scan.items():
            self.assertTrue(status["is_compliant"], f"{fw} not compliant")
            self.assertEqual(status["compliance_percentage"], 100.0)
            self.assertEqual(
                status["total_controls"],
                len(self.checker.frameworks[fw]["controls"]),
            )

    def test_account_gap_counted_once(self):
        """An account-wide gap (public AMI sharing) fails the account control
        ONCE with no per-instance attribution, regardless of fleet size."""
        account = self._clean_account_result(
            public_ami={"has_public_amis": True}
        )
        instances = [self._clean_instance(f"i-{n}") for n in range(5)]
        scan = self.checker.evaluate_scan(account, instances)

        # FSBP BP.PublicAMI is a pure account-level control.
        fsbp_failed = {f["control_id"]: f for f in scan["AWS-FSBP"]["failed"]}
        self.assertIn("BP.PublicAMI", fsbp_failed)
        self.assertEqual(fsbp_failed["BP.PublicAMI"]["scope"], "account")
        self.assertEqual(fsbp_failed["BP.PublicAMI"]["instances"], [])

    def test_instance_control_fails_once_listing_offenders(self):
        """IMDSv2 disabled on 1 of 3 instances = ONE failed control listing
        that instance — not three separate failures."""
        account = self._clean_account_result()
        instances = [
            self._clean_instance("i-good1"),
            self._clean_instance("i-bad", imdsv2={"enforced": False}),
            self._clean_instance("i-good2"),
        ]
        scan = self.checker.evaluate_scan(account, instances)

        fsbp_failed = {f["control_id"]: f for f in scan["AWS-FSBP"]["failed"]}
        self.assertIn("EC2.8", fsbp_failed)
        self.assertEqual(fsbp_failed["EC2.8"]["scope"], "instance")
        self.assertEqual(fsbp_failed["EC2.8"]["instances"], ["i-bad"])
        # Counted as exactly one failed control out of the framework total.
        self.assertEqual(
            scan["AWS-FSBP"]["passed_controls"]
            + scan["AWS-FSBP"]["failed_controls"],
            scan["AWS-FSBP"]["total_controls"],
        )

    def test_account_gap_does_not_scale_with_instance_count(self):
        """The compliance % for an account-only gap must be identical whether
        we scan 1 instance or 100 — proving no per-instance multiplication."""
        account = self._clean_account_result(
            ebs_default_encryption={"enabled": False}
        )
        scan_1 = self.checker.evaluate_scan(
            account, [self._clean_instance("i-0")]
        )
        scan_100 = self.checker.evaluate_scan(
            account, [self._clean_instance(f"i-{n}") for n in range(100)]
        )
        for fw in scan_1:
            self.assertEqual(
                scan_1[fw]["compliance_percentage"],
                scan_100[fw]["compliance_percentage"],
                f"{fw} compliance % changed with instance count",
            )


class TestFrameworkControlValidation(unittest.TestCase):
    """Validate each framework's control definitions."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def test_all_controls_have_required_keys(self):
        """Every control must have description, severity, and check."""
        for fw_id, framework in self.checker.frameworks.items():
            for ctrl_id, control in framework["controls"].items():
                self.assertIn(
                    "description", control,
                    f"{fw_id}/{ctrl_id} missing description"
                )
                self.assertIn(
                    "severity", control,
                    f"{fw_id}/{ctrl_id} missing severity"
                )
                self.assertIn(
                    "check", control,
                    f"{fw_id}/{ctrl_id} missing check"
                )
                self.assertTrue(
                    callable(control["check"]),
                    f"{fw_id}/{ctrl_id} check is not callable"
                )

    def test_all_severities_are_valid(self):
        """All severities should be CRITICAL, HIGH, MEDIUM, or LOW."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for fw_id, framework in self.checker.frameworks.items():
            for ctrl_id, control in framework["controls"].items():
                self.assertIn(
                    control["severity"], valid_severities,
                    f"{fw_id}/{ctrl_id} has invalid severity: {control['severity']}"
                )

    def test_all_lambdas_execute_without_error(self):
        """All lambda checks should execute against empty dict without exception."""
        for fw_id, framework in self.checker.frameworks.items():
            for ctrl_id, control in framework["controls"].items():
                try:
                    result = control["check"]({})
                    self.assertIsInstance(
                        result, bool,
                        f"{fw_id}/{ctrl_id} returned non-bool: {type(result)}"
                    )
                except Exception as e:
                    self.fail(
                        f"{fw_id}/{ctrl_id} lambda raised: {e}"
                    )


if __name__ == "__main__":
    unittest.main()
