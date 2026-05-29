"""Regression tests for two defects found during live AWS verification:

1. CloudTrail multi-region trails were not counted in non-home regions
   (false NO_CLOUDTRAIL). Fixed by including shadow trails.
2. Launch-template checks could never fire because describe_instances does
   not expose the instance's launch template. Fixed by auditing all launch
   templates at region level (check_all_launch_templates).
"""
import unittest
from unittest.mock import MagicMock

from ec2_security_scanner.checks.logging_monitoring import LoggingMonitoringChecker
from ec2_security_scanner.checks.instance_security import InstanceSecurityChecker


class TestCloudTrailMultiRegion(unittest.TestCase):
    def _checker(self, fake_ct):
        c = LoggingMonitoringChecker()
        c.get_client = lambda *a, **k: fake_ct
        return c

    def test_multiregion_shadow_trail_counts_in_other_region(self):
        """A multi-region trail homed elsewhere (shadow) must count as active
        in the scanned region — this was the false-positive bug."""
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{
            "TrailARN": "arn:aws:cloudtrail:eu-west-1:1:trail/org",
            "Name": "org", "IsMultiRegionTrail": True,
            "HomeRegion": "eu-west-1"}]}
        ct.get_trail_status.return_value = {"IsLogging": True}
        ct.get_event_selectors.return_value = {"EventSelectors": [
            {"IncludeManagementEvents": True, "ReadWriteType": "All"}]}
        res = self._checker(ct).check_cloudtrail("us-east-1")
        self.assertTrue(res["enabled"])
        self.assertTrue(res["multi_region"])
        self.assertEqual(res["active_trails"], 1)
        # Verify shadow trails were requested
        ct.describe_trails.assert_called_with(includeShadowTrails=True)

    def test_no_logging_trail_is_not_counted(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{
            "TrailARN": "arn:x:trail/t", "Name": "t",
            "IsMultiRegionTrail": True}]}
        ct.get_trail_status.return_value = {"IsLogging": False}
        res = self._checker(ct).check_cloudtrail("us-east-1")
        self.assertFalse(res["enabled"])
        self.assertEqual(res["active_trails"], 0)

    def test_duplicate_arns_counted_once(self):
        ct = MagicMock()
        dup = {"TrailARN": "arn:x:trail/t", "Name": "t",
               "IsMultiRegionTrail": True}
        ct.describe_trails.return_value = {"trailList": [dup, dup]}
        ct.get_trail_status.return_value = {"IsLogging": True}
        ct.get_event_selectors.return_value = {"EventSelectors": []}
        res = self._checker(ct).check_cloudtrail("us-east-1")
        self.assertEqual(res["active_trails"], 1)


class TestLaunchTemplateAudit(unittest.TestCase):
    def _checker(self, fake_ec2):
        c = InstanceSecurityChecker()
        c.get_client = lambda *a, **k: fake_ec2
        return c

    def _fake_ec2(self, templates, version_data):
        ec2 = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [{"LaunchTemplates": templates}]
        ec2.get_paginator.return_value = pag
        ec2.describe_launch_template_versions.return_value = {
            "LaunchTemplateVersions": [{"LaunchTemplateData": version_data}]}
        return ec2

    def test_bad_template_flagged(self):
        ec2 = self._fake_ec2(
            [{"LaunchTemplateId": "lt-1", "LaunchTemplateName": "bad"}],
            {"MetadataOptions": {"HttpTokens": "optional"},
             "NetworkInterfaces": [{"AssociatePublicIpAddress": True}],
             "BlockDeviceMappings": [{"Ebs": {"Encrypted": False}}]})
        res = self._checker(ec2).check_all_launch_templates("us-east-1")
        self.assertEqual(res["template_count"], 1)
        self.assertTrue(res["imdsv2_not_enforced"])
        self.assertTrue(res["assigns_public_ip"])
        self.assertTrue(res["ebs_unencrypted"])

    def test_good_template_clean(self):
        ec2 = self._fake_ec2(
            [{"LaunchTemplateId": "lt-2", "LaunchTemplateName": "good"}],
            {"MetadataOptions": {"HttpTokens": "required"},
             "NetworkInterfaces": [{"AssociatePublicIpAddress": False}],
             "BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]})
        res = self._checker(ec2).check_all_launch_templates("us-east-1")
        self.assertFalse(res["imdsv2_not_enforced"])
        self.assertFalse(res["assigns_public_ip"])
        self.assertFalse(res["ebs_unencrypted"])

    def test_absent_metadata_options_not_flagged(self):
        """No MetadataOptions => inherits default; can't assert, don't flag."""
        ec2 = self._fake_ec2(
            [{"LaunchTemplateId": "lt-3", "LaunchTemplateName": "min"}],
            {"BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]})
        res = self._checker(ec2).check_all_launch_templates("us-east-1")
        self.assertFalse(res["imdsv2_not_enforced"])
        self.assertFalse(res["assigns_public_ip"])


if __name__ == "__main__":
    unittest.main()
