"""Tests for Instance Security Checker (A.1-A.8)."""

import base64
import unittest
from unittest.mock import Mock, patch

from ec2_security_scanner.checks.instance_security import (
    InstanceSecurityChecker,
)


class TestIMDSv2Check(unittest.TestCase):
    """Test A.1 - IMDSv2 enforcement."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_imdsv2_enforced(self):
        instance = {
            "MetadataOptions": {
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
            }
        }
        result = self.checker.check_imdsv2(instance)
        self.assertTrue(result["enforced"])
        self.assertEqual(result["http_tokens"], "required")

    def test_imdsv2_not_enforced(self):
        instance = {
            "MetadataOptions": {
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled",
            }
        }
        result = self.checker.check_imdsv2(instance)
        self.assertFalse(result["enforced"])

    def test_imdsv2_missing_metadata_options(self):
        instance = {}
        result = self.checker.check_imdsv2(instance)
        self.assertFalse(result["enforced"])
        self.assertEqual(result["http_tokens"], "optional")


class TestPublicIPCheck(unittest.TestCase):
    """Test A.3 - Public IP check."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_no_public_ip(self):
        instance = {"NetworkInterfaces": [{"PrivateIpAddress": "10.0.0.1"}]}
        result = self.checker.check_public_ip(instance)
        self.assertFalse(result["has_public_ip"])
        self.assertIsNone(result["public_ip_address"])

    def test_has_public_ip(self):
        instance = {
            "PublicIpAddress": "54.1.2.3",
            "NetworkInterfaces": [],
        }
        result = self.checker.check_public_ip(instance)
        self.assertTrue(result["has_public_ip"])
        self.assertEqual(result["public_ip_address"], "54.1.2.3")

    def test_eip_associated(self):
        instance = {
            "NetworkInterfaces": [{
                "Association": {"PublicIp": "52.10.20.30"}
            }],
        }
        result = self.checker.check_public_ip(instance)
        self.assertTrue(result["has_public_ip"])
        self.assertTrue(result["eip_associated"])


class TestIAMProfileCheck(unittest.TestCase):
    """Test A.4 - IAM instance profile."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_no_profile(self):
        instance = {}
        result = self.checker.check_iam_profile(instance)
        self.assertFalse(result["attached"])

    def test_has_profile(self):
        instance = {
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/my-role"
            }
        }
        result = self.checker.check_iam_profile(instance)
        self.assertTrue(result["attached"])
        self.assertEqual(result["profile_name"], "my-role")


class TestVirtualizationCheck(unittest.TestCase):
    """Test A.5 - Virtualization type."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_hvm(self):
        result = self.checker.check_virtualization({"VirtualizationType": "hvm"})
        self.assertTrue(result["is_hvm"])

    def test_paravirtual(self):
        result = self.checker.check_virtualization({"VirtualizationType": "paravirtual"})
        self.assertFalse(result["is_hvm"])


class TestNetworkInterfacesCheck(unittest.TestCase):
    """Test A.6 - Multiple ENIs."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_single_eni(self):
        instance = {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]}
        result = self.checker.check_network_interfaces(instance)
        self.assertFalse(result["has_multiple"])
        self.assertEqual(result["count"], 1)

    def test_multiple_enis(self):
        instance = {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1"},
            {"NetworkInterfaceId": "eni-2"},
        ]}
        result = self.checker.check_network_interfaces(instance)
        self.assertTrue(result["has_multiple"])
        self.assertEqual(result["count"], 2)


class TestMonitoringCheck(unittest.TestCase):
    """Test A.7 - Detailed monitoring."""

    def setUp(self):
        self.checker = InstanceSecurityChecker()

    def test_monitoring_enabled(self):
        result = self.checker.check_monitoring({"Monitoring": {"State": "enabled"}})
        self.assertTrue(result["detailed_enabled"])

    def test_monitoring_disabled(self):
        result = self.checker.check_monitoring({"Monitoring": {"State": "disabled"}})
        self.assertFalse(result["detailed_enabled"])


class TestUserDataSecretsCheck(unittest.TestCase):
    """Test A.8 - Exposed secrets in UserData."""

    def _make_checker_with_userdata(self, userdata_text):
        """Create a checker that returns specified UserData."""
        mock_session = Mock()
        mock_ec2 = Mock()

        encoded = base64.b64encode(userdata_text.encode()).decode()
        mock_ec2.describe_instance_attribute.return_value = {
            "UserData": {"Value": encoded}
        }
        mock_session.client.return_value = mock_ec2

        checker = InstanceSecurityChecker(lambda: mock_session)
        return checker

    def test_no_userdata(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.describe_instance_attribute.return_value = {
            "UserData": {}
        }
        mock_session.client.return_value = mock_ec2

        checker = InstanceSecurityChecker(lambda: mock_session)
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertFalse(result["has_userdata"])
        self.assertFalse(result["has_secrets"])

    def test_clean_userdata(self):
        checker = self._make_checker_with_userdata(
            "#!/bin/bash\nyum update -y\necho hello"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_userdata"])
        self.assertFalse(result["has_secrets"])

    def test_aws_access_key_detected(self):
        checker = self._make_checker_with_userdata(
            "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_secrets"])
        self.assertGreater(result["finding_count"], 0)
        self.assertEqual(result["findings"][0]["type"], "AWS_ACCESS_KEY")

    def test_password_detected(self):
        checker = self._make_checker_with_userdata(
            "DB_PASSWORD=SuperSecret123"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_secrets"])

    def test_private_key_detected(self):
        checker = self._make_checker_with_userdata(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_secrets"])

    def test_github_token_detected(self):
        checker = self._make_checker_with_userdata(
            "GITHUB_TOKEN=ghp_ABCDEFghijklmnopqrstuvwxyz1234567890"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_secrets"])

    def test_connection_string_detected(self):
        checker = self._make_checker_with_userdata(
            "DATABASE_URL=postgres://admin:password@db.example.com/mydb"
        )
        result = checker.check_userdata_secrets("i-12345", "us-east-1")
        self.assertTrue(result["has_secrets"])


if __name__ == "__main__":
    unittest.main()
