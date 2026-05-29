"""Tests for Network Security Checker (B.1-B.10)."""

import unittest
from unittest.mock import Mock

from ec2_security_scanner.checks.network_security import (
    NetworkSecurityChecker,
)


class TestSGSSHCheck(unittest.TestCase):
    """Test B.2 - Open SSH check."""

    def test_ssh_open_to_world(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_ssh(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["open_to_world"])
        self.assertIn("sg-123", result["offending_sgs"])

    def test_ssh_restricted(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_ssh(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertFalse(result["open_to_world"])

    def test_ssh_open_ipv6(self):
        sg_rules = [{
            "GroupId": "sg-456",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_ssh(
            ["sg-456"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["open_to_world"])


class TestSGHighRiskPorts(unittest.TestCase):
    """Test B.4 - High-risk ports check."""

    def test_no_high_risk_ports(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_high_risk_ports(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertFalse(result["has_violations"])

    def test_mysql_port_open(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_high_risk_ports(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["has_violations"])
        self.assertIn(3306, result["open_ports"])

    def test_all_traffic_open(self):
        """Protocol -1 (all traffic) should flag all high-risk ports."""
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_high_risk_ports(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["has_violations"])
        self.assertGreater(len(result["open_ports"]), 0)


class TestSGEgressCheck(unittest.TestCase):
    """Test B.9 - Unrestricted egress."""

    def test_unrestricted_egress(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [],
            "IpPermissionsEgress": [{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_egress(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["unrestricted"])

    def test_restricted_egress(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [],
            "IpPermissionsEgress": [{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_egress(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertFalse(result["unrestricted"])


class TestSGAuthorizedPorts(unittest.TestCase):
    """Test B.10 - Authorized ports only."""

    def test_authorized_port_80(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_authorized_ports(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertFalse(result["has_violations"])

    def test_unauthorized_port_8080(self):
        sg_rules = [{
            "GroupId": "sg-123",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 8080,
                "ToPort": 8080,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [],
        }]
        checker = NetworkSecurityChecker()
        result = checker.check_sg_authorized_ports(
            ["sg-123"], "us-east-1", sg_rules=sg_rules
        )
        self.assertTrue(result["has_violations"])
        self.assertIn(8080, result["unauthorized_ports"])


class TestSourceDestCheck(unittest.TestCase):
    """Test B.8 - Source/destination check."""

    def test_source_dest_enabled(self):
        instance = {
            "NetworkInterfaces": [{"SourceDestCheck": True}]
        }
        checker = NetworkSecurityChecker()
        result = checker.check_source_dest(instance)
        self.assertTrue(result["enabled"])

    def test_source_dest_disabled(self):
        instance = {
            "NetworkInterfaces": [{"SourceDestCheck": False}]
        }
        checker = NetworkSecurityChecker()
        result = checker.check_source_dest(instance)
        self.assertFalse(result["enabled"])


if __name__ == "__main__":
    unittest.main()
