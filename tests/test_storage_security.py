"""Tests for Storage Security Checker (C.1-C.6)."""

import unittest
from unittest.mock import Mock, MagicMock

from ec2_security_scanner.checks.storage_security import (
    StorageSecurityChecker,
)


def _mock_paginator(pages):
    """Create a mock paginator that yields the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


class TestEBSEncryption(unittest.TestCase):
    """Test C.1 - EBS volume encryption."""

    def test_all_encrypted(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value = _mock_paginator([{
            "Volumes": [
                {"VolumeId": "vol-1", "Encrypted": True},
                {"VolumeId": "vol-2", "Encrypted": True},
            ]
        }])
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_ebs_encryption("i-12345", "us-east-1")
        self.assertTrue(result["all_encrypted"])
        self.assertEqual(result["volume_count"], 2)
        self.assertEqual(result["encrypted_count"], 2)
        self.assertEqual(result["unencrypted_volumes"], [])

    def test_unencrypted_volume(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value = _mock_paginator([{
            "Volumes": [
                {"VolumeId": "vol-1", "Encrypted": True},
                {"VolumeId": "vol-2", "Encrypted": False},
            ]
        }])
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_ebs_encryption("i-12345", "us-east-1")
        self.assertFalse(result["all_encrypted"])
        self.assertIn("vol-2", result["unencrypted_volumes"])

    def test_no_volumes(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value = _mock_paginator([{
            "Volumes": []
        }])
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_ebs_encryption("i-12345", "us-east-1")
        self.assertTrue(result["all_encrypted"])
        self.assertEqual(result["volume_count"], 0)


class TestEBSDefaultEncryption(unittest.TestCase):
    """Test C.2 - EBS default encryption."""

    def test_enabled(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_ebs_encryption_by_default.return_value = {
            "EbsEncryptionByDefault": True
        }
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_ebs_default_encryption("us-east-1")
        self.assertTrue(result["enabled"])

    def test_disabled(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_ebs_encryption_by_default.return_value = {
            "EbsEncryptionByDefault": False
        }
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_ebs_default_encryption("us-east-1")
        self.assertFalse(result["enabled"])


class TestPublicAMI(unittest.TestCase):
    """Test C.6 - Public AMI sharing."""

    def _mock_paginator(self, pages):
        paginator = Mock()
        paginator.paginate.return_value = iter(pages)
        return paginator

    def test_no_public_amis(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value = self._mock_paginator([
            {"Images": [{"ImageId": "ami-1", "Public": False}]},
        ])
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_public_ami("us-east-1")
        self.assertFalse(result["has_public_amis"])

    def test_public_ami_found(self):
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value = self._mock_paginator([
            {"Images": [
                {"ImageId": "ami-1", "Public": False},
                {"ImageId": "ami-2", "Public": True},
            ]},
        ])
        mock_session.client.return_value = mock_ec2

        checker = StorageSecurityChecker(lambda: mock_session)
        result = checker.check_public_ami("us-east-1")
        self.assertTrue(result["has_public_amis"])
        self.assertIn("ami-2", result["public_ami_ids"])


class TestSnapshotSharing(unittest.TestCase):
    """Test C.3 - public and cross-account EBS snapshot sharing."""

    def _checker(self, snapshots, perms):
        mock_ec2 = Mock()

        def _get_paginator(name):
            p = Mock()
            if name == "describe_volumes":
                p.paginate.return_value = iter(
                    [{"Volumes": [{"VolumeId": "vol-1"}]}])
            else:  # describe_snapshots
                p.paginate.return_value = iter([{"Snapshots": snapshots}])
            return p

        mock_ec2.get_paginator.side_effect = _get_paginator
        mock_ec2.describe_snapshot_attribute.return_value = {
            "CreateVolumePermissions": perms}
        mock_session = Mock()
        mock_session.client.return_value = mock_ec2
        return StorageSecurityChecker(lambda: mock_session)

    def test_cross_account_share_flagged(self):
        checker = self._checker(
            [{"SnapshotId": "snap-1"}], [{"UserId": "999999999999"}])
        result = checker.check_ebs_snapshot_public("i-1", "us-east-1")
        self.assertTrue(result["has_external_shares"])
        self.assertFalse(result["has_public_snapshots"])
        self.assertEqual(
            result["shared_snapshots"][0]["accounts"], ["999999999999"])

    def test_public_snapshot_still_flagged(self):
        checker = self._checker(
            [{"SnapshotId": "snap-1"}], [{"Group": "all"}])
        result = checker.check_ebs_snapshot_public("i-1", "us-east-1")
        self.assertTrue(result["has_public_snapshots"])
        self.assertFalse(result["has_external_shares"])

    def test_unshared_snapshot_clean(self):
        checker = self._checker([{"SnapshotId": "snap-1"}], [])
        result = checker.check_ebs_snapshot_public("i-1", "us-east-1")
        self.assertFalse(result["has_external_shares"])
        self.assertFalse(result["has_public_snapshots"])


if __name__ == "__main__":
    unittest.main()
