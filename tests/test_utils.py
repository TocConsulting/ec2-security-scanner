"""Tests for utility functions."""

import os
import tempfile
import unittest

from botocore.exceptions import ClientError

from ec2_security_scanner.checks.base import BaseChecker
from ec2_security_scanner.utils import (
    setup_logging,
    get_severity_color,
    format_datetime,
)


class TestSetupLogging(unittest.TestCase):
    """Test logging setup."""

    def test_setup_logging_creates_logger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(tmpdir)
            self.assertEqual(logger.name, "ec2_security_scanner")
            self.assertEqual(len(logger.handlers), 2)

    def test_setup_logging_creates_log_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            setup_logging(tmpdir)
            log_files = [f for f in os.listdir(tmpdir) if f.endswith(".log")]
            self.assertEqual(len(log_files), 1)
            self.assertTrue(log_files[0].startswith("ec2_scan_"))


class TestGetSeverityColor(unittest.TestCase):
    """Test severity color mapping."""

    def test_critical_color(self):
        self.assertEqual(get_severity_color("CRITICAL"), "bold red")

    def test_high_color(self):
        self.assertEqual(get_severity_color("HIGH"), "red")

    def test_medium_color(self):
        self.assertEqual(get_severity_color("MEDIUM"), "yellow")

    def test_low_color(self):
        self.assertEqual(get_severity_color("LOW"), "blue")

    def test_unknown_color(self):
        self.assertEqual(get_severity_color("UNKNOWN"), "white")


class TestFormatDatetime(unittest.TestCase):
    """Test datetime formatting."""

    def test_format_string_datetime(self):
        result = format_datetime("2026-03-11T10:30:00Z")
        self.assertIn("2026-03-11", result)

    def test_format_plain_string(self):
        result = format_datetime("not-a-date")
        self.assertEqual(result, "not-a-date")

    def test_format_none(self):
        result = format_datetime(None)
        self.assertEqual(result, "None")


class TestHandleClientError(unittest.TestCase):
    """Test that all permission-denial error codes degrade gracefully."""

    def _client_error(self, code):
        return ClientError(
            {"Error": {"Code": code, "Message": "denied"}}, "DescribeFoo"
        )

    def test_all_access_denied_codes_surface_error(self):
        checker = BaseChecker()
        # EC2 uses UnauthorizedOperation; IAM/STS use AccessDenied(Exception)
        for code in (
            "AccessDenied", "AccessDeniedException",
            "UnauthorizedOperation", "UnauthorizedAccess", "AuthFailure",
        ):
            resp = checker.handle_client_error(
                self._client_error(code), {"enabled": False}
            )
            self.assertIn("error", resp)
            self.assertEqual(resp["enabled"], False)

    def test_non_denial_error_still_returns_error_dict(self):
        checker = BaseChecker()
        resp = checker.handle_client_error(
            self._client_error("ThrottlingException"), {"x": 1}
        )
        self.assertIn("error", resp)


if __name__ == "__main__":
    unittest.main()
