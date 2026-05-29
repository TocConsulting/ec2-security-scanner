"""Tests for CLI interface."""

import unittest
from unittest.mock import patch, Mock
from click.testing import CliRunner

from ec2_security_scanner.cli import cli


class TestCLI(unittest.TestCase):
    """Test CLI commands and options."""

    def setUp(self):
        self.runner = CliRunner()

    def test_help_shows_banner(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("EC2 Security Scanner", result.output)

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1.0.0", result.output)

    def test_security_help(self):
        result = self.runner.invoke(cli, ["security", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("instance-id", result.output)
        self.assertIn("exclude-instance", result.output)
        self.assertIn("compliance-only", result.output)
        self.assertIn("tag-filter", result.output)
        self.assertIn("state-filter", result.output)
        self.assertIn("region", result.output)
        self.assertIn("profile", result.output)
        self.assertIn("output-format", result.output)

    def test_security_invalid_format(self):
        result = self.runner.invoke(
            cli, ["security", "-f", "xml"]
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_security_invalid_state_filter(self):
        result = self.runner.invoke(
            cli, ["security", "--state-filter", "terminated"]
        )
        self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
