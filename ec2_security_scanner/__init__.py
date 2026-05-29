"""EC2 Security Scanner - Comprehensive AWS EC2 security auditing tool
with multi-framework compliance mapping."""

__version__ = "1.0.0"
__author__ = "Toc Consulting"
__email__ = "tarek@tocconsulting.fr"

from .scanner import EC2SecurityScanner
from .compliance import ComplianceChecker

__all__ = ["EC2SecurityScanner", "ComplianceChecker"]
