# Contributing to EC2 Security Scanner

Thank you for your interest in contributing to the EC2 Security Scanner! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- AWS CLI configured with appropriate credentials
- Good understanding of AWS EC2 security concepts

### Development Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/TocConsulting/ec2-security-scanner.git
   cd ec2-security-scanner
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   # Install all development dependencies from pyproject.toml
   pip install -e ".[dev]"

   # Or install manually if needed
   pip install pytest pytest-cov black flake8 mypy "moto[ec2,iam,ssm,cloudtrail,cloudwatch,inspector2,backup,guardduty]"
   ```

## Development Workflow

### Code Style and Standards

We maintain high code quality standards using the following tools:

#### Code Formatting
```bash
# Format code with Black
black ec2_security_scanner/
```

#### Code Linting
```bash
# Check code style with flake8
flake8 ec2_security_scanner/

# Type checking with mypy
mypy ec2_security_scanner/
```

#### Testing
```bash
# Run tests with pytest
pytest tests/

# Run tests with coverage
pytest --cov=ec2_security_scanner tests/
```

### Code Quality Requirements

- **Line Length**: Maximum 79 characters (PEP8 standard)
- **Type Hints**: Required for all public functions and methods
- **Docstrings**: Required for all modules, classes, and public functions
- **Error Handling**: ClientError handled at the checker boundary; never let it bubble out of a check
- **Security**: No hardcoded credentials or sensitive information
- **Read-only**: The scanner must remain strictly read-only. No `create_*`, `modify_*`, `put_*`, `delete_*`, or `enable_*` calls in checker code.

## Making Changes

### Branch Naming Convention

- `feature/description-of-feature` - New features
- `bugfix/description-of-bug` - Bug fixes
- `docs/description-of-changes` - Documentation updates
- `refactor/description-of-refactor` - Code refactoring

### Commit Message Format

```
type(scope): short description

Longer description if needed

- List any breaking changes
- Reference issues: Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, well-documented code
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run all checks
   black ec2_security_scanner/
   flake8 ec2_security_scanner/
   pytest tests/
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(scanner): add new security check for VPC endpoints"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit Pull Request**
   - Provide clear description of changes
   - Reference any related issues
   - Include test results if applicable

## Testing Guidelines

### Test Structure

```
tests/
├── __init__.py
├── test_cli.py                  # CLI option and command tests
├── test_compliance.py           # Compliance framework validation
├── test_instance_security.py    # A.1-A.8 checker tests
├── test_network_security.py     # B.x checker tests
├── test_storage_security.py     # C.x checker tests
├── test_scoring.py              # Non-stacking scoring logic
└── test_utils.py                # Logging, formatting utilities
```

### Writing Tests

- Test individual functions and methods
- Use `unittest` (Python standard library) or `pytest`
- Mock AWS services using `unittest.mock` or `moto[ec2,iam,ssm,...]`
- Aim for good test coverage on every new check

### Example Test

```python
import unittest
from unittest.mock import Mock
from ec2_security_scanner.checks.instance_security import (
    InstanceSecurityChecker,
)


class TestIMDSv2(unittest.TestCase):
    def test_imdsv2_enforced(self):
        checker = InstanceSecurityChecker(lambda: Mock())
        instance = {
            "MetadataOptions": {
                "HttpTokens": "required",
                "HttpPutResponseHopLimit": 1,
            }
        }
        result = checker.check_imdsv2(instance)
        self.assertTrue(result["enforced"])
        self.assertTrue(result["hop_limit_safe"])
```

## Architecture Guidelines

### Project Structure

```
ec2_security_scanner/
├── __init__.py
├── cli.py                  # Click CLI
├── scanner.py              # Facade / orchestrator
├── compliance.py           # 137 controls / 10 frameworks
├── html_reporter.py        # Jinja2 HTML report
├── utils.py                # Logging, scoring
├── checks/
│   ├── base.py             # BaseChecker (session factory, error handling)
│   ├── instance_security.py
│   ├── network_security.py
│   ├── storage_security.py
│   ├── access_control.py
│   ├── logging_monitoring.py
│   ├── patch_vulnerability.py
│   ├── network_exposure.py
│   └── tagging_inventory.py
└── templates/
    └── report.html
```

### Adding New Features

#### New Security Checks

1. Add a `check_*` method to the appropriate checker module under `checks/`.
2. Wire it into `EC2SecurityScanner.scan_instance` (or `scan_account_security` / `scan_vpc_security` for account- or VPC-level checks).
3. Add issue analysis in `_analyze_issues` with a severity, issue type, description, and recommendation.
4. Add framework mappings in `compliance.py` if the check maps to a known control.
5. Add a scoring rule in `utils.calculate_security_score` if the check should affect the 0-100 score.
6. Add tests under `tests/`.

#### New Compliance Frameworks

1. Add framework definition to `ComplianceChecker._define_frameworks`.
2. Update CLI help text and README.
3. Add tests that verify control count and pass/fail behaviour.

#### New Report Formats

1. Create a new reporter class (follow `HTMLReporter` pattern).
2. Add an export method to `EC2SecurityScanner.generate_reports`.
3. Update CLI options.

## Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Python version, AWS region
- **Steps to Reproduce**: Clear steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Error Messages**: Full error messages and stack traces
- **Configuration**: Sanitized configuration details

## Feature Requests

When requesting features, please include:

- **Use Case**: Why this feature would be useful
- **Proposed Solution**: How you envision the feature working
- **Alternatives**: Alternative approaches you've considered
- **Compatibility**: Impact on existing functionality

## Documentation

### Documentation Types

- **Code Documentation**: Inline comments and docstrings
- **User Documentation**: README and usage guides
- **Developer Documentation**: Architecture and contribution guides

### Documentation Standards

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## Security Considerations

### Reporting Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please email security issues to: contact@tocconsulting.fr

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Guidelines

- Never commit AWS credentials or other secrets
- Use environment variables for sensitive configuration
- Follow AWS security best practices
- Validate all user inputs
- Use secure coding practices

## Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check README and inline documentation first

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Release Process

1. **Version Bumping**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Release Notes**: Document new features and fixes in GitHub release notes
3. **Testing**: Run full test suite and manual testing
4. **Documentation**: Update documentation as needed
5. **Release**: Create GitHub release with release notes
6. **Distribution**: Publish to PyPI

Thank you for contributing to making AWS EC2 environments more secure!
