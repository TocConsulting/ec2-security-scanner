#!/usr/bin/env python3
"""Command-line interface for EC2 Security Scanner."""

import logging
import sys
import traceback

import click
from rich.console import Console

from .scanner import EC2SecurityScanner
from . import __version__

# Configure logging format
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.WARNING,
)

console = Console()

# ASCII Art Banner
BANNER = """[bold red]╔══════════════════════════════════════════════════════════╗
║              EC2 Security Scanner                        ║
║         Comprehensive EC2 Security Auditing              ║
╚══════════════════════════════════════════════════════════╝[/bold red]"""


def print_banner():
    """Print the ASCII art banner."""
    console.print(BANNER)
    console.print(
        f"[dim]  Version {__version__} | "
        "https://github.com/TocConsulting/ec2-security-scanner[/dim]\n"
    )


# ====================================================================
# SHARED OPTIONS (composable decorators)
# ====================================================================


def shared_aws_options(f):
    """AWS connection options shared across commands."""
    f = click.option(
        "-r", "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )(f)
    f = click.option(
        "-p", "--profile",
        default=None,
        help="AWS profile name",
    )(f)
    return f


def shared_output_options(f):
    """Output options shared across commands."""
    f = click.option(
        "-o", "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)",
    )(f)
    f = click.option(
        "-f", "--output-format",
        type=click.Choice(
            ["json", "csv", "html", "all"], case_sensitive=False
        ),
        default="all",
        help="Report format (default: all)",
    )(f)
    return f


def shared_performance_options(f):
    """Performance and logging options shared across commands."""
    f = click.option(
        "-w", "--max-workers",
        default=5,
        type=int,
        help="Worker threads for parallel processing (default: 5)",
    )(f)
    f = click.option(
        "-q", "--quiet",
        is_flag=True,
        help="Suppress console output except errors",
    )(f)
    f = click.option(
        "-d", "--debug",
        is_flag=True,
        help="Enable debug logging",
    )(f)
    return f


def shared_options(f):
    """Apply all shared options to a command."""
    f = shared_aws_options(f)
    f = shared_output_options(f)
    f = shared_performance_options(f)
    return f


# ====================================================================
# MAIN CLI GROUP
# ====================================================================


class CustomGroup(click.Group):
    """Custom Click group with banner display."""

    def format_help(self, ctx, formatter):
        """Write the help into the formatter with banner."""
        print_banner()
        super().format_help(ctx, formatter)


@click.group(
    cls=CustomGroup,
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.version_option(
    version=__version__, prog_name="EC2 Security Scanner"
)
def cli():
    """
    Comprehensive AWS EC2 security scanner for vulnerability detection
    and multi-framework compliance auditing.

    \b
    FRAMEWORKS
    ══════════════════════════════════════════════════════════════
      AWS-FSBP, CIS v5.0, PCI DSS v4.0.1, HIPAA, SOC 2,
      ISO 27001:2022, ISO 27017, ISO 27018, GDPR, NIST 800-53

    \b
    QUICK START
    ══════════════════════════════════════════════════════════════
      Scan all instances:     ec2-security-scanner security
      Use AWS profile:        ec2-security-scanner security -p prod
      Specific region:        ec2-security-scanner security -r eu-west-1
      Specific instances:     ec2-security-scanner security -i i-12345
      Include stopped:        ec2-security-scanner security --state-filter all

    \b
    MORE INFO
    ══════════════════════════════════════════════════════════════
      Run COMMAND --help for detailed options
      Docs: https://github.com/TocConsulting/ec2-security-scanner
    """
    pass


# ====================================================================
# SECURITY COMMAND
# ====================================================================


@cli.command()
@click.option(
    "--instance-id", "-i",
    multiple=True,
    help="Specific instance ID(s) to scan (can be used multiple times)",
)
@click.option(
    "--exclude-instance",
    multiple=True,
    help="Instance ID(s) to exclude from scanning",
)
@click.option(
    "--compliance-only",
    is_flag=True,
    help="Output only the compliance report (skip JSON/CSV/HTML security "
         "reports) and print per-framework failed controls",
)
@click.option(
    "--tag-filter",
    multiple=True,
    help="Filter by tag (Key=Value format)",
)
@click.option(
    "--state-filter",
    type=click.Choice(["running", "stopped", "all"], case_sensitive=False),
    default="running",
    help="Instance state filter (default: running)",
)
@shared_options
def security(
    instance_id, exclude_instance, compliance_only, tag_filter,
    state_filter, region, profile, output_dir, output_format,
    max_workers, quiet, debug,
):
    """
    Scan EC2 instances for security vulnerabilities and compliance issues.

    \b
    Runs 46 security checks across 8 categories and evaluates compliance
    against 10 frameworks with 137 controls.

    \b
    EXAMPLES:
      ec2-security-scanner security
      ec2-security-scanner security -p prod -r us-west-2
      ec2-security-scanner security -i i-abc123 -i i-def456
      ec2-security-scanner security --state-filter all
      ec2-security-scanner security --tag-filter Environment=production
      ec2-security-scanner security --compliance-only
      ec2-security-scanner security -f html -o ./reports
    """
    # Configure logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("ec2_security_scanner").setLevel(
            logging.DEBUG
        )
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner()
        console.print(
            "[bold cyan]Starting EC2 security analysis...[/bold cyan]\n"
        )

    try:
        # Initialize scanner
        scanner = EC2SecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
        )

        # Get instances
        if instance_id:
            # Scan specific instances
            all_instances = scanner.get_all_instances(
                state_filter="all"
            )
            instances_to_scan = [
                i for i in all_instances
                if i["InstanceId"] in instance_id
            ]

            if not instances_to_scan:
                console.print(
                    "[red]None of the specified instances were found[/red]"
                )
                sys.exit(1)
        else:
            instances_to_scan = scanner.get_all_instances(
                state_filter=state_filter
            )

        # Apply tag filters
        if tag_filter:
            for tf in tag_filter:
                if "=" not in tf:
                    console.print(
                        f"[red]Invalid tag filter format: {tf} "
                        "(use Key=Value)[/red]"
                    )
                    sys.exit(1)
                key, value = tf.split("=", 1)
                instances_to_scan = [
                    i for i in instances_to_scan
                    if any(
                        t.get("Key") == key and t.get("Value") == value
                        for t in i.get("Tags", [])
                    )
                ]

        # Apply exclusions
        if exclude_instance:
            original = len(instances_to_scan)
            instances_to_scan = [
                i for i in instances_to_scan
                if i["InstanceId"] not in exclude_instance
            ]
            excluded = original - len(instances_to_scan)
            if not quiet and excluded > 0:
                console.print(
                    f"[yellow]Excluded {excluded} instance(s)[/yellow]"
                )

        if not instances_to_scan:
            console.print(
                "[red]No instances found to scan[/red]"
            )
            sys.exit(1)

        if not quiet:
            console.print(
                f"[green]Scanning {len(instances_to_scan)} "
                f"instance(s)...[/green]\n"
            )

        # Perform scan
        results = scanner.scan_all_instances(instances_to_scan)

        if not results:
            console.print("[red]No results generated[/red]")
            sys.exit(1)

        # Generate reports — compliance_only skips the security reports.
        report_files = scanner.generate_reports(
            results, output_format, compliance_only=compliance_only
        )

        if not quiet:
            scanner.print_summary(results)

            console.print(
                "\n[bold green]Reports Generated:[/bold green]"
            )
            for report_type, file_path in report_files.items():
                console.print(
                    f"  {report_type.upper()}: {file_path}"
                )

        if compliance_only:
            _print_compliance_detail(scanner.scan_compliance)

        if not quiet:
            console.print(
                "\n[bold green]Security scan completed "
                "successfully![/bold green]"
            )
            console.print(f"[dim]Reports saved to: {output_dir}[/dim]")

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted by user[/yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if debug:
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)


def _print_compliance_detail(scan_compliance):
    """Print detailed per-framework failed controls (scan level).

    Account-level controls are counted once; instance-level controls show
    the count of affected instances ("account" for account-wide controls).
    """
    from rich.table import Table

    frameworks = [
        "AWS-FSBP", "CIS-v5.0", "PCI-DSS-v4.0", "HIPAA",
        "SOC2", "ISO27001", "ISO27017", "ISO27018",
        "GDPR", "NIST-800-53",
    ]

    for fw in frameworks:
        fw_status = scan_compliance.get(fw, {})
        failed = fw_status.get("failed", [])
        if not failed:
            continue

        table = Table(
            title=f"{fw} - Failed Controls "
                  f"({fw_status.get('passed_controls', 0)}/"
                  f"{fw_status.get('total_controls', 0)} passed)"
        )
        table.add_column("Control", style="cyan", width=15)
        table.add_column("Description", width=40)
        table.add_column("Severity", width=10)
        table.add_column("Scope / Affected", justify="right", width=16)

        for ctrl in sorted(failed, key=lambda c: c["control_id"]):
            if ctrl.get("scope") == "account":
                affected = "account"
            else:
                affected = f"{len(ctrl.get('instances', []))} instance(s)"
            table.add_row(
                ctrl["control_id"],
                ctrl["description"],
                ctrl.get("severity", "MEDIUM"),
                affected,
            )

        console.print(table)


# For backward compatibility with entry point
main = cli


if __name__ == "__main__":
    cli()
