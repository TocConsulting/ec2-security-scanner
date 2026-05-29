"""Network Exposure Checker - Checks G.1 through G.5.

Covers: Unused EIPs, launch template public IP, subnet auto-assign public IP,
VPC Block Public Access, and Transit Gateway auto-accept.
"""

import logging
from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")


class NetworkExposureChecker(BaseChecker):
    """Checks G.1-G.5: Network exposure configuration."""

    def check_unused_eips(self, region: str) -> Dict[str, Any]:
        """G.1 - Unused EIPs should be released.

        EIPs not associated with any instance or ENI indicate
        abandoned resources. Account-level check.
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_addresses()
            addresses = response.get("Addresses", [])

            unused = [
                addr["AllocationId"]
                for addr in addresses
                if not addr.get("AssociationId")
            ]

            return {
                "count": len(unused),
                "eip_allocations": unused,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "count": 0,
                "eip_allocations": [],
            })

    def check_launch_template_public_ip(
        self, instance: Dict, region: str
    ) -> Dict[str, Any]:
        """G.2 - Launch templates should not assign public IPs.

        Checks network interface settings in the launch template.
        """
        lt_info = instance.get("LaunchTemplate")
        if not lt_info:
            return {"assigns_public_ip": False}

        template_id = lt_info.get("LaunchTemplateId")
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_launch_template_versions(
                LaunchTemplateId=template_id,
                Versions=["$Default"],
            )
            versions = response.get("LaunchTemplateVersions", [])
            if not versions:
                return {"assigns_public_ip": False}

            lt_data = versions[0].get("LaunchTemplateData", {})
            enis = lt_data.get("NetworkInterfaces", [])

            for eni in enis:
                if eni.get("AssociatePublicIpAddress", False):
                    return {"assigns_public_ip": True}

            return {"assigns_public_ip": False}
        except ClientError as e:
            return self.handle_client_error(
                e, {"assigns_public_ip": False}
            )

    def check_subnet_auto_assign(
        self, subnet_id: str, region: str
    ) -> Dict[str, Any]:
        """G.3 - Subnets should not auto-assign public IP addresses."""
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_subnets(SubnetIds=[subnet_id])
            subnets = response.get("Subnets", [])

            if not subnets:
                return {"enabled": False}

            enabled = subnets[0].get("MapPublicIpOnLaunch", False)
            return {"enabled": enabled}
        except ClientError as e:
            return self.handle_client_error(e, {"enabled": False})

    def check_vpc_bpa(self, region: str) -> Dict[str, Any]:
        """G.4 - VPC Block Public Access should block IGW traffic.

        Account-level check.
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_vpc_block_public_access_options()
            options = response.get(
                "VpcBlockPublicAccessOptions", {}
            )
            # Check if internet gateway traffic is blocked
            igw_mode = options.get(
                "InternetGatewayBlockMode", "off"
            )
            blocks_igw = igw_mode in (
                "block-bidirectional",
                "block-ingress",
            )
            return {"blocks_igw": blocks_igw}
        except ClientError as e:
            return self.handle_client_error(e, {"blocks_igw": False})

    def check_transit_gateway(self, region: str) -> Dict[str, Any]:
        """G.5 - Transit Gateways should not auto-accept VPC attachment requests.

        Auto-accept allows any VPC to attach without approval.
        Account-level check.
        """
        try:
            ec2 = self.get_client("ec2", region)
            auto_accept_tgws = []
            paginator = ec2.get_paginator(
                "describe_transit_gateways"
            )
            for page in paginator.paginate(
                Filters=[{
                    "Name": "state",
                    "Values": ["available"],
                }]
            ):
                for tgw in page.get("TransitGateways", []):
                    options = tgw.get("Options", {})
                    if options.get(
                        "AutoAcceptSharedAttachments", "disable"
                    ) == "enable":
                        auto_accept_tgws.append(
                            tgw["TransitGatewayId"]
                        )

            return {
                "auto_accept_enabled": len(auto_accept_tgws) > 0,
                "tgw_ids": auto_accept_tgws,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "auto_accept_enabled": False,
                "tgw_ids": [],
            })
