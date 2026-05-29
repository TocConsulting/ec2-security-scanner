"""Tagging & Inventory Checker - Checks H.1 through H.3.

Covers: Required tags, stopped instance cleanup, and unused security groups.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")


class TaggingInventoryChecker(BaseChecker):
    """Checks H.1-H.3: Tagging and inventory management."""

    DEFAULT_REQUIRED_TAGS = ["Name", "Environment", "Owner"]

    def check_required_tags(
        self, instance: Dict,
        required_tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """H.1 - EC2 resources should have required tags.

        Default required tags: Name, Environment, Owner.
        """
        if required_tags is None:
            required_tags = self.DEFAULT_REQUIRED_TAGS

        tags = instance.get("Tags", [])
        tag_dict = {t["Key"]: t["Value"] for t in tags}

        missing = [
            tag for tag in required_tags if tag not in tag_dict
        ]

        return {
            "has_required_tags": len(missing) == 0,
            "missing_tags": missing,
            "all_tags": tag_dict,
        }

    def check_stopped_instance(
        self, instance: Dict,
        threshold_days: int = 30,
    ) -> Dict[str, Any]:
        """H.2 - Stopped instances should be removed after threshold period.

        Parses StateTransitionReason to determine how long ago instance stopped.
        """
        state = instance.get("State", {}).get("Name", "")
        if state != "stopped":
            return {
                "is_stopped": False,
                "stopped_days": None,
                "exceeds_threshold": False,
            }

        # Parse StateTransitionReason for timestamp
        # Format: "User initiated (YYYY-MM-DD HH:MM:SS GMT)"
        reason = instance.get("StateTransitionReason", "")
        stopped_days = None

        match = re.search(
            r"\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+)\)",
            reason,
        )
        if match:
            try:
                date_str = match.group(1).replace(" GMT", "")
                stopped_date = datetime.strptime(
                    date_str, "%Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                stopped_days = (
                    datetime.now(timezone.utc) - stopped_date
                ).days
            except (ValueError, TypeError):
                pass

        return {
            "is_stopped": True,
            "stopped_days": stopped_days,
            "exceeds_threshold": (
                stopped_days is not None
                and stopped_days > threshold_days
            ),
        }

    def check_unused_sgs(
        self, sg_ids: List[str], region: str
    ) -> Dict[str, Any]:
        """H.3 - Unused security groups should be removed (account-level).

        Lists every non-default security group in the region and reports the
        ones not attached to any ENI. The `sg_ids` argument is unused but kept
        for backward compatibility with the per-instance call site.
        """
        try:
            ec2 = self.get_client("ec2", region)

            # 1) All non-default SGs in the region.
            all_sg_ids: list = []
            sg_paginator = ec2.get_paginator("describe_security_groups")
            for page in sg_paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    if sg.get("GroupName") != "default":
                        all_sg_ids.append(sg["GroupId"])

            if not all_sg_ids:
                return {"count": 0, "unused_sg_ids": []}

            # 2) All SG IDs actually attached to at least one ENI.
            used: set = set()
            eni_paginator = ec2.get_paginator(
                "describe_network_interfaces"
            )
            for page in eni_paginator.paginate():
                for eni in page.get("NetworkInterfaces", []):
                    for grp in eni.get("Groups", []):
                        used.add(grp.get("GroupId"))

            unused = [sid for sid in all_sg_ids if sid not in used]
            return {
                "count": len(unused),
                "unused_sg_ids": unused,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "count": 0,
                "unused_sg_ids": [],
            })
