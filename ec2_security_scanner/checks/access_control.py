"""Access Control Checker - Checks D.1 through D.4.

Covers: IAM role least privilege, key pair usage, serial console access,
and EC2 Instance Connect endpoints.
"""

import json
import logging
from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")

# Known overly permissive managed policies
ADMIN_POLICIES = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
]


class AccessControlChecker(BaseChecker):
    """Checks D.1-D.4: Access control configuration."""

    def check_iam_role(
        self, instance: Dict, region: str
    ) -> Dict[str, Any]:
        """D.1 - IAM roles attached to instances should follow least privilege.

        Flags roles with *:* actions, AdministratorAccess, or wildcard resources.
        """
        iam_profile = instance.get("IamInstanceProfile")
        if not iam_profile:
            return {
                "has_admin_access": False,
                "has_wildcard_actions": False,
                "overly_permissive_policies": [],
            }

        profile_arn = iam_profile.get("Arn", "")
        profile_name = (
            profile_arn.split("/")[-1] if "/" in profile_arn else profile_arn
        )

        try:
            iam = self.get_client("iam")
            overly_permissive = []
            has_admin = False
            has_wildcard = False

            # Get instance profile to find the role
            ip_response = iam.get_instance_profile(
                InstanceProfileName=profile_name
            )
            roles = ip_response.get("InstanceProfile", {}).get("Roles", [])

            for role in roles:
                role_name = role["RoleName"]

                # Check attached managed policies
                attached_policies = []
                att_paginator = iam.get_paginator(
                    "list_attached_role_policies"
                )
                for page in att_paginator.paginate(
                    RoleName=role_name
                ):
                    attached_policies.extend(
                        page.get("AttachedPolicies", [])
                    )
                for policy in attached_policies:
                    policy_arn = policy["PolicyArn"]

                    # Check for known admin policies
                    if any(
                        admin_arn in policy_arn
                        for admin_arn in ADMIN_POLICIES
                    ):
                        has_admin = True
                        overly_permissive.append(policy["PolicyName"])
                        continue

                    # Check policy document for wildcards
                    try:
                        policy_detail = iam.get_policy(
                            PolicyArn=policy_arn
                        )
                        version_id = policy_detail["Policy"][
                            "DefaultVersionId"
                        ]
                        version = iam.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )
                        document = version["PolicyVersion"]["Document"]
                        if isinstance(document, str):
                            document = json.loads(document)

                        if self._has_wildcard_permissions(document):
                            has_wildcard = True
                            overly_permissive.append(policy["PolicyName"])
                    except ClientError:
                        continue

                # Check inline policies
                inline_names = []
                inl_paginator = iam.get_paginator(
                    "list_role_policies"
                )
                for page in inl_paginator.paginate(
                    RoleName=role_name
                ):
                    inline_names.extend(
                        page.get("PolicyNames", [])
                    )
                for policy_name in inline_names:
                    try:
                        inline_policy = iam.get_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )
                        document = inline_policy.get("PolicyDocument", {})
                        if isinstance(document, str):
                            document = json.loads(document)

                        if self._has_wildcard_permissions(document):
                            has_wildcard = True
                            overly_permissive.append(policy_name)
                    except ClientError:
                        continue

            return {
                "has_admin_access": has_admin,
                "has_wildcard_actions": has_wildcard,
                "overly_permissive_policies": list(set(overly_permissive)),
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_admin_access": False,
                "has_wildcard_actions": False,
                "overly_permissive_policies": [],
            })

    def _has_wildcard_permissions(self, document: Dict) -> bool:
        """Check if a policy document contains overly broad permissions.

        Flags:
        - Full wildcard: Action=* (regardless of Resource).
        - NotAction or NotResource: inverse statements grant everything
          except what's listed, almost always over-broad.
        - Service or resource wildcard: Action=<service>:*  with a
          Resource that is "*" or ends with ":*" (e.g. "arn:aws:s3:::*").
        """
        statements = document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        def _is_wild_resource(value: str) -> bool:
            return value == "*" or value.endswith(":*")

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            # NotAction / NotResource almost always over-broad.
            if "NotAction" in stmt or "NotResource" in stmt:
                return True

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Action == "*" is admin regardless of Resource.
            if any(a == "*" for a in actions if isinstance(a, str)):
                return True

            # Service-wildcard action + any wildcardish resource.
            has_service_wildcard = any(
                isinstance(a, str) and a.endswith(":*") for a in actions
            )
            has_wild_resource = any(
                isinstance(r, str) and _is_wild_resource(r)
                for r in resources
            )
            if has_service_wildcard and has_wild_resource:
                return True

        return False

    def check_key_pair(
        self, instance: Dict, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """D.2 - Review instances using key pairs.

        Prefer SSM Session Manager or Instance Connect over SSH key pairs.
        """
        key_name = instance.get("KeyName")

        # Check if SSM-managed (mitigates key pair concern)
        ssm_managed = False
        try:
            ssm = self.get_client("ssm", region)
            response = ssm.describe_instance_information(
                Filters=[{
                    "Key": "InstanceIds",
                    "Values": [instance_id],
                }]
            )
            instances = response.get("InstanceInformationList", [])
            ssm_managed = len(instances) > 0
        except ClientError:
            pass

        return {
            "has_key_pair": key_name is not None,
            "key_name": key_name,
            "ssm_managed": ssm_managed,
        }

    def check_serial_console(self, region: str) -> Dict[str, Any]:
        """D.3 - EC2 serial console access should be disabled at account level.

        Account-level check — runs once per scan.
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.get_serial_console_access_status()
            enabled = response.get("SerialConsoleAccessEnabled", False)
            return {"enabled": enabled}
        except ClientError as e:
            return self.handle_client_error(e, {"enabled": False})

    def check_instance_connect(
        self, vpc_id: str, region: str
    ) -> Dict[str, Any]:
        """D.4 - Check if EC2 Instance Connect endpoints are configured.

        Informational check for secure access without public IPs.
        """
        try:
            ec2 = self.get_client("ec2", region)
            endpoints = []
            paginator = ec2.get_paginator(
                "describe_instance_connect_endpoints"
            )
            for page in paginator.paginate(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ):
                endpoints.extend(
                    page.get("InstanceConnectEndpoints", [])
                )
            return {
                "endpoints_configured": len(endpoints) > 0,
            }
        except ClientError as e:
            return self.handle_client_error(
                e, {"endpoints_configured": False}
            )
