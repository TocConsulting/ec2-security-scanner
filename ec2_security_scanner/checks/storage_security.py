"""Storage Security Checker - Checks C.1 through C.6.

Covers: EBS volume encryption, default encryption, public snapshots,
backup plans, launch template EBS encryption, and public AMI sharing.
"""

import logging
from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")


class StorageSecurityChecker(BaseChecker):
    """Checks C.1-C.6: Storage-level security configuration."""

    def check_ebs_encryption(
        self, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """C.1 - All attached EBS volumes should be encrypted at rest."""
        try:
            ec2 = self.get_client("ec2", region)
            volumes = []
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate(
                Filters=[{
                    "Name": "attachment.instance-id",
                    "Values": [instance_id],
                }]
            ):
                volumes.extend(page.get("Volumes", []))

            if not volumes:
                return {
                    "all_encrypted": True,
                    "volume_count": 0,
                    "encrypted_count": 0,
                    "unencrypted_volumes": [],
                }

            encrypted_count = 0
            unencrypted = []
            for vol in volumes:
                if vol.get("Encrypted", False):
                    encrypted_count += 1
                else:
                    unencrypted.append(vol["VolumeId"])

            return {
                "all_encrypted": len(unencrypted) == 0,
                "volume_count": len(volumes),
                "encrypted_count": encrypted_count,
                "unencrypted_volumes": unencrypted,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "all_encrypted": True,
                "volume_count": 0,
                "encrypted_count": 0,
                "unencrypted_volumes": [],
            })

    def check_ebs_default_encryption(
        self, region: str
    ) -> Dict[str, Any]:
        """C.2 - EBS default encryption should be enabled at account/region level."""
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.get_ebs_encryption_by_default()
            enabled = response.get("EbsEncryptionByDefault", False)
            return {"enabled": enabled}
        except ClientError as e:
            return self.handle_client_error(e, {"enabled": False})

    def check_ebs_snapshot_public(
        self, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """C.3 - EBS snapshots should not be publicly restorable.

        Checks snapshots associated with the instance's volumes.
        """
        try:
            ec2 = self.get_client("ec2", region)

            # Get volumes attached to instance
            volume_ids = []
            vol_paginator = ec2.get_paginator("describe_volumes")
            for page in vol_paginator.paginate(
                Filters=[{
                    "Name": "attachment.instance-id",
                    "Values": [instance_id],
                }]
            ):
                volume_ids.extend(
                    v["VolumeId"] for v in page.get("Volumes", [])
                )

            if not volume_ids:
                return {
                    "has_public_snapshots": False,
                    "public_snapshot_ids": [],
                }

            # Get snapshots for these volumes
            snapshots = []
            snap_paginator = ec2.get_paginator("describe_snapshots")
            for page in snap_paginator.paginate(
                Filters=[{
                    "Name": "volume-id",
                    "Values": volume_ids,
                }],
                OwnerIds=["self"],
            ):
                snapshots.extend(page.get("Snapshots", []))

            public_snapshots = []
            for snap in snapshots:
                try:
                    attr_response = ec2.describe_snapshot_attribute(
                        SnapshotId=snap["SnapshotId"],
                        Attribute="createVolumePermission",
                    )
                    perms = attr_response.get(
                        "CreateVolumePermissions", []
                    )
                    for perm in perms:
                        if perm.get("Group") == "all":
                            public_snapshots.append(snap["SnapshotId"])
                            break
                except ClientError:
                    continue

            return {
                "has_public_snapshots": len(public_snapshots) > 0,
                "public_snapshot_ids": public_snapshots,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_public_snapshots": False,
                "public_snapshot_ids": [],
            })

    def check_ebs_backup(
        self, instance_id: str, region: str,
        account_id: str = "",
    ) -> Dict[str, Any]:
        """C.4 - EBS volumes should be covered by a backup plan.

        Uses describe_protected_resource (O(1)) to check the instance ARN
        and each attached volume ARN directly, avoiding a full account
        list_protected_resources scan that causes throttling at scale.
        Falls back gracefully if the resource is not found.
        """
        try:
            ec2 = self.get_client("ec2", region)
            backup = self.get_client("backup", region)

            # Get volume IDs attached to this instance
            volume_ids = []
            vol_paginator = ec2.get_paginator("describe_volumes")
            for page in vol_paginator.paginate(
                Filters=[{
                    "Name": "attachment.instance-id",
                    "Values": [instance_id],
                }]
            ):
                volume_ids.extend(
                    v["VolumeId"] for v in page.get("Volumes", [])
                )

            # Build candidate ARNs if account_id is available (O(1) checks).
            # Derive the ARN partition from the region so GovCloud (aws-us-gov),
            # China (aws-cn), and ISO partitions also work.
            if account_id:
                session = (
                    self.session_factory()
                    if callable(self.session_factory)
                    else self.session_factory
                )
                partition = (
                    session.get_partition_for_region(region)
                    if session is not None
                    else "aws"
                )
                candidate_arns = [
                    f"arn:{partition}:ec2:{region}:{account_id}"
                    f":instance/{instance_id}",
                ] + [
                    f"arn:{partition}:ec2:{region}:{account_id}:volume/{vid}"
                    for vid in volume_ids
                ]
                for arn in candidate_arns:
                    try:
                        backup.describe_protected_resource(
                            ResourceArn=arn
                        )
                        return {"covered": True}
                    except ClientError as e:
                        err = e.response.get("Error", {}).get("Code", "")
                        if err == "ResourceNotFoundException":
                            continue
                        raise
                return {"covered": False}

            # Fallback: paginate (used when account_id unavailable)
            paginator = backup.get_paginator("list_protected_resources")
            for page in paginator.paginate():
                for resource in page.get("Results", []):
                    resource_arn = resource.get("ResourceArn", "")
                    resource_type = resource.get("ResourceType", "")
                    if (resource_type == "EC2"
                            and resource_arn.endswith(instance_id)):
                        return {"covered": True}
                    if resource_type == "EBS":
                        for vid in volume_ids:
                            if resource_arn.endswith(vid):
                                return {"covered": True}
            return {"covered": False}

        except ClientError as e:
            return self.handle_client_error(e, {"covered": False})

    def check_launch_template_ebs(
        self, instance: Dict, region: str
    ) -> Dict[str, Any]:
        """C.5 - Launch template EBS volumes should be encrypted."""
        lt_info = instance.get("LaunchTemplate")
        if not lt_info:
            return {
                "checked": False,
                "all_encrypted": True,  # Not applicable
            }

        template_id = lt_info.get("LaunchTemplateId")
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_launch_template_versions(
                LaunchTemplateId=template_id,
                Versions=["$Default"],
            )
            versions = response.get("LaunchTemplateVersions", [])
            if not versions:
                return {
                    "checked": True,
                    "all_encrypted": False,
                }

            lt_data = versions[0].get("LaunchTemplateData", {})
            bdms = lt_data.get("BlockDeviceMappings", [])

            if not bdms:
                return {
                    "checked": True,
                    "all_encrypted": True,  # No block devices defined
                }

            all_encrypted = all(
                bdm.get("Ebs", {}).get("Encrypted", False)
                for bdm in bdms
                if "Ebs" in bdm
            )

            return {
                "checked": True,
                "all_encrypted": all_encrypted,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "checked": False,
                "all_encrypted": False,
            })

    def check_ebs_snapshot_bpa(self, region: str) -> Dict[str, Any]:
        """C.7 - Account-level EBS Snapshot Block Public Access (FSBP EC2.182).

        Checks whether the account-level Block Public Access setting for EBS
        snapshots is set to 'block-all-sharing'. This is a preventive control
        distinct from C.3 which detects already-public individual snapshots.

        Requires: ec2:GetSnapshotBlockPublicAccessState
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.get_snapshot_block_public_access_state()
            state = response.get("State", "unblocked")
            managed_by = response.get("ManagedBy", "account")
            return {
                "state": state,
                # Only 'block-all-sharing' satisfies FSBP EC2.182
                "blocked": state == "block-all-sharing",
                "managed_by": managed_by,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "state": "unblocked",
                "blocked": False,
                "managed_by": "account",
            })

    def check_public_ami(self, region: str) -> Dict[str, Any]:
        """C.6 - Account-owned AMIs should not be publicly shared.

        This is an account-level check — runs once per scan.
        """
        try:
            ec2 = self.get_client("ec2", region)
            public_amis: list = []
            paginator = ec2.get_paginator("describe_images")
            for page in paginator.paginate(Owners=["self"]):
                for img in page.get("Images", []):
                    if img.get("Public", False):
                        public_amis.append(img["ImageId"])

            return {
                "has_public_amis": len(public_amis) > 0,
                "public_ami_ids": public_amis,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_public_amis": False,
                "public_ami_ids": [],
            })
