"""Logging & Monitoring Checker - Checks E.1 through E.4.

Covers: CloudTrail EC2 API logging, CloudWatch alarms,
SSM inventory/management, and GuardDuty EC2 protection.
"""

import logging
from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")


class LoggingMonitoringChecker(BaseChecker):
    """Checks E.1-E.4: Logging and monitoring configuration."""

    def check_cloudtrail(self, region: str) -> Dict[str, Any]:
        """E.1 - CloudTrail should be logging EC2 management events.

        Validates:
        - At least one active trail (IsLogging=True)
        - Trail is multi-region (IsMultiRegionTrail=True)
        - Trail captures management events (GetEventSelectors)
        Account-level check — runs once per scan.
        """
        try:
            ct = self.get_client("cloudtrail", region)
            # Include shadow trails: a multi-region trail homed in another
            # region appears here as a shadow and DOES log this region's
            # events. Excluding them caused a false NO_CLOUDTRAIL in every
            # region except the trail's home region. Dedupe by TrailARN so a
            # trail is only counted once.
            response = ct.describe_trails(includeShadowTrails=True)
            trails = response.get("trailList", [])

            active_count = 0
            multi_region_active = False
            management_events_enabled = False
            seen_arns = set()

            for trail in trails:
                arn = trail.get("TrailARN", trail.get("Name", ""))
                if arn in seen_arns:
                    continue
                seen_arns.add(arn)
                # Prefer ARN for cross-region trails; fall back to Name
                trail_ref = trail.get("TrailARN", trail.get("Name", ""))
                try:
                    status = ct.get_trail_status(Name=trail_ref)
                    if not status.get("IsLogging", False):
                        continue

                    active_count += 1

                    if trail.get("IsMultiRegionTrail", False):
                        multi_region_active = True

                    # Verify management events are being captured
                    try:
                        selectors = ct.get_event_selectors(
                            TrailName=trail_ref
                        )
                        for sel in selectors.get("EventSelectors", []):
                            if (sel.get("IncludeManagementEvents", False)
                                    and sel.get("ReadWriteType") in (
                                        "All", "WriteOnly"
                                    )):
                                management_events_enabled = True
                    except ClientError:
                        pass

                except ClientError:
                    continue

            return {
                "enabled": active_count > 0,
                "active_trails": active_count,
                "multi_region": multi_region_active,
                "management_events": management_events_enabled,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enabled": False,
                "active_trails": 0,
                "multi_region": False,
                "management_events": False,
            })

    def check_cloudwatch_alarms(
        self, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """E.2 - EC2 instances should have CloudWatch alarms configured.

        Checks for alarms with InstanceId dimension by retrieving all
        metric alarms and filtering for the specific instance.
        """
        try:
            cw = self.get_client("cloudwatch", region)
            alarm_count = 0
            paginator = cw.get_paginator("describe_alarms")

            for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
                for alarm in page.get("MetricAlarms", []):
                    for dim in alarm.get("Dimensions", []):
                        if (dim.get("Name") == "InstanceId"
                                and dim.get("Value") == instance_id):
                            alarm_count += 1
                            break

            return {
                "has_alarms": alarm_count > 0,
                "alarm_count": alarm_count,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_alarms": False,
                "alarm_count": 0,
            })

    def check_ssm_managed(
        self, instance_id: str, region: str
    ) -> Dict[str, Any]:
        """E.3 - EC2 instances should be managed by AWS Systems Manager.

        Checks if instance appears in SSM managed instance inventory.
        """
        try:
            ssm = self.get_client("ssm", region)
            response = ssm.describe_instance_information(
                Filters=[{
                    "Key": "InstanceIds",
                    "Values": [instance_id],
                }]
            )
            instances = response.get("InstanceInformationList", [])

            if instances:
                ping_status = instances[0].get("PingStatus", "Inactive")
                return {
                    "is_managed": True,
                    "ping_status": ping_status,
                }

            return {
                "is_managed": False,
                "ping_status": None,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "is_managed": False,
                "ping_status": None,
            })

    def check_guardduty(self, region: str) -> Dict[str, Any]:
        """E.4 - GuardDuty should be enabled with EC2 runtime monitoring.

        Account-level check — runs once per scan.
        """
        try:
            gd = self.get_client("guardduty", region)
            detectors = gd.list_detectors()
            detector_ids = detectors.get("DetectorIds", [])

            if not detector_ids:
                return {
                    "enabled": False,
                    "runtime_monitoring": False,
                    "ebs_malware_protection": False,
                }

            # Check first detector's features
            detector = gd.get_detector(DetectorId=detector_ids[0])
            features = detector.get("Features", [])

            runtime_monitoring = False
            ec2_agent_management = False
            ebs_malware = False

            for feature in features:
                name = feature.get("Name", "")
                status = feature.get("Status", "DISABLED")
                if name == "RUNTIME_MONITORING" and status == "ENABLED":
                    runtime_monitoring = True
                    # Check whether automated EC2 agent deployment is enabled.
                    # Without this, Runtime Monitoring is on but agents may
                    # not be deployed on individual instances.
                    for sub in feature.get(
                        "AdditionalConfiguration", []
                    ):
                        if (sub.get("Name") == "EC2_AGENT_MANAGEMENT"
                                and sub.get("Status") == "ENABLED"):
                            ec2_agent_management = True
                elif (name == "EBS_MALWARE_PROTECTION"
                        and status == "ENABLED"):
                    ebs_malware = True

            return {
                "enabled": True,
                "runtime_monitoring": runtime_monitoring,
                "ec2_agent_management": ec2_agent_management,
                "ebs_malware_protection": ebs_malware,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enabled": False,
                "runtime_monitoring": False,
                "ebs_malware_protection": False,
            })
