"""Network Security Checker - Checks B.1 through B.10.

Covers: Default SG restrictions, SSH/RDP/high-risk/remote-admin port checks,
VPC flow logs, NACLs, source/dest check, SG egress, and authorized ports.

Optimization: Security group rules are fetched ONCE per instance via
_get_security_group_rules() and reused across B.2-B.5, B.9-B.10.
"""

import logging
from typing import Dict, Any, List, Optional

from botocore.exceptions import ClientError

from .base import BaseChecker


logger = logging.getLogger("ec2_security_scanner")

# Open CIDR ranges that indicate "open to the world"
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class NetworkSecurityChecker(BaseChecker):
    """Checks B.1-B.10: Network-level security configuration."""

    # High-risk ports per FSBP EC2.19 (24 ports)
    HIGH_RISK_PORTS = [
        20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434,
        3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601,
        8080, 8088, 8888, 9200, 9300,
    ]

    # Remote admin ports (SSH, RDP, WinRM HTTP/HTTPS)
    REMOTE_ADMIN_PORTS = [22, 3389, 5985, 5986]

    # Default authorized ports for public access
    DEFAULT_AUTHORIZED_PORTS = [80, 443]

    def _get_security_group_rules(
        self, sg_ids: List[str], region: str
    ) -> List[Dict]:
        """Fetch security group rules once, reused by B.2-B.5, B.9-B.10.

        Args:
            sg_ids: List of security group IDs
            region: AWS region

        Returns:
            List of security group dicts with IpPermissions/IpPermissionsEgress
        """
        if not sg_ids:
            return []

        try:
            ec2 = self.get_client("ec2", region)
            sgs = []
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate(GroupIds=sg_ids):
                sgs.extend(page.get("SecurityGroups", []))
            return sgs
        except ClientError as e:
            logger.warning(f"Error fetching SG rules: {e}")
            return []

    def _is_port_open_to_world(
        self, sg_rules: List[Dict], port: int, direction: str = "ingress"
    ) -> List[str]:
        """Check if a specific port is open to 0.0.0.0/0 or ::/0.

        Returns list of offending security group IDs.
        """
        offending = []
        for sg in sg_rules:
            permissions = (
                sg.get("IpPermissions", [])
                if direction == "ingress"
                else sg.get("IpPermissionsEgress", [])
            )
            for perm in permissions:
                if self._permission_allows_port(perm, port):
                    cidrs = {
                        r.get("CidrIp", "")
                        for r in perm.get("IpRanges", [])
                    }
                    ipv6_cidrs = {
                        r.get("CidrIpv6", "")
                        for r in perm.get("Ipv6Ranges", [])
                    }
                    if cidrs & OPEN_CIDRS or ipv6_cidrs & OPEN_CIDRS:
                        offending.append(sg["GroupId"])
                        break
        return offending

    def _is_port_open_to_ipv4(
        self, sg_rules: List[Dict], port: int
    ) -> List[str]:
        """Check if a port is open to 0.0.0.0/0 (IPv4 only).

        Used to distinguish CIS 5.3 (IPv4) from CIS 5.4 (IPv6).
        Returns list of offending security group IDs.
        """
        offending = []
        for sg in sg_rules:
            for perm in sg.get("IpPermissions", []):
                if not self._permission_allows_port(perm, port):
                    continue
                cidrs = {
                    r.get("CidrIp", "")
                    for r in perm.get("IpRanges", [])
                }
                if "0.0.0.0/0" in cidrs:
                    offending.append(sg["GroupId"])
                    break
        return offending

    def _is_port_open_to_ipv6(
        self, sg_rules: List[Dict], port: int
    ) -> List[str]:
        """Check if a port is open to ::/0 (IPv6 only).

        Used to distinguish CIS 5.3 (IPv4) from CIS 5.4 (IPv6).
        Returns list of offending security group IDs.
        """
        offending = []
        for sg in sg_rules:
            for perm in sg.get("IpPermissions", []):
                if not self._permission_allows_port(perm, port):
                    continue
                ipv6_cidrs = {
                    r.get("CidrIpv6", "")
                    for r in perm.get("Ipv6Ranges", [])
                }
                if "::/0" in ipv6_cidrs:
                    offending.append(sg["GroupId"])
                    break
        return offending

    def _permission_allows_port(self, perm: Dict, port: int) -> bool:
        """Check if an IpPermission entry covers a specific port."""
        protocol = perm.get("IpProtocol", "")

        # Protocol -1 means all traffic
        if protocol == "-1":
            return True

        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 0)

        # Check if port falls within the range
        if from_port is not None and to_port is not None:
            return from_port <= port <= to_port

        return False

    def _get_open_ports_to_world(
        self, sg_rules: List[Dict], ports: List[int]
    ) -> tuple:
        """Check which ports from a list are open to the world.

        Returns (open_ports, offending_sg_ids).
        """
        open_ports = set()
        offending_sgs = set()

        for sg in sg_rules:
            for perm in sg.get("IpPermissions", []):
                cidrs = {
                    r.get("CidrIp", "") for r in perm.get("IpRanges", [])
                }
                ipv6_cidrs = {
                    r.get("CidrIpv6", "")
                    for r in perm.get("Ipv6Ranges", [])
                }
                if not (cidrs & OPEN_CIDRS or ipv6_cidrs & OPEN_CIDRS):
                    continue

                for port in ports:
                    if self._permission_allows_port(perm, port):
                        open_ports.add(port)
                        offending_sgs.add(sg["GroupId"])

        return sorted(open_ports), sorted(offending_sgs)

    def check_default_sg(
        self, vpc_id: str, region: str
    ) -> Dict[str, Any]:
        """B.1 - VPC default SG should have no inbound or outbound rules.

        Resources should use custom security groups, not the default.
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )
            sgs = response.get("SecurityGroups", [])
            if not sgs:
                return {
                    "has_rules": False,
                    "inbound_rule_count": 0,
                    "outbound_rule_count": 0,
                }

            default_sg = sgs[0]
            inbound = len(default_sg.get("IpPermissions", []))
            outbound = len(default_sg.get("IpPermissionsEgress", []))

            return {
                "has_rules": (inbound + outbound) > 0,
                "inbound_rule_count": inbound,
                "outbound_rule_count": outbound,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_rules": False,
                "inbound_rule_count": 0,
                "outbound_rule_count": 0,
            })

    def check_sg_ssh(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
    ) -> Dict[str, Any]:
        """B.2 - No 0.0.0.0/0 or ::/0 to port 22 (SSH)."""
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        offending = self._is_port_open_to_world(sg_rules, 22)
        offending_v4 = self._is_port_open_to_ipv4(sg_rules, 22)
        offending_v6 = self._is_port_open_to_ipv6(sg_rules, 22)
        return {
            "open_to_world": len(offending) > 0,
            "open_to_ipv4": len(offending_v4) > 0,
            "open_to_ipv6": len(offending_v6) > 0,
            "offending_sgs": offending,
        }

    def check_sg_rdp(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
    ) -> Dict[str, Any]:
        """B.3 - No 0.0.0.0/0 or ::/0 to port 3389 (RDP)."""
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        offending = self._is_port_open_to_world(sg_rules, 3389)
        offending_v4 = self._is_port_open_to_ipv4(sg_rules, 3389)
        offending_v6 = self._is_port_open_to_ipv6(sg_rules, 3389)
        return {
            "open_to_world": len(offending) > 0,
            "open_to_ipv4": len(offending_v4) > 0,
            "open_to_ipv6": len(offending_v6) > 0,
            "offending_sgs": offending,
        }

    def check_sg_high_risk_ports(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
    ) -> Dict[str, Any]:
        """B.4 - No 0.0.0.0/0 or ::/0 to any of 24 high-risk ports."""
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        open_ports, offending = self._get_open_ports_to_world(
            sg_rules, self.HIGH_RISK_PORTS
        )
        return {
            "has_violations": len(open_ports) > 0,
            "open_ports": open_ports,
            "offending_sgs": offending,
        }

    def check_sg_remote_admin(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
    ) -> Dict[str, Any]:
        """B.5 - No 0.0.0.0/0 or ::/0 to remote admin ports.

        open_to_ipv4 / open_to_ipv6 are returned separately to support
        CIS v5.0 controls 5.3 (IPv4) and 5.4 (IPv6) independently.
        """
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        open_ports, offending = self._get_open_ports_to_world(
            sg_rules, self.REMOTE_ADMIN_PORTS
        )
        open_to_ipv4 = any(
            self._is_port_open_to_ipv4(sg_rules, p)
            for p in self.REMOTE_ADMIN_PORTS
        )
        open_to_ipv6 = any(
            self._is_port_open_to_ipv6(sg_rules, p)
            for p in self.REMOTE_ADMIN_PORTS
        )
        return {
            "open_to_world": len(open_ports) > 0,
            "open_to_ipv4": open_to_ipv4,
            "open_to_ipv6": open_to_ipv6,
            "open_ports": open_ports,
            "offending_sgs": offending,
        }

    def check_vpc_flow_logs(
        self, vpc_id: str, region: str
    ) -> Dict[str, Any]:
        """B.6 - VPC should have at least one flow log configured."""
        try:
            ec2 = self.get_client("ec2", region)
            flow_log_ids: list = []
            paginator = ec2.get_paginator("describe_flow_logs")
            for page in paginator.paginate(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ):
                for fl in page.get("FlowLogs", []):
                    flow_log_ids.append(fl["FlowLogId"])

            return {
                "enabled": len(flow_log_ids) > 0,
                "flow_log_ids": flow_log_ids,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enabled": False,
                "flow_log_ids": [],
            })

    def check_nacl_admin_ports(
        self, vpc_id: str, region: str
    ) -> Dict[str, Any]:
        """B.7 - NACLs should not allow 0.0.0.0/0 ingress to ports 22/3389."""
        try:
            ec2 = self.get_client("ec2", region)
            nacls = []
            paginator = ec2.get_paginator("describe_network_acls")
            for page in paginator.paginate(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ):
                nacls.extend(page.get("NetworkAcls", []))

            offending = []
            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                for entry in nacl.get("Entries", []):
                    # Only check inbound allow rules
                    if entry.get("Egress", True):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue

                    cidr = entry.get("CidrBlock", "")
                    ipv6_cidr = entry.get("Ipv6CidrBlock", "")
                    if cidr not in OPEN_CIDRS and ipv6_cidr not in OPEN_CIDRS:
                        continue

                    # Check port range
                    port_range = entry.get("PortRange", {})
                    from_port = port_range.get("From", 0)
                    to_port = port_range.get("To", 65535)

                    # Check if admin ports fall in range
                    protocol = str(entry.get("Protocol", "-1"))
                    if protocol == "-1":
                        # All traffic
                        offending.append(nacl_id)
                        break
                    elif protocol == "6":  # TCP
                        if (from_port <= 22 <= to_port
                                or from_port <= 3389 <= to_port):
                            offending.append(nacl_id)
                            break

            return {
                "open_to_world": len(offending) > 0,
                "offending_nacls": list(set(offending)),
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "open_to_world": False,
                "offending_nacls": [],
            })

    def check_source_dest(self, instance: Dict) -> Dict[str, Any]:
        """B.8 - Source/destination check should be enabled on ENIs.

        Unless instance is NAT/VPN/firewall.
        """
        enis = instance.get("NetworkInterfaces", [])
        if not enis:
            return {"enabled": True}

        # Check all ENIs - flag if ANY has it disabled
        all_enabled = all(
            eni.get("SourceDestCheck", True) for eni in enis
        )
        return {"enabled": all_enabled}

    def check_sg_egress(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
    ) -> Dict[str, Any]:
        """B.9 - No unrestricted outbound (egress) to 0.0.0.0/0 on all ports.

        Checks for protocol -1 (all traffic) to 0.0.0.0/0 or ::/0.
        """
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        offending = []
        for sg in sg_rules:
            for perm in sg.get("IpPermissionsEgress", []):
                protocol = perm.get("IpProtocol", "")

                # Check for all-traffic (-1) or full port range (0-65535)
                is_all_traffic = protocol == "-1"
                if not is_all_traffic:
                    from_port = perm.get("FromPort", -1)
                    to_port = perm.get("ToPort", -1)
                    is_all_traffic = (from_port == 0 and to_port == 65535)

                if not is_all_traffic:
                    continue

                cidrs = {
                    r.get("CidrIp", "") for r in perm.get("IpRanges", [])
                }
                ipv6_cidrs = {
                    r.get("CidrIpv6", "")
                    for r in perm.get("Ipv6Ranges", [])
                }
                if cidrs & OPEN_CIDRS or ipv6_cidrs & OPEN_CIDRS:
                    offending.append(sg["GroupId"])
                    break

        return {
            "unrestricted": len(offending) > 0,
            "offending_sgs": offending,
        }

    def check_sg_authorized_ports(
        self, sg_ids: List[str], region: str,
        sg_rules: List[Dict] = None,
        authorized_ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """B.10 - Only authorized ports (default: 80, 443) open to 0.0.0.0/0.

        Any SG rule allowing open CIDR on ports NOT in the authorized list
        is flagged. Distinct from B.4 which checks specific high-risk ports.
        """
        if sg_rules is None:
            sg_rules = self._get_security_group_rules(sg_ids, region)

        if authorized_ports is None:
            authorized_ports = self.DEFAULT_AUTHORIZED_PORTS

        unauthorized = set()
        offending = set()

        for sg in sg_rules:
            for perm in sg.get("IpPermissions", []):
                cidrs = {
                    r.get("CidrIp", "") for r in perm.get("IpRanges", [])
                }
                ipv6_cidrs = {
                    r.get("CidrIpv6", "")
                    for r in perm.get("Ipv6Ranges", [])
                }
                if not (cidrs & OPEN_CIDRS or ipv6_cidrs & OPEN_CIDRS):
                    continue

                protocol = perm.get("IpProtocol", "")
                if protocol == "-1":
                    # All traffic open = definitely unauthorized
                    unauthorized.add(0)  # Represent "all ports"
                    offending.add(sg["GroupId"])
                    continue

                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)

                if from_port is not None and to_port is not None:
                    port_range_size = to_port - from_port + 1
                    if port_range_size > 1024:
                        # Wide range open to world = unauthorized
                        # Record the range boundaries, not every port
                        unauthorized.add(from_port)
                        unauthorized.add(to_port)
                        offending.add(sg["GroupId"])
                    else:
                        for port in range(from_port, to_port + 1):
                            if port not in authorized_ports:
                                unauthorized.add(port)
                                offending.add(sg["GroupId"])

        return {
            "has_violations": len(unauthorized) > 0,
            "unauthorized_ports": sorted(unauthorized),
            "offending_sgs": sorted(offending),
        }

    def check_vpn_ikev2(self, region: str) -> Dict[str, Any]:
        """B.11 - VPN connections should use IKEv2 protocol only (FSBP EC2.183).

        EC2.183 was added to AWS FSBP on April 7, 2026.
        VPN tunnels that permit IKEv1 are vulnerable to known weaknesses.
        A tunnel passes only when IkeVersions contains exclusively 'ikev2'.
        Account-level check — runs once per scan.
        """
        try:
            ec2 = self.get_client("ec2", region)
            response = ec2.describe_vpn_connections()
            connections = response.get("VpnConnections", [])

            non_ikev2_ids: List[str] = []
            for conn in connections:
                if conn.get("State", "") in ("deleted", "deleting"):
                    continue
                conn_id = conn.get("VpnConnectionId", "")
                tunnels = conn.get("Options", {}).get("TunnelOptions", [])
                for tunnel in tunnels:
                    ike_vals = [
                        v.get("Value", "ikev1")
                        for v in tunnel.get("IkeVersions", [])
                    ]
                    # Empty list = default (ikev1 permitted); flag it.
                    # Any "ikev1" present = fails.
                    if not ike_vals or "ikev1" in ike_vals:
                        non_ikev2_ids.append(conn_id)
                        break

            return {
                "all_ikev2": len(non_ikev2_ids) == 0,
                "non_ikev2_connections": list(set(non_ikev2_ids)),
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "all_ikev2": True,
                "non_ikev2_connections": [],
            })
