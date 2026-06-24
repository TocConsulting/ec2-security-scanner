# EC2 Security Scanner - Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for all security vulnerabilities detected by the EC2 Security Scanner. Each vulnerability includes remediation steps using AWS Console, AWS CLI, and Python boto3 methods. Check IDs (A.1, B.2, ...) match [security-checks.md](security-checks.md); framework mappings are in [compliance.md](compliance.md).

> **Scope note**: some findings are per-instance (IMDSv2, public IP, IAM role) and some are account/region-wide (EBS default encryption, VPC Block Public Access, GuardDuty, CloudTrail). Account-wide fixes remediate every instance in the region at once.

> **Note on compliance tokens**: the `Compliance:` line on each finding lists indicative framework references for orientation. The authoritative, per-check control mappings are maintained in [compliance.md](compliance.md).

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| EC2 Security Best Practices | [EC2 Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html) |
| Instance Metadata Service v2 | [Configure IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) |
| Security Groups | [VPC Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) |
| EBS Encryption | [EBS Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html) |
| EBS Snapshot Block Public Access | [Snapshot BPA](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-snapshots.html) |
| VPC Flow Logs | [Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) |
| VPC Block Public Access | [VPC BPA](https://docs.aws.amazon.com/vpc/latest/userguide/security-vpc-bpa.html) |
| SSM Session Manager | [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) |
| SSM Patch Manager | [Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html) |
| Amazon Inspector v2 | [Inspector v2](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) |
| AWS CLI EC2 Commands | [AWS CLI EC2 Reference](https://docs.aws.amazon.com/cli/latest/reference/ec2/) |
| Boto3 EC2 Documentation | [Boto3 EC2 Service](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html) |

## Table of Contents

1. [Instance Security](#instance-security)
2. [Network Security](#network-security)
3. [Storage Security](#storage-security)
4. [Access Control](#access-control)
5. [Logging & Monitoring](#logging--monitoring)
6. [Patch & Vulnerability Management](#patch--vulnerability-management)
7. [Network Exposure](#network-exposure)
8. [Tagging & Inventory](#tagging--inventory)
9. [Quick Reference Commands](#quick-reference-commands)
10. [Additional Notes](#additional-notes)

---

## Instance Security

### 1. Enforce IMDSv2

**Issue**: Instance allows IMDSv1, or a launch template does not enforce IMDSv2 (checks A.1, LT-IMDSv2)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.8 (A.1), EC2.170 (LT-IMDSv2), CIS 5.7 (A.1), PCI-DSS 2.2.1, NIST AC-6, IA-2, ISO 27001 A.8.5

IMDSv1 lets any SSRF or local process read instance role credentials over a single GET. Require IMDSv2 (`HttpTokens=required`) on instances and in launch templates, with a hop limit of 1 (or 2 for container workloads).

#### AWS Console
1. **EC2 Console** -> **Instances** -> select instance -> **Actions** -> **Instance settings** -> **Modify instance metadata options**
2. Set **IMDSv2** to **Required**, **Hop limit** to 1 (or 2 for containers)
3. For launch templates: **Launch templates** -> new version -> **Advanced details** -> **Metadata version** = **V2 only**

#### AWS CLI
```bash
# Instance (A.1)
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled

# Launch template (LT-IMDSv2): create a new version with V2 enforced
aws ec2 create-launch-template-version \
  --launch-template-id lt-0abc \
  --source-version 1 \
  --launch-template-data '{"MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":2}}'
# (hop limit 2 here for container/ECS-on-EC2 workloads; use 1 for plain instances)
```

#### Python boto3
```python
import boto3

def enforce_imdsv2(instance_id, hop_limit=1):
    ec2 = boto3.client('ec2')
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id, HttpTokens='required',
        HttpPutResponseHopLimit=hop_limit, HttpEndpoint='enabled')
    print(f"IMDSv2 required on {instance_id}.")

# Usage
# enforce_imdsv2('i-0123456789abcdef0')
```

---

### 2. Remove Public IPv4 Addresses

**Issue**: Instance has a public IPv4 address (check A.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.9, PCI-DSS 1.3.1, NIST SC-7, AC-4, ISO 27001 A.8.20

A public IP makes the instance directly internet-reachable. Place workloads in private subnets behind a NAT/ALB. A public IP cannot be removed from a running instance directly; move it to a private subnet or front it with a load balancer, and disassociate any Elastic IP.

#### AWS Console
1. For an auto-assigned public IP: stop the instance, and relaunch/replace it in a **private subnet** (or behind an ALB)
2. For an **Elastic IP**: **EC2 Console** -> **Elastic IPs** -> select -> **Actions** -> **Disassociate**, then **Release**
3. Use SSM Session Manager for access instead of a public IP

#### AWS CLI
```bash
# Disassociate and release an Elastic IP
aws ec2 disassociate-address --association-id eipassoc-0abc
aws ec2 release-address --allocation-id eipalloc-0abc

# Confirm the instance no longer has a public IP
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[].Instances[].PublicIpAddress'
```

#### Python boto3
```python
import boto3

def find_public_instances():
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            if inst.get('PublicIpAddress'):
                flagged.append((inst['InstanceId'], inst['PublicIpAddress']))
    for iid, ip in flagged:
        print(f"HIGH: {iid} has public IP {ip}")
    return flagged

# Usage
find_public_instances()
```

---

### 3. Attach an IAM Instance Profile

**Issue**: Instance has no IAM instance profile (check A.3)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 7.2.1, NIST AC-6, IA-2, ISO 27001 A.5.15

Without an instance profile, applications tend to use long-lived IAM user keys baked into the AMI/UserData. Attach a least-privilege instance profile so the instance uses short-lived, auto-rotating IMDS credentials. The executing principal needs `ec2:AssociateIamInstanceProfile` **and** `iam:PassRole` on the target role, or the call returns AccessDenied.

#### AWS Console
1. Create an IAM role trusting `ec2.amazonaws.com` with least-privilege policies
2. **EC2 Console** -> select instance -> **Actions** -> **Security** -> **Modify IAM role**
3. Choose the role and **Update IAM role**

#### AWS CLI
```bash
aws ec2 associate-iam-instance-profile \
  --instance-id i-0123456789abcdef0 \
  --iam-instance-profile Name=myAppInstanceProfile
```

#### Python boto3
```python
import boto3

def attach_instance_profile(instance_id, profile_name):
    ec2 = boto3.client('ec2')
    ec2.associate_iam_instance_profile(
        InstanceId=instance_id,
        IamInstanceProfile={'Name': profile_name})
    print(f"Attached instance profile {profile_name} to {instance_id}.")

# Usage
# attach_instance_profile('i-0123456789abcdef0', 'myAppInstanceProfile')
```

---

### 4. Remove Secrets From UserData

**Issue**: Hardcoded credentials/keys/tokens in instance UserData (check A.4)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP BP.UserData, PCI-DSS 8.6.2, HIPAA 164.312(a)(2)(i), NIST IA-5, SC-12, ISO 27001 A.8.11

UserData is readable via `ec2:DescribeInstanceAttribute`, IMDS, and the console. Remove all secrets, rotate any that were exposed, and fetch secrets at boot from Secrets Manager / SSM Parameter Store instead.

#### AWS Console
1. **Rotate** every credential that appeared in UserData (assume compromised)
2. Stop the instance -> **Actions** -> **Instance settings** -> **Edit user data** -> remove the secrets, replace with a Secrets Manager/SSM fetch
3. Grant the instance role read access to those secrets

#### AWS CLI
```bash
# Inspect current UserData
aws ec2 describe-instance-attribute --instance-id i-0123 --attribute userData \
  --query 'UserData.Value' --output text | base64 -d

# Replace UserData (instance must be stopped); rotate exposed secrets first
aws ec2 modify-instance-attribute --instance-id i-0123 \
  --attribute userData --value file://clean-userdata.txt
```

#### Python boto3
```python
import base64
import re
import boto3

PATTERNS = [r'AKIA[0-9A-Z]{16}', r'aws_secret_access_key',
            r'ghp_[A-Za-z0-9]{36}', r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
            r'password\s*=', r'://[^:]+:[^@]+@']

def scan_userdata_for_secrets(instance_id):
    ec2 = boto3.client('ec2')
    attr = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute='userData')
    raw = attr.get('UserData', {}).get('Value')
    if not raw:
        return []
    text = base64.b64decode(raw).decode('utf-8', errors='ignore')
    hits = [p for p in PATTERNS if re.search(p, text)]
    if hits:
        print(f"CRITICAL: {instance_id} UserData matches {hits}")
    return hits

# Usage
# scan_userdata_for_secrets('i-0123456789abcdef0')
```

---

### 5. Use HVM Virtualization

**Issue**: Instance uses paravirtual (PV) virtualization (check A.5)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.24, PCI-DSS 2.2.1, NIST CM-6, SC-39, ISO 27001 A.8.9

PV instances run on legacy infrastructure with a wider hypervisor attack surface. Migrate the workload to an HVM AMI on a current (Nitro) instance family.

#### AWS Console
1. Create or select an **HVM AMI** for the OS
2. Launch a replacement instance on a current-generation (Nitro) instance type using the HVM AMI
3. Migrate data/config and decommission the PV instance

#### AWS CLI
```bash
# Identify paravirtual instances
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?VirtualizationType==`paravirtual`].[InstanceId,InstanceType]'
# Remediation is a migration to an HVM AMI / Nitro instance type (relaunch).
```

#### Python boto3
```python
import boto3

def find_paravirtual_instances():
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            if inst.get('VirtualizationType') == 'paravirtual':
                flagged.append(inst['InstanceId'])
    for iid in flagged:
        print(f"MEDIUM: {iid} is paravirtual -> migrate to HVM")
    return flagged

# Usage
find_paravirtual_instances()
```

---

### 6. Avoid Multi-ENI Dual-Homing

**Issue**: Instance has more than one ENI (check A.6)
**Severity**: LOW
**Compliance**: AWS-FSBP EC2.17, NIST SC-7, AC-4, ISO 27001 A.8.22

Dual-homed instances can bridge subnets that should stay isolated. Unless the instance is a deliberate NAT/firewall, remove the extra ENI and route through proper network constructs.

#### AWS Console
1. **EC2 Console** -> **Network interfaces** -> identify the secondary ENI on the instance
2. If not required, **Detach** it (and delete if unused)
3. Route cross-subnet traffic through a NAT gateway / TGW / PrivateLink instead

#### AWS CLI
```bash
# List ENIs on an instance
aws ec2 describe-instances --instance-ids i-0123 \
  --query 'Reservations[].Instances[].NetworkInterfaces[].NetworkInterfaceId'

# Detach a secondary ENI (find its attachment id first)
aws ec2 detach-network-interface --attachment-id eni-attach-0abc
```

#### Python boto3
```python
import boto3

def find_multi_eni_instances():
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            if len(inst.get('NetworkInterfaces', [])) > 1:
                flagged.append(inst['InstanceId'])
    for iid in flagged:
        print(f"LOW: {iid} has multiple ENIs")
    return flagged

# Usage
find_multi_eni_instances()
```

---

### 7. Enable Detailed Monitoring

**Issue**: Instance uses 5-minute basic monitoring, not 1-minute detailed monitoring (check A.7)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 10.x, NIST AU-6, SI-4, ISO 27001 A.8.16

At 5-minute resolution, short cryptomining or exfiltration bursts are invisible. Enable detailed (1-minute) monitoring.

#### AWS Console
1. **EC2 Console** -> select instance -> **Actions** -> **Monitor and troubleshoot** -> **Manage detailed monitoring**
2. Enable **Detailed monitoring**
3. **Save**

#### AWS CLI
```bash
aws ec2 monitor-instances --instance-ids i-0123456789abcdef0
```

#### Python boto3
```python
import boto3

def enable_detailed_monitoring(instance_id):
    ec2 = boto3.client('ec2')
    ec2.monitor_instances(InstanceIds=[instance_id])
    print(f"Detailed monitoring enabled on {instance_id}.")

# Usage
# enable_detailed_monitoring('i-0123456789abcdef0')
```

---

### 8. Replace SSH Key Pairs With SSM-Managed Access

**Issue**: Instance has a key pair but is not SSM-managed (check A.8)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 8.6.1, NIST AC-17, AU-2, ISO 27001 A.8.5

SSH keys are hard to rotate/revoke and bypass audit. Manage the instance with SSM and use Session Manager (full CloudTrail logging, no inbound port 22).

#### AWS Console
1. Attach an instance profile with **AmazonSSMManagedInstanceCore** and ensure the SSM agent is running
2. Access the instance via **Session Manager** (**EC2 Console** -> **Connect** -> **Session Manager**)
3. Remove the inbound SSH rule and stop distributing the key pair

#### AWS CLI
```bash
# Confirm SSM management
aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=i-0123" \
  --query 'InstanceInformationList[].PingStatus'

# Connect via Session Manager (no port 22)
aws ssm start-session --target i-0123456789abcdef0
```

#### Python boto3
```python
import boto3

def find_keypair_not_ssm():
    ec2 = boto3.client('ec2')
    ssm = boto3.client('ssm')
    managed = {i['InstanceId'] for i in ssm.describe_instance_information()[
        'InstanceInformationList']}
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            if inst.get('KeyName') and inst['InstanceId'] not in managed:
                flagged.append(inst['InstanceId'])
    for iid in flagged:
        print(f"MEDIUM: {iid} uses a key pair and is not SSM-managed")
    return flagged

# Usage
find_keypair_not_ssm()
```

---

## Network Security

### 9. Enable VPC Flow Logs

**Issue**: A VPC has no active flow log (check B.1)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.6, CIS 3.7, PCI-DSS 10.2.1, HIPAA 164.312(b), NIST AU-2, SI-4, ISO 27001 A.8.15

Flow logs are the network audit trail. Enable them (destination CloudWatch Logs or S3) on every VPC.

#### AWS Console
1. **VPC Console** -> select the VPC -> **Flow logs** tab -> **Create flow log**
2. Filter **All**, destination **CloudWatch Logs** (or S3), choose/create the log group and role
3. **Create flow log**

#### AWS CLI
```bash
aws ec2 create-flow-logs \
  --resource-type VPC --resource-ids vpc-0123 \
  --traffic-type ALL --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT_ID:role/flowlogsRole
```

#### Python boto3
```python
import boto3

def enable_flow_logs_all_vpcs(log_group, role_arn):
    ec2 = boto3.client('ec2')
    for vpc in ec2.describe_vpcs()['Vpcs']:
        vid = vpc['VpcId']
        existing = ec2.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': [vid]}])['FlowLogs']
        if existing:
            continue
        ec2.create_flow_logs(
            ResourceType='VPC', ResourceIds=[vid], TrafficType='ALL',
            LogDestinationType='cloud-watch-logs', LogGroupName=log_group,
            DeliverLogsPermissionArn=role_arn)
        print(f"Flow logs enabled on {vid}.")

# Usage
# enable_flow_logs_all_vpcs('/vpc/flowlogs', 'arn:aws:iam::123456789012:role/flowlogsRole')
```

---

### 10. Close Public Ingress on Security Groups

**Issue**: Security groups allow `0.0.0.0/0`/`::/0` to SSH (22), RDP (3389), remote-admin ports, high-risk ports, or unauthorized ports (checks B.2, B.3, B.4, B.5, B.7)
**Severity**: CRITICAL (B.4 high-risk ports), HIGH (B.2 SSH, B.3 RDP, B.5 remote-admin, B.7 unauthorized ports)
**Compliance**: AWS-FSBP EC2.13, EC2.14, EC2.19, EC2.53, EC2.18, CIS 5.3, 5.4, PCI-DSS 1.2.1, NIST AC-4, SC-7, ISO 27001 A.8.20

The only ports that should be open to the world are a deliberate short list (typically 80/443 behind an ALB). Remove world-open rules for: SSH 22 (B.2), RDP 3389 (B.3), the 24 high-risk ports (B.4), remote-admin ports SSH/RDP/WinRM/VNC/Telnet/SMB (B.5), and any port not on the authorized allow-list (B.7). Use SSM Session Manager / EICE instead of public admin ports.

#### AWS Console
1. **VPC Console** -> **Security groups** -> select the SG -> **Inbound rules** -> **Edit**
2. Delete every rule whose source is `0.0.0.0/0` or `::/0` on 22, 3389, databases, and other non-80/443 ports
3. Re-add rules sourced from specific SGs/CIDRs (or a bastion), and **Save rules**

#### AWS CLI
```bash
# Remove world-open SSH (B.2) and RDP (B.3)
aws ec2 revoke-security-group-ingress --group-id sg-0123 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress --group-id sg-0123 \
  --protocol tcp --port 3389 --cidr 0.0.0.0/0

# Remove a world-open high-risk/unauthorized port (B.4 / B.7), e.g. MySQL 3306
aws ec2 revoke-security-group-ingress --group-id sg-0123 \
  --protocol tcp --port 3306 --cidr 0.0.0.0/0

# Re-add scoped access from an application/bastion SG
aws ec2 authorize-security-group-ingress --group-id sg-0123 \
  --protocol tcp --port 22 --source-group sg-bastion
```

#### Python boto3
```python
import boto3

HIGH_RISK = {20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306,
             3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300}
AUTHORIZED = {80, 443}

def find_world_open_ingress():
    ec2 = boto3.client('ec2')
    flagged = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for rule in sg.get('IpPermissions', []):
            public = any(r.get('CidrIp') == '0.0.0.0/0'
                         for r in rule.get('IpRanges', [])) or any(
                r.get('CidrIpv6') == '::/0' for r in rule.get('Ipv6Ranges', []))
            if not public:
                continue
            lo = rule.get('FromPort', 0); hi = rule.get('ToPort', 65535)
            ports = set(range(lo, hi + 1)) if hi - lo < 1000 else {lo, hi}
            risky = ports & HIGH_RISK or not ports <= AUTHORIZED
            if risky:
                flagged.append((sg['GroupId'], lo, hi))
    for gid, lo, hi in flagged:
        print(f"OPEN: {gid} ports {lo}-{hi} to the world -> restrict")
    return flagged

# Usage
find_world_open_ingress()
```

---

### 11. Restrict Security Group Egress

**Issue**: Security group allows unrestricted egress to `0.0.0.0/0`/`::/0` on all ports (check B.6)
**Severity**: LOW (opinionated; AWS default is allow-all)
**Compliance**: AWS-FSBP BP.Egress, PCI-DSS 1.3.2, HIPAA 164.312(e)(2)(ii), NIST AC-4, SC-7, ISO 27001 A.8.21

Default allow-all egress lets a compromised instance reach any C2/exfil destination. Restrict outbound to required destinations (S3/VPC endpoints, package mirrors, monitoring).

#### AWS Console
1. **VPC Console** -> **Security groups** -> the SG -> **Outbound rules** -> **Edit**
2. Remove the default all-traffic-to-`0.0.0.0/0` rule; add specific destinations/ports
3. **Save rules**

#### AWS CLI
```bash
aws ec2 revoke-security-group-egress --group-id sg-0123 \
  --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
aws ec2 authorize-security-group-egress --group-id sg-0123 \
  --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=10.0.0.0/16}]'
```

#### Python boto3
```python
import boto3

def find_unrestricted_egress():
    ec2 = boto3.client('ec2')
    flagged = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for rule in sg.get('IpPermissionsEgress', []):
            if rule.get('IpProtocol') == '-1' and any(
                    r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', [])):
                flagged.append(sg['GroupId'])
    for gid in flagged:
        print(f"LOW: {gid} allows unrestricted egress")
    return flagged

# Usage
find_unrestricted_egress()
```

---

### 12. Lock Down NACL Admin Ports

**Issue**: A network ACL allows `0.0.0.0/0` ingress to port 22 or 3389 (check B.8)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.21, CIS 5.2, PCI-DSS 1.2.1, NIST AC-4, SC-7, ISO 27001 A.8.20

NACLs are evaluated before SGs at the subnet boundary. Remove permissive admin-port allow rules so a later SG mistake is not silently exposed.

#### AWS Console
1. **VPC Console** -> **Network ACLs** -> select the NACL -> **Inbound rules** -> **Edit**
2. Remove/replace any `allow` rule with source `0.0.0.0/0` covering 22 or 3389
3. **Save changes**

#### AWS CLI
```bash
# Replace a permissive inbound NACL entry (re-create as needed)
aws ec2 delete-network-acl-entry --network-acl-id acl-0123 --rule-number 100 --ingress
# Then add a scoped rule, e.g. allow 443 from a trusted CIDR:
aws ec2 create-network-acl-entry --network-acl-id acl-0123 --rule-number 100 \
  --protocol tcp --port-range From=443,To=443 --cidr-block 10.0.0.0/16 \
  --rule-action allow --ingress
```

#### Python boto3
```python
import boto3

def find_open_nacl_admin_ports():
    ec2 = boto3.client('ec2')
    flagged = []
    for nacl in ec2.describe_network_acls()['NetworkAcls']:
        for e in nacl['Entries']:
            if (e.get('RuleAction') == 'allow' and not e['Egress']
                    and e.get('CidrBlock') == '0.0.0.0/0'):
                pr = e.get('PortRange', {'From': 0, 'To': 65535})
                if pr['From'] <= 22 <= pr['To'] or pr['From'] <= 3389 <= pr['To']:
                    flagged.append((nacl['NetworkAclId'], e['RuleNumber']))
    for aclid, rn in flagged:
        print(f"MEDIUM: NACL {aclid} rule {rn} opens admin ports to the world")
    return flagged

# Usage
find_open_nacl_admin_ports()
```

---

### 13. Enable Source/Destination Check

**Issue**: An ENI has source/destination check disabled (and is not a NAT/firewall) (check B.9)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.180, PCI-DSS 1.3.x, NIST SC-7, AC-4, ISO 27001 A.8.22

With source/dest check off, a compromised instance can route/intercept traffic for others (MITM). Re-enable it on ENIs that are not legitimately routing.

#### AWS Console
1. **EC2 Console** -> **Network interfaces** -> select the ENI -> **Actions** -> **Change source/dest check**
2. Set to **Enabled** (Stop)
3. **Save**

#### AWS CLI
```bash
aws ec2 modify-network-interface-attribute \
  --network-interface-id eni-0123 \
  --source-dest-check
# (use --no-source-dest-check to disable; the flag is a boolean, not JSON)
```

#### Python boto3
```python
import boto3

def fix_source_dest_check(remediate=False):
    ec2 = boto3.client('ec2')
    flagged = []
    for eni in ec2.describe_network_interfaces()['NetworkInterfaces']:
        if eni.get('SourceDestCheck') is False:
            nid = eni['NetworkInterfaceId']
            flagged.append(nid)
            print(f"MEDIUM: {nid} has source/dest check disabled")
            if remediate:  # skip legitimate NAT/firewall/VPN ENIs
                ec2.modify_network_interface_attribute(
                    NetworkInterfaceId=nid, SourceDestCheck={'Value': True})
    return flagged

# Usage
fix_source_dest_check(remediate=False)
```

---

### 14. Disable Subnet Auto-Assign Public IP

**Issue**: A subnet auto-assigns public IPv4 addresses on launch (check B.10)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.15, PCI-DSS 1.3.1, NIST SC-7, AC-4, ISO 27001 A.8.22

Auto-assign-public-IP silently exposes every new instance in the subnet. Turn it off for private subnets.

#### AWS Console
1. **VPC Console** -> **Subnets** -> select the subnet -> **Actions** -> **Edit subnet settings**
2. Uncheck **Enable auto-assign public IPv4 address**
3. **Save**

#### AWS CLI
```bash
aws ec2 modify-subnet-attribute \
  --subnet-id subnet-0123 \
  --no-map-public-ip-on-launch
```

#### Python boto3
```python
import boto3

def disable_subnet_auto_public_ip():
    ec2 = boto3.client('ec2')
    flagged = []
    for sn in ec2.describe_subnets()['Subnets']:
        if sn.get('MapPublicIpOnLaunch'):
            flagged.append(sn['SubnetId'])
    for sid in flagged:
        print(f"MEDIUM: subnet {sid} auto-assigns public IPs")
    return flagged

# Usage
disable_subnet_auto_public_ip()
```

---

### 15. Enable VPC Block Public Access

**Issue**: VPC Block Public Access is not blocking internet gateway traffic (check B.11)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.172, PCI-DSS 1.3.1, NIST SC-7, AC-4, ISO 27001 A.8.20

VPC BPA is an account/region kill switch that blocks IGW traffic even if a subnet/SG is misconfigured. Set it to block ingress (or bidirectional).

#### AWS Console
1. **VPC Console** -> **Settings** / **Block public access** (region scope)
2. Set the **Internet gateway block mode** to **Block ingress** (or **Bidirectional**)
3. **Save**

#### AWS CLI
```bash
aws ec2 modify-vpc-block-public-access-options \
  --internet-gateway-block-mode block-ingress
```

#### Python boto3
```python
import boto3

def enable_vpc_bpa(mode='block-ingress'):
    ec2 = boto3.client('ec2')
    ec2.modify_vpc_block_public_access_options(
        InternetGatewayBlockMode=mode)
    print(f"VPC Block Public Access set to {mode}.")

# Usage
# enable_vpc_bpa('block-ingress')
```

---

### 16. Disable Transit Gateway Auto-Accept

**Issue**: A Transit Gateway has `AutoAcceptSharedAttachments` enabled (check B.12)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.23, PCI-DSS 1.2.x, NIST AC-4, SC-7, ISO 27001 A.8.22

Auto-accept lets any shared VPC join the hub network without approval, enabling pivots from a compromised peripheral account. Require manual attachment approval.

#### AWS Console
1. **VPC Console** -> **Transit gateways** -> select the TGW -> **Actions** -> **Modify**
2. Set **Auto accept shared attachments** to **disable**
3. **Modify transit gateway**

#### AWS CLI
```bash
aws ec2 modify-transit-gateway \
  --transit-gateway-id tgw-0123 \
  --options AutoAcceptSharedAttachments=disable
```

#### Python boto3
```python
import boto3

def find_tgw_auto_accept():
    ec2 = boto3.client('ec2')
    flagged = []
    for tgw in ec2.describe_transit_gateways()['TransitGateways']:
        if tgw.get('Options', {}).get('AutoAcceptSharedAttachments') == 'enable':
            flagged.append(tgw['TransitGatewayId'])
    for tid in flagged:
        print(f"HIGH: {tid} auto-accepts shared attachments")
    return flagged

# Usage
find_tgw_auto_accept()
```

---

### 17. Enforce IKEv2 on Site-to-Site VPNs

**Issue**: A VPN connection tunnel permits IKEv1 (check B.13)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.183, PCI-DSS 4.2.1, NIST SC-8, SC-12, ISO 27001 A.8.24

IKEv1 (aggressive mode) is vulnerable to offline PSK cracking. Restrict each tunnel to IKEv2 only.

#### AWS Console
1. **VPC Console** -> **Site-to-Site VPN connections** -> select the connection -> **Tunnel details** -> **Modify VPN tunnel options**
2. Set **IKE versions** to **ikev2** for each tunnel
3. **Save** (this re-establishes the tunnel)

#### AWS CLI
```bash
aws ec2 modify-vpn-tunnel-options \
  --vpn-connection-id vpn-0123 \
  --vpn-tunnel-outside-ip-address 203.0.113.10 \
  --tunnel-options '{"IKEVersions":[{"Value":"ikev2"}]}'
```

#### Python boto3
```python
import boto3

def find_ikev1_vpns():
    ec2 = boto3.client('ec2')
    flagged = []
    for vpn in ec2.describe_vpn_connections()['VpnConnections']:
        for t in vpn.get('Options', {}).get('TunnelOptions', []):
            versions = [v['Value'] for v in t.get('IkeVersions', [])]
            if 'ikev1' in versions:
                flagged.append((vpn['VpnConnectionId'],
                                t.get('OutsideIpAddress')))
    for vid, ip in flagged:
        print(f"HIGH: VPN {vid} tunnel {ip} allows IKEv1")
    return flagged

# Usage
find_ikev1_vpns()
```

---

## Storage Security

### 18. Encrypt EBS Volumes

**Issue**: An attached EBS volume is not encrypted (check C.1)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.3, PCI-DSS 3.4.1, HIPAA 164.312(a)(2)(iv), GDPR Art.32, NIST SC-28, ISO 27001 A.8.24

EBS encryption cannot be toggled on an existing volume. Snapshot it, copy the snapshot with encryption, create a new encrypted volume, and swap it in.

#### AWS Console
1. **EC2 Console** -> **Volumes** -> snapshot the volume
2. **Snapshots** -> **Copy** the snapshot with **Encryption** enabled (choose a KMS key)
3. Create a volume from the encrypted snapshot, stop the instance, detach the old volume, attach the new one at the same device name

#### AWS CLI
```bash
aws ec2 create-snapshot --volume-id vol-0123 --description "pre-encrypt"
aws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id snap-0123 \
  --encrypted --kms-key-id alias/aws/ebs --description "encrypted"
aws ec2 create-volume --snapshot-id snap-ENCRYPTED \
  --availability-zone us-east-1a --encrypted
```

#### Python boto3
```python
import boto3

def find_unencrypted_volumes(instance_id):
    ec2 = boto3.client('ec2')
    flagged = []
    vols = ec2.describe_volumes(Filters=[
        {'Name': 'attachment.instance-id', 'Values': [instance_id]}])['Volumes']
    for v in vols:
        if not v.get('Encrypted'):
            flagged.append(v['VolumeId'])
    for vid in flagged:
        print(f"MEDIUM: volume {vid} is unencrypted")
    return flagged

# Usage
# find_unencrypted_volumes('i-0123456789abcdef0')
```

---

### 19. Enable EBS Default Encryption

**Issue**: Account/region EBS default encryption is disabled (check C.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.7, CIS 5.1.1, PCI-DSS 3.4.1, NIST SC-28, SC-13, ISO 27001 A.8.24

Default encryption guarantees every new volume is encrypted even if the launch parameter is forgotten. Enable it per region.

#### AWS Console
1. **EC2 Console** -> **EC2 Dashboard** -> **Account attributes** / **Data encryption** -> **Manage**
2. Enable **Always encrypt new EBS volumes**, choose a default KMS key
3. **Update**

#### AWS CLI
```bash
aws ec2 enable-ebs-encryption-by-default
aws ec2 get-ebs-encryption-by-default
```

#### Python boto3
```python
import boto3

def enable_ebs_default_encryption():
    ec2 = boto3.client('ec2')
    ec2.enable_ebs_encryption_by_default()
    state = ec2.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
    print(f"EBS default encryption enabled: {state}")

# Usage
# enable_ebs_default_encryption()
```

---

### 20. Remove Public EBS Snapshots

**Issue**: An account-owned EBS snapshot is publicly restorable (check C.3)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP EC2.1, PCI-DSS 1.3.1, HIPAA 164.310(d)(1), GDPR Art.32, NIST AC-3, MP-6, ISO 27001 A.8.12

A public snapshot exposes the full volume image to every AWS account. Remove the `all` create-volume permission immediately.

#### AWS Console
1. **EC2 Console** -> **Snapshots** -> select the snapshot -> **Actions** -> **Modify permissions**
2. Set to **Private**; remove **Public**
3. **Save**

#### AWS CLI
```bash
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-0123 \
  --attribute createVolumePermission \
  --operation-type remove --group-names all
```

#### Python boto3
```python
import boto3

def make_snapshots_private():
    ec2 = boto3.client('ec2')
    flagged = []
    for snap in ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']:
        attr = ec2.describe_snapshot_attribute(
            SnapshotId=snap['SnapshotId'], Attribute='createVolumePermission')
        if any(p.get('Group') == 'all'
               for p in attr.get('CreateVolumePermissions', [])):
            print(f"CRITICAL public snapshot {snap['SnapshotId']} -> private")
            ec2.modify_snapshot_attribute(
                SnapshotId=snap['SnapshotId'],
                Attribute='createVolumePermission',
                OperationType='remove', GroupNames=['all'])
            flagged.append(snap['SnapshotId'])
    return flagged

# Usage
# make_snapshots_private()
```

---

### 21. Cover EBS Volumes With a Backup Plan

**Issue**: An EBS volume is not covered by an AWS Backup plan (check C.4)
**Severity**: LOW
**Compliance**: AWS-FSBP EC2.28, PCI-DSS 10.5.x, HIPAA 164.308(a)(7), NIST CP-9, ISO 27001 A.8.13

Volumes outside a backup plan have no recovery path against ransomware/deletion. Assign them to an AWS Backup plan (for example by tag).

#### AWS Console
1. **AWS Backup Console** -> **Backup plans** -> create/select a plan with a schedule and retention
2. **Assign resources** -> select EBS volumes by tag or ARN
3. **Assign resources**

#### AWS CLI
```bash
# Tag volumes so a tag-based backup selection picks them up
aws ec2 create-tags --resources vol-0123 --tags Key=backup,Value=daily

# (Backup plan + selection created once via aws backup create-backup-plan /
#  create-backup-selection with a tag condition backup=daily)
```

#### Python boto3
```python
import boto3

def find_unbacked_volumes():
    ec2 = boto3.client('ec2')
    backup = boto3.client('backup')
    # describe_volumes does not return OwnerId; get the account from STS.
    account = boto3.client('sts').get_caller_identity()['Account']
    flagged = []
    for v in ec2.describe_volumes()['Volumes']:
        arn = f"arn:aws:ec2:{ec2.meta.region_name}:" \
              f"{account}:volume/{v['VolumeId']}"
        try:
            res = backup.describe_protected_resource(ResourceArn=arn)
            if not res.get('LastBackupTime'):
                flagged.append(v['VolumeId'])
        except backup.exceptions.ResourceNotFoundException:
            flagged.append(v['VolumeId'])
    for vid in flagged:
        print(f"LOW: volume {vid} not covered by a backup plan")
    return flagged

# Usage
# find_unbacked_volumes()
```

---

### 22. Encrypt Launch Template EBS Volumes

**Issue**: A launch template's block device mappings do not set `Encrypted=true` (check C.5)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.181, PCI-DSS 3.4.1, NIST SC-28, SC-13, ISO 27001 A.8.24

Otherwise every Auto Scaling / fleet launch produces unencrypted volumes. Publish a new template version with encryption enabled (enabling account-wide default encryption, remediation 19, also covers this).

#### AWS Console
1. **EC2 Console** -> **Launch templates** -> select template -> **Actions** -> **Modify template (create new version)**
2. Under **Storage**, set each volume's **Encrypted** to **Yes**
3. Set the new version as **Default**

#### AWS CLI
```bash
aws ec2 create-launch-template-version \
  --launch-template-id lt-0123 --source-version 1 \
  --launch-template-data '{"BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"Encrypted":true,"VolumeType":"gp3"}}]}'
aws ec2 modify-launch-template --launch-template-id lt-0123 --default-version 2
```

#### Python boto3
```python
import boto3

def find_unencrypted_lt_volumes():
    ec2 = boto3.client('ec2')
    flagged = []
    for lt in ec2.describe_launch_templates()['LaunchTemplates']:
        ver = ec2.describe_launch_template_versions(
            LaunchTemplateId=lt['LaunchTemplateId'],
            Versions=[str(lt['DefaultVersionNumber'])])['LaunchTemplateVersions'][0]
        for bdm in ver['LaunchTemplateData'].get('BlockDeviceMappings', []):
            if bdm.get('Ebs') and not bdm['Ebs'].get('Encrypted'):
                flagged.append(lt['LaunchTemplateName'])
    for name in set(flagged):
        print(f"MEDIUM: launch template {name} has unencrypted EBS")
    return flagged

# Usage
find_unencrypted_lt_volumes()
```

---

### 23. Make AMIs Private

**Issue**: An account-owned AMI is shared publicly (check C.6)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP BP.PublicAMI, PCI-DSS 1.3.1, HIPAA 164.310(d)(1), NIST AC-3, MP-6, ISO 27001 A.8.12

A public AMI is a launch-ready disk image (OS, app, config, often secrets) exposed to everyone. Remove the public launch permission.

#### AWS Console
1. **EC2 Console** -> **AMIs** (owned by me) -> select the AMI -> **Actions** -> **Edit AMI permissions**
2. Set to **Private**
3. **Save changes**

#### AWS CLI
```bash
aws ec2 modify-image-attribute \
  --image-id ami-0123 \
  --launch-permission '{"Remove":[{"Group":"all"}]}'
```

#### Python boto3
```python
import boto3

def make_amis_private():
    ec2 = boto3.client('ec2')
    flagged = []
    for img in ec2.describe_images(Owners=['self'])['Images']:
        if img.get('Public'):
            print(f"CRITICAL public AMI {img['ImageId']} -> private")
            ec2.modify_image_attribute(
                ImageId=img['ImageId'],
                LaunchPermission={'Remove': [{'Group': 'all'}]})
            flagged.append(img['ImageId'])
    return flagged

# Usage
# make_amis_private()
```

---

### 24. Enable EBS Snapshot Block Public Access

**Issue**: EBS Snapshot Block Public Access is not enabled (check C.7)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.182, PCI-DSS 1.3.1, NIST AC-3, MP-6, ISO 27001 A.8.12

Snapshot BPA is the account/region preventive control: even if a team mis-shares a snapshot, BPA blocks public exposure. Set it to block all sharing.

#### AWS Console
1. **EC2 Console** -> **EC2 Dashboard** -> **Data protection and security** / **Block public access for snapshots** -> **Manage**
2. Set to **Block all sharing** (or **Block new sharing**)
3. **Update**

#### AWS CLI
```bash
aws ec2 enable-snapshot-block-public-access --state block-all-sharing
aws ec2 get-snapshot-block-public-access-state
```

#### Python boto3
```python
import boto3

def enable_snapshot_bpa():
    ec2 = boto3.client('ec2')
    ec2.enable_snapshot_block_public_access(State='block-all-sharing')
    state = ec2.get_snapshot_block_public_access_state()['State']
    print(f"EBS snapshot BPA: {state}")

# Usage
# enable_snapshot_bpa()
```

---

## Access Control

### 25. Scope Down the Instance IAM Role

**Issue**: The attached instance role has admin/wildcard permissions (check D.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 7.2.1, NIST AC-6, AC-3, ISO 27001 A.5.18

Stolen IMDS credentials carry whatever the instance role grants. Remove `AdministratorAccess` and `service:*`-on-`*` permissions; scope to the exact actions/resources the workload needs.

#### AWS Console
1. **EC2 Console** -> instance -> **Security** -> open the **IAM role**
2. In IAM, remove admin managed policies and rewrite inline/customer policies to least privilege
3. Save the policy changes

#### AWS CLI
```bash
aws iam detach-role-policy --role-name myInstanceRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam put-role-policy --role-name myInstanceRole --policy-name app \
  --policy-document file://least-privilege.json
```

#### Python boto3
```python
import boto3

ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'

def audit_instance_role(role_name):
    iam = boto3.client('iam')
    attached = [p['PolicyArn'] for p in iam.list_attached_role_policies(
        RoleName=role_name)['AttachedPolicies']]
    if ADMIN in attached:
        print(f"HIGH: {role_name} has AdministratorAccess")
    return attached

# Usage
# audit_instance_role('myInstanceRole')
```

---

### 26. Disable Serial Console Access

**Issue**: Account-level EC2 Serial Console access is enabled (check D.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 7.2.x, NIST AC-6, AC-17, ISO 27001 A.8.5

Serial console grants OS-level access regardless of network position. Disable it unless actively needed for break-glass recovery.

#### AWS Console
1. **EC2 Console** -> **EC2 Dashboard** -> **Account attributes** -> **EC2 Serial Console**
2. **Manage** -> **Disable**
3. **Update**

#### AWS CLI
```bash
aws ec2 disable-serial-console-access
aws ec2 get-serial-console-access-status
```

#### Python boto3
```python
import boto3

def disable_serial_console():
    ec2 = boto3.client('ec2')
    ec2.disable_serial_console_access()
    enabled = ec2.get_serial_console_access_status()[
        'SerialConsoleAccessEnabled']
    print(f"Serial console enabled: {enabled}")

# Usage
# disable_serial_console()
```

---

### 27. Use EC2 Instance Connect Endpoints

**Issue**: No EC2 Instance Connect Endpoint is configured for VPCs hosting instances (check D.3)
**Severity**: LOW (informational)
**Compliance**: AWS-FSBP EC2 baseline, NIST AC-17, AU-2, ISO 27001 A.8.5

EICE provides SSH/RDP without public IPs or bastions, with IAM auth and CloudTrail logging. Create an endpoint per VPC so there is no reason to expose port 22.

#### AWS Console
1. **VPC Console** -> **Endpoints** -> **Create endpoint** -> **EC2 Instance Connect Endpoint**
2. Select the VPC, a private subnet, and a security group
3. **Create endpoint**, then connect via **EC2 Console** -> **Connect** -> **EC2 Instance Connect Endpoint**

#### AWS CLI
```bash
aws ec2 create-instance-connect-endpoint \
  --subnet-id subnet-private1 \
  --security-group-ids sg-eice
```

#### Python boto3
```python
import boto3

def find_vpcs_without_eice():
    ec2 = boto3.client('ec2')
    eice_vpcs = {e['VpcId'] for e in ec2.describe_instance_connect_endpoints()[
        'InstanceConnectEndpoints']}
    flagged = [v['VpcId'] for v in ec2.describe_vpcs()['Vpcs']
               if v['VpcId'] not in eice_vpcs]
    for vid in flagged:
        print(f"LOW: VPC {vid} has no Instance Connect Endpoint")
    return flagged

# Usage
find_vpcs_without_eice()
```

---

## Logging & Monitoring

### 28. Enable CloudTrail

**Issue**: No active multi-region CloudTrail capturing management events (check E.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP CloudTrail baseline, PCI-DSS 10.2.1, HIPAA 164.312(b), NIST AU-2, AU-12, ISO 27001 A.8.15

Without CloudTrail, AWS API activity is invisible. Create a multi-region trail logging management events to a secured S3 bucket.

#### AWS Console
1. **CloudTrail Console** -> **Trails** -> **Create trail**
2. Enable **multi-region**, log **Management events** (read + write), choose/create an encrypted S3 bucket
3. **Create trail** and confirm logging is **On**

#### AWS CLI
```bash
aws cloudtrail create-trail --name org-trail \
  --s3-bucket-name my-cloudtrail-bucket --is-multi-region-trail
aws cloudtrail start-logging --name org-trail
```

#### Python boto3
```python
import boto3

def check_cloudtrail():
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=False)['trailList']
    active = []
    for t in trails:
        status = ct.get_trail_status(Name=t['Name'])
        if status.get('IsLogging'):
            active.append(t['Name'])
    if not active:
        print("HIGH: no active CloudTrail trail")
    return active

# Usage
check_cloudtrail()
```

---

### 29. Add CloudWatch Alarms

**Issue**: An instance has no associated CloudWatch alarm (check E.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 10.x, NIST SI-4, AU-6, ISO 27001 A.8.16

An instance with zero alarms is operationally invisible until it fails. Add at least a status-check (and CPU) alarm.

#### AWS Console
1. **CloudWatch Console** -> **Alarms** -> **Create alarm**
2. Select the instance's **StatusCheckFailed** (and/or CPUUtilization) metric, set a threshold and SNS action
3. **Create alarm**

#### AWS CLI
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "i-0123-status-check" \
  --namespace AWS/EC2 --metric-name StatusCheckFailed \
  --dimensions Name=InstanceId,Value=i-0123 \
  --statistic Maximum --period 60 --evaluation-periods 2 \
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:REGION:ACCOUNT_ID:ec2-alerts
```

#### Python boto3
```python
import boto3

def create_status_alarm(instance_id, sns_arn):
    cw = boto3.client('cloudwatch')
    cw.put_metric_alarm(
        AlarmName=f"{instance_id}-status-check", Namespace='AWS/EC2',
        MetricName='StatusCheckFailed',
        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
        Statistic='Maximum', Period=60, EvaluationPeriods=2, Threshold=1,
        ComparisonOperator='GreaterThanOrEqualToThreshold',
        AlarmActions=[sns_arn])
    print(f"Status-check alarm created for {instance_id}.")

# Usage
# create_status_alarm('i-0123456789abcdef0', 'arn:aws:sns:us-east-1:123456789012:ec2-alerts')
```

---

### 30. Manage Instances With SSM

**Issue**: Instance is not registered/online with AWS Systems Manager (check E.3)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 11.5.1, NIST CM-8, CA-7, ISO 27001 A.8.16

An unmanaged instance has no patch state, inventory, or Session Manager fallback. Attach the SSM core policy and ensure the agent is running.

#### AWS Console
1. Attach an instance profile with **AmazonSSMManagedInstanceCore**
2. Ensure the SSM Agent is installed/running and the instance has network egress to the SSM endpoints (or VPC endpoints)
3. Confirm under **Systems Manager** -> **Fleet Manager** that the instance is **Online**

#### AWS CLI
```bash
aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=i-0123" \
  --query 'InstanceInformationList[].PingStatus'
```

#### Python boto3
```python
import boto3

def find_unmanaged_instances():
    ec2 = boto3.client('ec2')
    ssm = boto3.client('ssm')
    online = {i['InstanceId'] for i in ssm.describe_instance_information()[
        'InstanceInformationList'] if i.get('PingStatus') == 'Online'}
    flagged = []
    for r in ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
    )['Reservations']:
        for inst in r['Instances']:
            if inst['InstanceId'] not in online:
                flagged.append(inst['InstanceId'])
    for iid in flagged:
        print(f"MEDIUM: {iid} is not SSM-managed/online")
    return flagged

# Usage
find_unmanaged_instances()
```

---

### 31. Enable GuardDuty Runtime Monitoring

**Issue**: GuardDuty is not enabled with EC2 Runtime Monitoring and the EC2 agent (check E.4)
**Severity**: HIGH
**Compliance**: AWS-FSBP GuardDuty baseline, PCI-DSS 11.5.1, HIPAA 164.308(a)(6), NIST SI-4, IR-4, ISO 27001 A.8.16

GuardDuty Runtime Monitoring detects in-instance threats (cryptominers, reverse shells, credential access) that network-only analysis misses. Enable it with EC2 agent management.

#### AWS Console
1. **GuardDuty Console** -> enable GuardDuty (if not already)
2. **Protection plans** -> **Runtime Monitoring** -> enable, with **Automated agent configuration** for **EC2**
3. Confirm coverage under **Runtime Monitoring** -> **Coverage**

#### AWS CLI
```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty update-detector --detector-id "$DETECTOR" \
  --features '[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"EC2_AGENT_MANAGEMENT","Status":"ENABLED"}]}]'
```

#### Python boto3
```python
import boto3

def enable_guardduty_runtime():
    gd = boto3.client('guardduty')
    detectors = gd.list_detectors()['DetectorIds']
    if not detectors:
        print("HIGH: GuardDuty not enabled")
        return
    gd.update_detector(DetectorId=detectors[0], Features=[
        {'Name': 'RUNTIME_MONITORING', 'Status': 'ENABLED',
         'AdditionalConfiguration': [
             {'Name': 'EC2_AGENT_MANAGEMENT', 'Status': 'ENABLED'}]}])
    print("GuardDuty EC2 runtime monitoring enabled.")

# Usage
# enable_guardduty_runtime()
```

---

## Patch & Vulnerability Management

### 32. Maintain SSM Patch Compliance

**Issue**: An SSM-managed instance reports missing/failed patches (check F.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 6.3.3, HIPAA 164.312(c)(1), NIST SI-2, RA-5, ISO 27001 A.8.8

Unpatched CVEs are a top breach cause. Use Patch Manager with a baseline and a maintenance window to keep instances compliant.

#### AWS Console
1. **Systems Manager** -> **Patch Manager** -> **Configure patching**
2. Define a **patch baseline** and a **maintenance window** (scan + install) targeting the instances
3. Run **Patch now** for immediate remediation

#### AWS CLI
```bash
# Check patch state
aws ssm describe-instance-patch-states --instance-ids i-0123 \
  --query 'InstancePatchStates[].{Missing:MissingCount,Failed:FailedCount}'

# Patch now via the AWS-RunPatchBaseline document
aws ssm send-command --document-name "AWS-RunPatchBaseline" \
  --parameters Operation=Install --instance-ids i-0123
```

#### Python boto3
```python
import boto3

def find_noncompliant_patch_states():
    ssm = boto3.client('ssm')
    flagged = []
    for st in ssm.describe_instance_patch_states(
            InstanceIds=[i['InstanceId'] for i in
                         ssm.describe_instance_information()[
                             'InstanceInformationList']]
    ).get('InstancePatchStates', []):
        if st.get('MissingCount', 0) or st.get('FailedCount', 0):
            flagged.append(st['InstanceId'])
    for iid in flagged:
        print(f"HIGH: {iid} has missing/failed patches")
    return flagged

# Usage
# find_noncompliant_patch_states()
```

---

### 33. Refresh Stale AMIs

**Issue**: Instance runs on an AMI older than the threshold (default 180 days) (check F.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 6.3.3, NIST SI-2, CM-2, ISO 27001 A.8.8

Old AMIs start with hundreds of accumulated vulnerabilities. Bake AMIs on a regular cadence and relaunch instances from a current image.

#### AWS Console
1. Build a fresh, patched AMI (EC2 Image Builder or a manual bake)
2. Update launch templates / Auto Scaling groups to the new AMI ID
3. Roll instances to relaunch on the current AMI

#### AWS CLI
```bash
# Find the AMI age for an instance
AMI=$(aws ec2 describe-instances --instance-ids i-0123 \
  --query 'Reservations[0].Instances[0].ImageId' --output text)
aws ec2 describe-images --image-ids "$AMI" \
  --query 'Images[0].CreationDate'
# Remediation is to relaunch from a freshly baked AMI.
```

#### Python boto3
```python
import boto3
from datetime import datetime, timezone

def find_stale_amis(threshold_days=180):
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            img = ec2.describe_images(ImageIds=[inst['ImageId']])['Images']
            if not img:
                continue
            created = datetime.fromisoformat(
                img[0]['CreationDate'].replace('Z', '+00:00'))
            age = (datetime.now(timezone.utc) - created).days
            if age > threshold_days:
                flagged.append((inst['InstanceId'], age))
    for iid, age in flagged:
        print(f"MEDIUM: {iid} runs a {age}-day-old AMI")
    return flagged

# Usage
# find_stale_amis()
```

---

### 34. Enable Inspector v2 EC2 Scanning

**Issue**: Inspector v2 EC2 scanning is disabled, the instance is uncovered, or it has CRITICAL/HIGH findings (check F.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2 baseline, PCI-DSS 11.3.1, 11.5.1, NIST RA-5, SI-2, ISO 27001 A.8.8

Inspector v2 continuously scans for OS/library CVEs. Enable EC2 scanning, confirm coverage, and remediate CRITICAL/HIGH findings (via patching, remediation 32).

#### AWS Console
1. **Inspector Console** -> **Activate Inspector** -> enable **EC2 scanning**
2. Confirm the instance appears under **Coverage**
3. Triage and remediate **Critical/High** findings (patch, then rescan)

#### AWS CLI
```bash
aws inspector2 enable --resource-types EC2

aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"resourceType":[{"comparison":"EQUALS","value":"AWS_EC2_INSTANCE"}]}'
```

#### Python boto3
```python
import boto3

def inspector_status():
    ins = boto3.client('inspector2')
    sts = boto3.client('sts')
    acct = sts.get_caller_identity()['Account']
    state = ins.batch_get_account_status(accountIds=[acct])['accounts']
    for a in state:
        ec2_state = a['resourceState']['ec2']['status']
        print(f"Inspector EC2 scanning: {ec2_state}")
    return state

# Usage
# inspector_status()
```

---

## Network Exposure

### 35. Release Unused Elastic IPs

**Issue**: An Elastic IP is allocated but not associated (check G.1)
**Severity**: LOW
**Compliance**: AWS-FSBP EC2.12, NIST CM-8, ISO 27001 A.5.9

Dangling EIPs cost money and can leave stale DNS records (IP-squatting risk). Release the ones you no longer need.

#### AWS Console
1. **EC2 Console** -> **Elastic IPs** -> select an EIP with no association
2. **Actions** -> **Release Elastic IP addresses**
3. Confirm

#### AWS CLI
```bash
# List unassociated EIPs
aws ec2 describe-addresses \
  --query 'Addresses[?AssociationId==null].AllocationId'

# Release one
aws ec2 release-address --allocation-id eipalloc-0123
```

#### Python boto3
```python
import boto3

def find_unused_eips():
    ec2 = boto3.client('ec2')
    flagged = [a['AllocationId'] for a in ec2.describe_addresses()['Addresses']
               if not a.get('AssociationId')]
    for aid in flagged:
        print(f"LOW: unused Elastic IP {aid}")
    return flagged

# Usage
find_unused_eips()
```

---

### 36. Disable Launch Template Public IP Assignment

**Issue**: A launch template assigns public IPs (check G.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.25, PCI-DSS 1.3.1, NIST SC-7, AC-4, ISO 27001 A.8.22

Otherwise every Auto Scaling launch gets a public IP regardless of subnet settings. Publish a new template version with `AssociatePublicIpAddress=false`.

#### AWS Console
1. **EC2 Console** -> **Launch templates** -> **Modify template (create new version)**
2. Under **Network interfaces**, set **Auto-assign public IP** to **Disable**
3. Set the new version as **Default**

#### AWS CLI
```bash
aws ec2 create-launch-template-version \
  --launch-template-id lt-0123 --source-version 1 \
  --launch-template-data '{"NetworkInterfaces":[{"DeviceIndex":0,"AssociatePublicIpAddress":false}]}'
aws ec2 modify-launch-template --launch-template-id lt-0123 --default-version 2
```

#### Python boto3
```python
import boto3

def find_lt_public_ip():
    ec2 = boto3.client('ec2')
    flagged = []
    for lt in ec2.describe_launch_templates()['LaunchTemplates']:
        ver = ec2.describe_launch_template_versions(
            LaunchTemplateId=lt['LaunchTemplateId'],
            Versions=[str(lt['DefaultVersionNumber'])])['LaunchTemplateVersions'][0]
        for ni in ver['LaunchTemplateData'].get('NetworkInterfaces', []):
            if ni.get('AssociatePublicIpAddress'):
                flagged.append(lt['LaunchTemplateName'])
    for name in set(flagged):
        print(f"HIGH: launch template {name} assigns public IPs")
    return flagged

# Usage
find_lt_public_ip()
```

---

### 37. Lock Down the Default Security Group

**Issue**: A VPC's default security group allows inbound or outbound traffic (check G.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP EC2.2, CIS 5.5, PCI-DSS 1.2.1, NIST SC-7, AC-4, ISO 27001 A.8.20

Any instance that lands on the default SG inherits its permissiveness. Strip all rules so "forgot to pick an SG" fails closed.

#### AWS Console
1. **VPC Console** -> **Security groups** -> the **default** SG of each VPC
2. **Inbound rules** and **Outbound rules** -> **Edit** -> remove all rules
3. **Save rules**

#### AWS CLI
```bash
# Remove the default intra-SG inbound rule and the all-egress rule
aws ec2 revoke-security-group-ingress --group-id sg-default \
  --ip-permissions 'IpProtocol=-1,UserIdGroupPairs=[{GroupId=sg-default}]'
aws ec2 revoke-security-group-egress --group-id sg-default \
  --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
```

#### Python boto3
```python
import boto3

def find_permissive_default_sgs():
    ec2 = boto3.client('ec2')
    flagged = []
    for sg in ec2.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['default']}]
    )['SecurityGroups']:
        if sg.get('IpPermissions') or sg.get('IpPermissionsEgress'):
            flagged.append(sg['GroupId'])
    for gid in flagged:
        print(f"HIGH: default SG {gid} still has rules")
    return flagged

# Usage
find_permissive_default_sgs()
```

---

### 38. Remove Unused Security Groups

**Issue**: A security group is attached to no resource (check G.4)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.22, NIST CM-7, CM-8, ISO 27001 A.5.9

Unused SGs are clutter that can be attached later by mistake. Delete the ones no ENI references.

#### AWS Console
1. **VPC Console** -> **Security groups** -> identify SGs not referenced by any ENI
2. Select an unused (non-default) SG -> **Actions** -> **Delete security groups**
3. Confirm

#### AWS CLI
```bash
# SGs in use (referenced by ENIs)
IN_USE=$(aws ec2 describe-network-interfaces \
  --query 'NetworkInterfaces[].Groups[].GroupId' --output text | tr '\t' '\n' | sort -u)
# Compare against all SGs to find unused ones, then:
aws ec2 delete-security-group --group-id sg-unused
```

#### Python boto3
```python
import boto3

def find_unused_security_groups():
    ec2 = boto3.client('ec2')
    in_use = set()
    for eni in ec2.describe_network_interfaces()['NetworkInterfaces']:
        in_use.update(g['GroupId'] for g in eni.get('Groups', []))
    flagged = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        if sg['GroupName'] != 'default' and sg['GroupId'] not in in_use:
            flagged.append(sg['GroupId'])
    for gid in flagged:
        print(f"MEDIUM: security group {gid} is unused")
    return flagged

# Usage
find_unused_security_groups()
```

---

## Tagging & Inventory

### 39. Apply Required Tags

**Issue**: Instances, security groups, or volumes are missing required tags (check H.1)
**Severity**: LOW
**Compliance**: AWS-FSBP EC2.38, EC2.43, EC2.45, NIST CM-8, AC-3, ISO 27001 A.5.9

Tags (for example `Name`, `Environment`, `Owner`, `CostCenter`) are foundational to incident response, cost allocation, and policy automation. Apply the required keys to instances, SGs, and volumes.

#### AWS Console
1. **EC2 Console** -> select the resource (instance, security group, or volume) -> **Tags** tab -> **Manage tags**
2. Add the required keys/values
3. **Save**

#### AWS CLI
```bash
aws ec2 create-tags --resources i-0123 sg-0123 vol-0123 \
  --tags Key=Name,Value=app01 Key=Environment,Value=prod \
         Key=Owner,Value=platform Key=CostCenter,Value=cc-42
```

#### Python boto3
```python
import boto3

REQUIRED = {'Name', 'Environment', 'Owner', 'CostCenter'}

def find_untagged_instances():
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances()['Reservations']:
        for inst in r['Instances']:
            keys = {t['Key'] for t in inst.get('Tags', [])}
            missing = REQUIRED - keys
            if missing:
                flagged.append((inst['InstanceId'], missing))
    for iid, missing in flagged:
        print(f"LOW: {iid} missing tags {missing}")
    return flagged

# Usage
find_untagged_instances()
```

---

### 40. Clean Up Stopped Instances

**Issue**: An instance has been stopped longer than the threshold (default 30 days) (check H.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EC2.4, NIST CM-8, MP-6, ISO 27001 A.8.10

A long-stopped instance keeps its EBS data and IAM permissions and can be restarted by anyone with `ec2:StartInstances`. Terminate it after confirming the data is backed up / no longer needed.

#### AWS Console
1. **EC2 Console** -> filter **Instance state = stopped**, review the **stopped** duration
2. Confirm backups, then select the instance -> **Instance state** -> **Terminate instance**
3. Confirm

#### AWS CLI
```bash
# List stopped instances and when they stopped
aws ec2 describe-instances \
  --filters Name=instance-state-name,Values=stopped \
  --query 'Reservations[].Instances[].[InstanceId,StateTransitionReason]'

# Terminate after verifying backups
aws ec2 terminate-instances --instance-ids i-0123
```

#### Python boto3
```python
import boto3

def find_long_stopped_instances():
    ec2 = boto3.client('ec2')
    flagged = []
    for r in ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )['Reservations']:
        for inst in r['Instances']:
            flagged.append((inst['InstanceId'],
                            inst.get('StateTransitionReason', '')))
    for iid, reason in flagged:
        print(f"MEDIUM: stopped instance {iid} ({reason})")
    return flagged

# Usage
find_long_stopped_instances()
```

---

## Quick Reference Commands

### Read-Only Audit Script

```bash
#!/bin/bash
# ec2-quick-audit.sh - read-only checks that mirror common findings
REGION=${1:-us-east-1}

echo "== Instances allowing IMDSv1 (A.1) =="
aws ec2 describe-instances --region "$REGION" \
  --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`].InstanceId'

echo "== Instances with public IPv4 (A.2) =="
aws ec2 describe-instances --region "$REGION" \
  --query 'Reservations[].Instances[?PublicIpAddress!=null].InstanceId'

echo "== Public EBS snapshots (C.3) =="
for s in $(aws ec2 describe-snapshots --region "$REGION" --owner-ids self \
  --query 'Snapshots[].SnapshotId' --output text); do
  aws ec2 describe-snapshot-attribute --region "$REGION" --snapshot-id "$s" \
    --attribute createVolumePermission \
    --query 'CreateVolumePermissions[?Group==`all`]' --output text | grep -q all \
    && echo "  PUBLIC: $s"
done

echo "== EBS default encryption (C.2) / Snapshot BPA (C.7) =="
aws ec2 get-ebs-encryption-by-default --region "$REGION" --query 'EbsEncryptionByDefault'
aws ec2 get-snapshot-block-public-access-state --region "$REGION" --query 'State'
```

### Python Bulk Hardening Function

```python
import boto3


def harden_account_region(region='us-east-1'):
    """Apply account/region-wide EC2 preventive controls (idempotent)."""
    ec2 = boto3.client('ec2', region_name=region)
    ec2.enable_ebs_encryption_by_default()                         # C.2
    ec2.enable_snapshot_block_public_access(State='block-all-sharing')  # C.7
    try:
        ec2.modify_vpc_block_public_access_options(
            InternetGatewayBlockMode='block-ingress')              # B.11
    except ec2.exceptions.ClientError as e:
        print(f"VPC BPA: {e}")
    print(f"Account/region preventive controls applied in {region}. "
          f"Per-instance findings (IMDSv2, public IP, IAM) need per-resource fixes.")


# Usage
# harden_account_region('us-east-1')
```

---

## Additional Notes

### AWS IAM Permissions Required

Remediation requires write access across EC2, IAM, SSM, CloudTrail, CloudWatch, GuardDuty, Inspector, and Backup:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "ec2:AssociateIamInstanceProfile",
                "iam:PassRole",
                "ssm:SendCommand",
                "cloudtrail:CreateTrail",
                "cloudtrail:StartLogging",
                "cloudwatch:PutMetricAlarm",
                "guardduty:UpdateDetector",
                "inspector2:Enable",
                "backup:StartBackupJob"
            ],
            "Resource": "*"
        }
    ]
}
```

> The **scanner itself** only needs read-only permissions (see the README IAM policy). Apply remediation changes from a separate, tightly-controlled administrative principal.

### Validation Commands

After applying remediations, verify with:

```bash
# Re-run the EC2 Security Scanner
ec2-security-scanner security --compliance-only

# Spot-check specific controls
aws ec2 describe-instances --instance-ids i-0123 \
  --query 'Reservations[].Instances[].{IMDS:MetadataOptions.HttpTokens,PublicIP:PublicIpAddress,Profile:IamInstanceProfile.Arn}'
aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault'
aws ec2 get-snapshot-block-public-access-state --query 'State'
```

### Emergency Response

For an exposed or compromised instance:

```bash
# 1. Isolate: replace the instance's SGs with a quarantine SG (no ingress/egress)
aws ec2 modify-instance-attribute --instance-id i-0123 --groups sg-quarantine

# 2. Make any public snapshot/AMI private immediately
aws ec2 modify-snapshot-attribute --snapshot-id snap-0123 \
  --attribute createVolumePermission --operation-type remove --group-names all
aws ec2 modify-image-attribute --image-id ami-0123 \
  --launch-permission '{"Remove":[{"Group":"all"}]}'

# 3. Revoke the instance role's sessions (rotate/scope the role) and snapshot
#    the volumes for forensics before stopping the instance.
aws ec2 create-snapshot --volume-id vol-0123 --description "forensics"

# 4. Review CloudTrail, VPC Flow Logs, and GuardDuty findings for the instance.
```

This comprehensive remediation guide provides solutions for all security vulnerabilities detected by the EC2 Security Scanner. Each remediation includes multiple implementation methods to accommodate different operational preferences and automation requirements.
