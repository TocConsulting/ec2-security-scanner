# EC2 Security Scanner — Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for every security finding produced by the EC2 Security Scanner. Each finding includes remediation via the AWS Console, the AWS CLI, and Python `boto3`.

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|-------------------|
| EC2 Security Best Practices | [AWS EC2 Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html) |
| IMDSv2 (Instance Metadata Service v2) | [Configure IMDS Options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) |
| Security Groups | [Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) |
| EBS Encryption | [EBS Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html) |
| EBS Snapshot BPA | [Block public access for snapshots](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-snapshots.html) |
| VPC Block Public Access | [VPC BPA](https://docs.aws.amazon.com/vpc/latest/userguide/security-vpc-bpa.html) |
| Amazon Inspector v2 | [Inspector User Guide](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) |
| AWS Systems Manager | [Systems Manager User Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html) |
| AWS GuardDuty EC2 | [GuardDuty Runtime Monitoring](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html) |
| AWS CloudTrail | [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) |
| AWS Backup | [AWS Backup User Guide](https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html) |

## Table of Contents

1. [Instance Security (A.*)](#instance-security)
2. [Network Security (B.*)](#network-security)
3. [Storage Security (C.*)](#storage-security)
4. [Access Control (D.*)](#access-control)
5. [Logging & Monitoring (E.*)](#logging--monitoring)
6. [Patch & Vulnerability (F.*)](#patch--vulnerability)
7. [Network Exposure (G.*)](#network-exposure)
8. [Tagging & Inventory (H.*)](#tagging--inventory)
9. [Errored Checks](#errored-checks)

---

## Instance Security

### IMDSV2_NOT_ENFORCED — HIGH

**Issue:** Instance allows IMDSv1 (`HttpTokens=optional`), which is vulnerable to SSRF attacks.

#### AWS Console
1. EC2 → Instances → select instance → **Actions** → **Instance settings** → **Modify instance metadata options**
2. Set **IMDSv2** to **Required**, **Metadata response hop limit** to **1** or **2**
3. Save.

#### AWS CLI
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123 \
  --http-tokens required \
  --http-put-response-hop-limit 2 \
  --http-endpoint enabled
```

#### Python boto3
```python
import boto3
ec2 = boto3.client("ec2")
ec2.modify_instance_metadata_options(
    InstanceId="i-0abc123",
    HttpTokens="required",
    HttpPutResponseHopLimit=2,
    HttpEndpoint="enabled",
)
```

### IMDSV2_HOP_LIMIT_TOO_HIGH — LOW

**Issue:** IMDSv2 is enforced but `HttpPutResponseHopLimit > 2`, which lets tokens leak through nested containers.

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123 \
  --http-put-response-hop-limit 2
```

### LAUNCH_TEMPLATE_IMDSV2_NOT_ENFORCED — HIGH

**Issue:** Launch template does not enforce IMDSv2; new instances will inherit insecure defaults.

#### AWS CLI
```bash
# Create new version with IMDSv2 enforced
aws ec2 create-launch-template-version \
  --launch-template-id lt-0abc \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpPutResponseHopLimit": 2,
      "HttpEndpoint": "enabled"
    }
  }' \
  --source-version 1

# Set the new version as default
aws ec2 modify-launch-template \
  --launch-template-id lt-0abc \
  --default-version 2
```

### PUBLIC_IP_ASSIGNED — HIGH

**Issue:** Instance has a public IPv4 address, increasing its attack surface.

#### Mitigation strategy
A running EC2 instance's public IP can only be removed by replacing the network interface. Long-term remediation:
1. Place the instance in a **private subnet** and route outbound traffic through a NAT Gateway or VPC endpoints.
2. For inbound admin access, use **SSM Session Manager** or **EC2 Instance Connect Endpoint**.
3. For inbound user traffic, place an **ALB/NLB** in a public subnet and put the instance behind it.

#### Disassociating an Elastic IP
```bash
aws ec2 disassociate-address --association-id eipassoc-0abc
aws ec2 release-address --allocation-id eipalloc-0abc
```

### NO_IAM_PROFILE — MEDIUM

**Issue:** No IAM instance profile is attached; the application must use long-lived access keys (often baked into AMIs or UserData).

#### AWS CLI
```bash
# 1. Create role + trust policy
aws iam create-role --role-name MyEC2Role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# 2. Attach a least-privilege managed policy (example: SSM only)
aws iam attach-role-policy --role-name MyEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# 3. Create instance profile, add role
aws iam create-instance-profile --instance-profile-name MyEC2Profile
aws iam add-role-to-instance-profile --instance-profile-name MyEC2Profile --role-name MyEC2Role

# 4. Attach to running instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-0abc123 \
  --iam-instance-profile Name=MyEC2Profile
```

### PARAVIRTUAL_INSTANCE — MEDIUM

**Issue:** Instance uses PV virtualization. PV has weaker security isolation than HVM.

**Fix:** Re-launch using an HVM instance type (e.g., `t3.*`, `m5.*`). PV instance types (e.g., `t1.micro`) cannot be upgraded in place — create a new instance from an HVM-compatible AMI and migrate workload.

### MULTIPLE_ENIS — LOW

**Issue:** Instance has more than one ENI. This is sometimes intentional (dual-homed firewall, NAT), but otherwise expands the attack surface.

#### AWS CLI
```bash
# List ENIs and detach the unnecessary ones
aws ec2 describe-network-interfaces --filters Name=attachment.instance-id,Values=i-0abc123
aws ec2 detach-network-interface --attachment-id eni-attach-0abc
```

### DETAILED_MONITORING_DISABLED — MEDIUM

**Issue:** Detailed (1-minute) CloudWatch monitoring is off; only 5-minute basic metrics are collected.

#### AWS CLI
```bash
aws ec2 monitor-instances --instance-ids i-0abc123
```

### USERDATA_SECRETS_EXPOSED — CRITICAL

**Issue:** UserData contains hardcoded secrets (AWS keys, passwords, API tokens).

#### Remediation
1. **Rotate the leaked secret immediately** (most important step).
2. Use AWS Secrets Manager or SSM Parameter Store and read the secret at boot:
   ```bash
   # In UserData script:
   DB_PASSWORD=$(aws secretsmanager get-secret-value \
     --secret-id prod/db/password --query SecretString --output text)
   ```
3. Replace UserData with sanitized version:
   ```bash
   # Stop instance, modify UserData attribute
   aws ec2 stop-instances --instance-ids i-0abc123
   aws ec2 modify-instance-attribute --instance-id i-0abc123 \
     --user-data file://clean-userdata.sh
   aws ec2 start-instances --instance-ids i-0abc123
   ```
4. For instances launched from a Launch Template, update the template version and refresh the Auto Scaling Group.

---

## Network Security

### DEFAULT_SG_HAS_RULES — HIGH

**Issue:** VPC default SG has rules. The default SG is the fallback for new ENIs and should restrict all traffic.

#### AWS CLI
```bash
# Find default SG
SG_ID=$(aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=vpc-0abc Name=group-name,Values=default \
  --query 'SecurityGroups[0].GroupId' --output text)

# Revoke ALL ingress and egress rules
aws ec2 revoke-security-group-ingress --group-id $SG_ID \
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].IpPermissions' --output json)"
aws ec2 revoke-security-group-egress --group-id $SG_ID \
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].IpPermissionsEgress' --output json)"
```

### SSH_OPEN_TO_WORLD — HIGH

**Issue:** Security group allows port 22 from `0.0.0.0/0`.

#### AWS CLI
```bash
# Revoke the offending rule
aws ec2 revoke-security-group-ingress --group-id sg-0abc \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Better: use SSM Session Manager (no inbound port needed)
aws ssm start-session --target i-0abc123
```

### RDP_OPEN_TO_WORLD — HIGH

**Issue:** Security group allows port 3389 from `0.0.0.0/0`.

```bash
aws ec2 revoke-security-group-ingress --group-id sg-0abc \
  --protocol tcp --port 3389 --cidr 0.0.0.0/0

# Use Fleet Manager / Session Manager for RDP forwarding instead
```

### HIGH_RISK_PORTS_OPEN — CRITICAL

**Issue:** High-risk service ports (3306 MySQL, 5432 Postgres, 1433/1434 MSSQL, 9200/9300 Elasticsearch, 5601 Kibana, 8080/8088/8888 admin consoles, etc.) open to the world. The scanner flags the 24-port AWS FSBP EC2.19 canonical list.

```bash
# Identify and revoke each
aws ec2 revoke-security-group-ingress --group-id sg-0abc \
  --protocol tcp --port 3306 --cidr 0.0.0.0/0
```

**Better:** databases should be in private subnets, with VPC peering or PrivateLink for cross-account access.

### REMOTE_ADMIN_PORTS_OPEN — HIGH

**Issue:** Other remote admin protocols (Telnet 23, SMB 445, WinRM 5985/5986, VNC 5900) open to the world.

```bash
for port in 23 445 5985 5986 5900; do
  aws ec2 revoke-security-group-ingress --group-id sg-0abc \
    --protocol tcp --port $port --cidr 0.0.0.0/0 || true
done
```

### NO_VPC_FLOW_LOGS — MEDIUM

**Issue:** VPC flow logging is not enabled — no audit trail for network traffic.

#### AWS CLI
```bash
# Create log group
aws logs create-log-group --log-group-name /aws/vpc/flowlogs

# Create flow log
aws ec2 create-flow-logs \
  --resource-type VPC --resource-ids vpc-0abc \
  --traffic-type ALL \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogsRole
```

### NACL_ADMIN_PORTS_OPEN — MEDIUM

**Issue:** Network ACL allows SSH/RDP from `0.0.0.0/0`. NACLs are stateless, so even denied SGs may not protect if NACLs are open.

```bash
# Revoke offending NACL entry (replace rule_number)
aws ec2 delete-network-acl-entry --network-acl-id acl-0abc --rule-number 100 --ingress
```

### SOURCE_DEST_CHECK_DISABLED — MEDIUM

**Issue:** Source/destination check is off but instance isn't a NAT/VPN/firewall — could enable IP spoofing.

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-0abc123 \
  --source-dest-check '{"Value":true}'
```

### UNRESTRICTED_EGRESS — MEDIUM

**Issue:** SG allows all outbound traffic.

```bash
# Replace default 0.0.0.0/0 egress with allow-lists
aws ec2 revoke-security-group-egress --group-id sg-0abc \
  --protocol -1 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress --group-id sg-0abc \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
```

### UNAUTHORIZED_PORTS_OPEN — HIGH

**Issue:** Ports other than 80/443 are open to the world.

Audit the rule and either restrict the CIDR (specific IP range) or remove the rule entirely.

---

## Storage Security

### EBS_NOT_ENCRYPTED — MEDIUM

**Issue:** One or more EBS volumes on the instance are not encrypted at rest.

#### Procedure
1. Create an encrypted snapshot of the unencrypted volume:
   ```bash
   SNAP=$(aws ec2 create-snapshot --volume-id vol-0abc --query 'SnapshotId' --output text)
   aws ec2 copy-snapshot --source-snapshot-id $SNAP --source-region us-east-1 --encrypted
   ```
2. Create a new encrypted volume from the encrypted snapshot.
3. Stop the instance, detach the old volume, attach the new encrypted volume.
4. Delete the unencrypted volume.

### EBS_DEFAULT_ENCRYPTION_DISABLED — MEDIUM

**Issue:** New EBS volumes in this region aren't encrypted by default.

```bash
aws ec2 enable-ebs-encryption-by-default
aws ec2 modify-ebs-default-kms-key-id --kms-key-id alias/aws/ebs
```

### PUBLIC_EBS_SNAPSHOTS — CRITICAL

**Issue:** EBS snapshots owned by this account are publicly accessible.

```bash
aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc \
  --attribute createVolumePermission --operation-type remove \
  --group-names all
```

### NO_EBS_BACKUP — LOW

**Issue:** Volumes are not part of an AWS Backup plan.

Set up a backup plan via the AWS Backup console (recommended) or:
```bash
aws backup create-backup-plan --backup-plan file://plan.json
aws backup create-backup-selection \
  --backup-plan-id <id> --backup-selection file://selection.json
```

### LAUNCH_TEMPLATE_EBS_NOT_ENCRYPTED — MEDIUM

**Issue:** Launch template's `BlockDeviceMappings` define volumes with `Encrypted=false`.

```bash
aws ec2 create-launch-template-version \
  --launch-template-id lt-0abc \
  --source-version 1 \
  --launch-template-data '{
    "BlockDeviceMappings": [{
      "DeviceName": "/dev/xvda",
      "Ebs": {"Encrypted": true, "VolumeType": "gp3"}
    }]
  }'
aws ec2 modify-launch-template --launch-template-id lt-0abc --default-version <new-version>
```

### PUBLIC_AMI_SHARING — CRITICAL

**Issue:** Account has AMIs shared publicly.

```bash
aws ec2 modify-image-attribute --image-id ami-0abc \
  --launch-permission "Remove=[{Group=all}]"
```

### EBS_SNAPSHOT_BPA_NOT_ENABLED — HIGH

**Issue:** Account-level EBS Snapshot Block Public Access is not enabled. (FSBP EC2.182)

```bash
aws ec2 enable-snapshot-block-public-access --state block-all-sharing
# Verify
aws ec2 get-snapshot-block-public-access-state
```

---

## Access Control

### IAM_ADMIN_ACCESS — HIGH

**Issue:** IAM role attached to the instance has admin or wildcard permissions (`Action: *`, `NotAction`, service-level wildcards on broad resources).

#### Remediation
1. Audit the policy and replace `*` with specific actions and resource ARNs.
2. Use [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html) to generate a least-privilege policy based on real usage.
3. Detach the over-broad managed policy and attach a scoped policy:
   ```bash
   aws iam detach-role-policy --role-name MyEC2Role \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   aws iam attach-role-policy --role-name MyEC2Role \
     --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
   ```

### KEY_PAIR_WITHOUT_SSM — MEDIUM

**Issue:** Instance has an SSH key pair but is not SSM-managed.

#### Fix
1. Install the SSM agent (already present on AL2/AL2023/Ubuntu 20.04+).
2. Attach an IAM role with `AmazonSSMManagedInstanceCore`.
3. Confirm:
   ```bash
   aws ssm describe-instance-information --filters Key=InstanceIds,Values=i-0abc123
   ```
4. Use `aws ssm start-session` instead of SSH and remove the key pair from the instance.

### SERIAL_CONSOLE_ENABLED — MEDIUM

**Issue:** EC2 Serial Console access is enabled at the account level.

```bash
aws ec2 disable-serial-console-access
```

### NO_INSTANCE_CONNECT_ENDPOINT — LOW

**Issue:** No EC2 Instance Connect Endpoint configured in the VPC.

```bash
aws ec2 create-instance-connect-endpoint \
  --subnet-id subnet-0abc \
  --security-group-ids sg-0abc
```

---

## Logging & Monitoring

### NO_CLOUDTRAIL — HIGH

**Issue:** No active multi-region CloudTrail trail.

```bash
aws cloudtrail create-trail \
  --name org-trail --s3-bucket-name my-trail-bucket \
  --is-multi-region-trail --enable-log-file-validation
aws cloudtrail start-logging --name org-trail
```

### NO_CLOUDWATCH_ALARMS — MEDIUM

**Issue:** No CloudWatch alarms configured for instance metrics.

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "i-0abc123-cpu-high" \
  --metric-name CPUUtilization --namespace AWS/EC2 \
  --statistic Average --period 300 --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=InstanceId,Value=i-0abc123 \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:ops-alerts
```

### NOT_SSM_MANAGED — MEDIUM

**Issue:** Instance is not registered with Systems Manager.

Checklist:
1. Install/start the SSM agent.
2. Attach `AmazonSSMManagedInstanceCore` to the instance role.
3. Ensure outbound HTTPS to `ssm.<region>.amazonaws.com`, `ssmmessages.<region>.amazonaws.com`, `ec2messages.<region>.amazonaws.com` (or VPC endpoints in a private subnet).

### NO_GUARDDUTY — HIGH

**Issue:** GuardDuty with EC2 runtime monitoring is not enabled for this account.

```bash
DETECTOR_ID=$(aws guardduty create-detector --enable --query DetectorId --output text)
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --features '[{
    "Name":"RUNTIME_MONITORING",
    "Status":"ENABLED",
    "AdditionalConfiguration":[{
      "Name":"EC2_AGENT_MANAGEMENT","Status":"ENABLED"
    }]
  }]'
```

---

## Patch & Vulnerability

### SSM_PATCH_NONCOMPLIANT — HIGH

**Issue:** SSM reports missing or failed patches on the instance.

```bash
# Trigger immediate patch scan and install
aws ssm send-command \
  --document-name AWS-RunPatchBaseline \
  --targets Key=InstanceIds,Values=i-0abc123 \
  --parameters Operation=Install
```

For ongoing compliance, set up an SSM Patch Manager **Patch Group** and a maintenance window.

### STALE_AMI — MEDIUM

**Issue:** Instance is running an AMI older than 180 days.

#### Fix
1. Identify the latest patched AMI for your distro (e.g., latest AL2023, Ubuntu 22.04 LTS).
2. Create a new AMI (or use the official AWS-provided AMI), and replace the instance using a blue/green or rolling deployment.
3. For Auto Scaling Groups, update the Launch Template to the new AMI ID and refresh the instances.

### INSPECTOR_V2_DISABLED — HIGH
### INSPECTOR_CRITICAL_FINDINGS — HIGH

**Issue:** Amazon Inspector v2 EC2 scanning is not enabled, or critical/high findings exist.

```bash
# Enable Inspector v2 for EC2 in account
aws inspector2 enable --resource-types EC2

# List critical/high findings
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}'
```

Remediate critical findings by patching, hardening or removing affected packages.

---

## Network Exposure

### UNUSED_ELASTIC_IPS — LOW

**Issue:** Account has Elastic IPs not attached to a running instance (incurs charges).

```bash
aws ec2 release-address --allocation-id eipalloc-0abc
```

### LAUNCH_TEMPLATE_PUBLIC_IP — HIGH

**Issue:** Launch template assigns public IPs to instances.

```bash
aws ec2 create-launch-template-version \
  --launch-template-id lt-0abc \
  --source-version 1 \
  --launch-template-data '{
    "NetworkInterfaces": [{
      "DeviceIndex": 0,
      "AssociatePublicIpAddress": false,
      "Groups": ["sg-0abc"]
    }]
  }'
aws ec2 modify-launch-template --launch-template-id lt-0abc --default-version <new>
```

### SUBNET_AUTO_ASSIGN_PUBLIC_IP — MEDIUM

**Issue:** Subnet has `MapPublicIpOnLaunch=true`.

```bash
aws ec2 modify-subnet-attribute \
  --subnet-id subnet-0abc --no-map-public-ip-on-launch
```

### VPC_BPA_NOT_ENABLED — HIGH

**Issue:** VPC Block Public Access is not blocking IGW traffic.

```bash
aws ec2 modify-vpc-block-public-access-options \
  --internet-gateway-block-mode block-bidirectional
```

### TGW_AUTO_ACCEPT — HIGH

**Issue:** Transit Gateway auto-accepts VPC attachments (anyone in the org can attach).

```bash
aws ec2 modify-transit-gateway \
  --transit-gateway-id tgw-0abc \
  --options AutoAcceptSharedAttachments=disable
```

### VPN_NOT_IKEV2 — HIGH

**Issue:** Site-to-Site VPN tunnel permits IKEv1 (deprecated).

Modify each tunnel:
```bash
aws ec2 modify-vpn-tunnel-options \
  --vpn-connection-id vpn-0abc \
  --vpn-tunnel-outside-ip-address <tunnel-outside-ip> \
  --tunnel-options '{"IKEVersions":[{"Value":"ikev2"}]}'
```

---

## Tagging & Inventory

### MISSING_REQUIRED_TAGS — LOW

**Issue:** Instance is missing required tags (Name, Environment, Owner).

```bash
aws ec2 create-tags --resources i-0abc123 \
  --tags Key=Name,Value=prod-web-01 \
         Key=Environment,Value=production \
         Key=Owner,Value=platform-team
```

### STOPPED_INSTANCE_STALE — MEDIUM

**Issue:** Instance has been stopped for more than the configured threshold (default 30 days).

Terminate or document the reason in a tag:
```bash
aws ec2 terminate-instances --instance-ids i-0abc123
# or
aws ec2 create-tags --resources i-0abc123 --tags Key=KeepReason,Value="awaiting-DR-test"
```

### UNUSED_SECURITY_GROUPS — MEDIUM

**Issue:** Security groups in the account are not attached to any ENI.

```bash
aws ec2 delete-security-group --group-id sg-0abc
```

---

## Errored Checks

### CHECK_FAILED — ERROR

**Issue:** The scanner could not run one or more checks because the AWS API returned an error (most commonly `AccessDenied`).

This is **not** a security finding — it means the scanner's IAM role is missing permissions. Compare the failing check name against the required permissions table in the [README](README.md#aws-requirements) and grant the missing permission. After the fix, rerun the scan.

If the failure is persistent (`InvalidParameterValue`, `Throttling`, etc.), please file an issue: https://github.com/TocConsulting/ec2-security-scanner/issues

---

## Bulk Hardening Script

The following script remediates the most common findings on a single instance:

```bash
#!/bin/bash
set -euo pipefail
INSTANCE_ID="$1"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Enforce IMDSv2
aws ec2 modify-instance-metadata-options --region "$REGION" \
  --instance-id "$INSTANCE_ID" \
  --http-tokens required --http-put-response-hop-limit 2

# Enable detailed monitoring
aws ec2 monitor-instances --region "$REGION" --instance-ids "$INSTANCE_ID"

# Enable source/dest check
aws ec2 modify-instance-attribute --region "$REGION" \
  --instance-id "$INSTANCE_ID" --source-dest-check '{"Value":true}'

# Add required tags
aws ec2 create-tags --region "$REGION" --resources "$INSTANCE_ID" \
  --tags Key=Environment,Value=production Key=Owner,Value=ops

echo "Hardened $INSTANCE_ID"
```

For organization-wide enforcement, prefer [AWS Config rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html) and [Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) — Config detects drift, SCPs prevent it at the API boundary.
