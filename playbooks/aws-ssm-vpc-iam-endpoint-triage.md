# PB-CLOUD-004: AWS Systems Manager (SSM), VPC Endpoints & IAM Instance Profile Triage

- **Document ID:** PB-CLOUD-004
- **Version:** 1.1.0
- **Domain:** Cloud Infrastructure & SecOps (AWS EC2 / Systems Manager / IAM / VPC)
- **Target OS:** Windows Server 2019/2022 & Amazon Linux 2023 / Ubuntu LTS

---

## 1. Incident Scope & Symptoms

Managed EC2 instances deployed in private or isolated VPC subnets (`10.24.16.0/24`) report **Connection Lost** or **Unmanaged** in AWS Systems Manager Fleet Manager, preventing patch orchestration (Patch Manager), Session Manager shell access, and automated incident response playbooks.

### Common Observable Indicators
- AWS Systems Manager Fleet Manager shows `PingStatus: ConnectionLost` or the instance is completely absent from Managed Nodes.
- Attempting to start an SSM Session fails with `TargetNotConnected`.
- Instance system logs (`C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log` or `/var/log/amazon/ssm/amazon-ssm-agent.log`) display:
  - `RequestError: send request failed caused by: Post "https://ssm.us-east-1.amazonaws.com/": dial tcp 52.46.132.10:443: i/o timeout`
  - `AccessDeniedException: User: arn:aws:sts::111122223333:assumed-role/CorpEC2Role/i-0a1b2c3d4e5f6g7h8 is not authorized to perform: ssm:UpdateInstanceInformation`
  - `EC2RoleRequestError: no EC2 instance role found` or IMDSv2 token retrieval failure (`HTTP 401 Unauthorized` on `169.254.169.254`).

---

## 2. Architecture & Failure Points

AWS Systems Manager Agent (`amazon-ssm-agent`) requires four operational layers to register and maintain a persistent control channel without opening inbound SSH (`22`) or RDP (`3389`) ports:

```text
[OS Service: AmazonSSMAgent]
             │
             ▼
[Instance Metadata Service (IMDSv2): 169.254.169.254:80]
             │
             ▼
[IAM Instance Profile: AmazonSSMManagedInstanceCore]
             │
             ▼
[TLS 443 Egress via NAT Gateway OR VPC Interface Endpoints (ssm / ssmmessages / ec2messages)]
```

| Layer | Component | Typical Root Cause |
| :--- | :--- | :--- |
| **Metadata (IMDSv2)** | `http://169.254.169.254/latest/` | Windows Firewall or static route blocking link-local `169.254.169.254/32`, or `HttpPutResponseHopLimit = 1` inside containerized workloads. |
| **Identity (IAM)** | IAM Instance Profile | Missing `AmazonSSMManagedInstanceCore` managed policy, or KMS key policy blocking `kms:Decrypt` on Session Manager encrypted sessions. |
| **Network / DNS** | VPC Endpoints / NAT Gateway | Private subnet without NAT Gateway missing the 3 required VPC Interface Endpoints (`ssm`, `ssmmessages`, `ec2messages`) or Private DNS disabled on the endpoint. |
| **Endpoint Security** | Security Group / NACL / Proxy | Outbound TCP `443` restricted in Security Group, or corporate WinHTTP proxy redirecting `169.254.169.254` metadata traffic away from the link-local interface. |

---

## 3. Diagnostic Triage Procedure

### Step 3.1: Control-Plane Check via AWS CLI (From SecOps Jump Host)
Before accessing the host, verify the EC2 instance metadata options, attached IAM Instance Profile, and subnet routing from the AWS CLI:
```bash
# Verify IAM Instance Profile and IMDSv2 configuration
aws ec2 describe-instances \
    --instance-ids i-0a1b2c3d4e5f6g7h8 \
    --query "Reservations[0].Instances[0].{State:State.Name,SubnetId:SubnetId,VpcId:VpcId,IamProfile:IamInstanceProfile.Arn,MetadataOptions:MetadataOptions}" \
    --output json

# Check last known SSM heartbeat status
aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=i-0a1b2c3d4e5f6g7h8" \
    --output json
```

### Step 3.2: Verify VPC Interface Endpoints (Private Subnets Without NAT)
If the instance resides in an air-gapped or private subnet without an Internet/NAT Gateway, verify that `com.amazonaws.<region>.ssm` and `com.amazonaws.<region>.ssmmessages` exist, have `PrivateDnsEnabled: true`, and allow inbound TCP `443` from the instance's Security Group:
```bash
aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=vpc-0123456789abcdef0" \
    --query "VpcEndpoints[].{Service:ServiceName,State:State,PrivateDns:PrivateDnsEnabled,Subnets:SubnetIds}" \
    --output table
```

### Step 3.3: Host-Level Triage on Windows Server EC2 Nodes
Execute via EC2 Serial Console, WinRM from a bastion host, or offline volume inspection:

```powershell
# 1. Verify Amazon SSM Agent service state
Get-Service -Name "AmazonSSMAgent" | Select-Object Name, Status, StartType

# 2. Test IMDSv2 Token Generation and IAM Role retrieval (Link-Local 169.254.169.254)
$token = Invoke-RestMethod -Uri "http://169.254.169.254/latest/api/token" -Method Put -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -TimeoutSec 5
$roleName = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" -Headers @{"X-aws-ec2-metadata-token" = $token} -TimeoutSec 5
Write-Output "Attached IAM Role: $roleName"

# 3. Verify DNS resolution and TCP 443 reachability to Regional SSM Endpoints
$region = "us-east-1"
foreach ($svc in @("ssm", "ssmmessages", "ec2messages")) {
    $fqdn = "$svc.$region.amazonaws.com"
    Test-NetConnection -ComputerName $fqdn -Port 443 | Select-Object ComputerName, RemoteAddress, TcpTestSucceeded
}

# 4. Inspect recent errors in Amazon SSM Agent log
Get-Content -Path "C:\ProgramData\Amazon\SSM\Logs\errors.log" -Tail 25 -ErrorAction SilentlyContinue
```

---

## 4. Remediation & Recovery

### Scenario A: Missing `NO_PROXY` Exclusion for Link-Local Metadata (`169.254.169.254`)
When a corporate proxy is configured on Windows Server EC2 instances for outbound web filtering, `amazon-ssm-agent` attempts to route `169.254.169.254` through the proxy, causing `EC2RoleRequestError`.
Configure the proxy bypass list for the `AmazonSSMAgent` service registry key and restart the agent:
```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AmazonSSMAgent"
[string[]]$envVars = @(
    "HTTPS_PROXY=http://proxy.corp.contoso.com:8080",
    "NO_PROXY=169.254.169.254,ssm.us-east-1.amazonaws.com,ssmmessages.us-east-1.amazonaws.com,ec2messages.us-east-1.amazonaws.com"
)
Set-ItemProperty -Path $regPath -Name "Environment" -Value $envVars -Type MultiString
Restart-Service -Name "AmazonSSMAgent" -Force
```

### Scenario B: Broken Persistent Route to `169.254.169.254` After Sysprep / AMI Clone
Restore the default Amazon EC2 link-local route to the primary network interface gateway via EC2Launch v2:
```powershell
& "C:\Program Files\Amazon\EC2Launch\ec2launch.exe" reset --Private
Restart-Service -Name "AmazonSSMAgent" -Force
```

### Scenario C: Missing `AmazonSSMManagedInstanceCore` Policy on Instance Profile
Attach the required baseline AWS managed policy to the instance role:
```bash
aws iam attach-role-policy \
    --role-name CorpEC2Role \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

---

## 5. Verification & Post-Incident Validation

1. **Verify SSM Heartbeat Online:**
   ```bash
   aws ssm describe-instance-information \
       --filters "Key=InstanceIds,Values=i-0a1b2c3d4e5f6g7h8" \
       --query "InstanceInformationList[0].{InstanceId:InstanceId,PingStatus:PingStatus,AgentVersion:AgentVersion,LastPingDateTime:LastPingDateTime}"
   ```
   Confirm `PingStatus` returns `Online`.
2. **Validate Session Manager Control Channel:**
   ```bash
   aws ssm start-session --target i-0a1b2c3d4e5f6g7h8
   ```

---

## 6. Escalation & RCA Criteria

Before escalating to Cloud Networking / L4 AWS Infrastructure:
- Execute `ssm-cli get-diagnostics --output table` on the affected host and attach the output.
- Include VPC Flow Logs for the instance Primary ENI (`eni-0123456789abcdef0`) filtering destination port `443` (`REJECT` vs `ACCEPT` records).
