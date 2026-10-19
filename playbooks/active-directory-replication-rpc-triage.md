# PB-ID-002: Hybrid AD DS Replication, RPC 1722 & Entra Connect Triage

- **Document ID:** PB-ID-002
- **Version:** 1.0.0
- **Domain:** Hybrid Identity & Directory Services (Active Directory / Entra Connect)
- **Target OS:** Windows Server 2019 / 2022 Domain Controllers

---

## 1. Incident Scope & Symptoms

Password resets, group membership updates, or account lockouts on on-premises Domain Controllers (`DC01.corp.contoso.com`, `192.0.2.10`) fail to propagate across sites (`DC02.corp.contoso.com`, `198.51.100.10`) or fail to synchronize to Microsoft Entra ID via Entra Connect.

### Common Observable Indicators
- `repadmin /replsummary` reports replication failures (`Last error: 1722 (0x6ba): The RPC server is unavailable` or `8453: Replication access was denied`).
- Entra Connect Synchronization Service Manager (`miisclient.exe`) shows `stopped-connectivity` or `sync-generic-failure` on the Active Directory Connector (`corp.contoso.com`).
- Directory Service Event Log logs **Event ID 2042** (*"It has been too long since this machine replicated with the named source machine. The time between replications with this source has exceeded the tombstone lifetime"*).
- SYSVOL / Netlogon shares are inconsistent across domain controllers, causing GPO application failures on client workstations.

---

## 2. Architecture & Failure Points

Active Directory intra-site and inter-site replication depends on DNS locator records, Kerberos authentication, and dynamic RPC port allocation:

```text
[Source DC: DC01 (192.0.2.10)] ◄─── TCP 135 (RPC Endpoint Mapper) ───► [Destination DC: DC02 (198.51.100.10)]
                               ◄─── TCP 49152-65535 (Dynamic RPC) ───►
                               ◄─── TCP/UDP 53 (DNS _msdcs SRV)   ───►
                               ◄─── TCP/UDP 88 (Kerberos)         ───►
                               ◄─── TCP/UDP 389 / 636 (LDAP/LDAPS)───►
```

| Failure Code / Symptom | Underlying Subsystem | Typical Root Cause |
| :--- | :--- | :--- |
| **Error 1722 (`0x6ba`)** | RPC / Firewall / DNS | Firewall dropping dynamic RPC ports (`49152-65535`), stale CNAME record in `_msdcs.corp.contoso.com`, or `NTDS` / `RpcSs` service hung. |
| **Error 1753 (`0x6d9`)** | RPC Endpoint Mapper | Port `135` reachable, but no more endpoints available from the endpoint mapper. |
| **Error 8606 / 2042** | Lingering Objects / Tombstone | Disconnected DC exceeded Tombstone Lifetime (default 180 days); strict replication consistency blocked inbound updates. |
| **Entra Connect `no-start-ma`** | AD DS Connector Account | `MSOL_xxxxxxxxxxxx` service account password expired, locked, or missing `Replicating Directory Changes` permissions. |

---

## 3. Diagnostic Triage Procedure

Execute all diagnostic commands from an elevated PowerShell session on the affected Domain Controller or management jump host.

### Step 3.1: Assess Forest-Wide Replication Health
```powershell
repadmin /replsummary
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object { $_.'Last Failure Status' -ne '0' } |
    Select-Object 'Source DSA', 'Destination DSA', 'Naming Context', 'Last Failure Time', 'Last Failure Status', 'Number of Failures'
```

### Step 3.2: Verify DNS `_msdcs` GUID Resolution
Every Domain Controller replicates using its `DSA Object GUID` CNAME record under `_msdcs.<forest-root>`:
```powershell
# Retrieve the DSA GUID and test DNS resolution from the destination DC
$dcInfo = Get-ADDomainController -Identity "DC02.corp.contoso.com"
$dsaGuid = $dcInfo.NTDSSettingsObjectDN
dcdiag /test:DNS /s:DC02.corp.contoso.com /v
```
- Verify that `<GUID>._msdcs.corp.contoso.com` resolves to the exact current IPv4 address (`198.51.100.10`).

### Step 3.3: Validate RPC Endpoint Mapper (TCP 135) & Dynamic Ports
```powershell
Test-NetConnection -ComputerName "198.51.100.10" -Port 135
Test-NetConnection -ComputerName "198.51.100.10" -Port 389
Test-NetConnection -ComputerName "198.51.100.10" -Port 88
```
- If TCP `135` succeeds but `repadmin` still fails with `1722`, a network firewall between subnets `192.0.2.0/24` and `198.51.100.0/24` is blocking the negotiated high RPC port (`49152-65535`).

### Step 3.4: Check Time Skew (Kerberos Ticket Validity)
Kerberos authentication fails if clock drift between DCs exceeds 5 minutes:
```powershell
w32tm /monitor /domain:corp.contoso.com
```

### Step 3.5: Inspect Entra Connect Sync Scheduler & Connector Space
On the Entra Connect server (`ADCON01.corp.contoso.com`):
```powershell
Import-Module ADSync
Get-ADSyncScheduler
Get-ADSyncConnectorRunStatus
```

---

## 4. Remediation & Recovery

### Scenario A: Stale or Missing `_msdcs` DNS Records
Force registration of Dynamic DNS records and restart the Netlogon service on the affected Domain Controller:
```powershell
ipconfig /registerdns
nltest /dsregdns
Restart-Service -Name Netlogon -Force
```

### Scenario B: Firewall Blocking Ephemeral RPC Ports Across WAN/VPN
1. Restore temporary replication by restricting NTDS RPC traffic to a deterministic static port (e.g., `TCP 50001`) in registry key `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\TCP/IP Port` if required by strict WAN firewall rules, or open `TCP 49152-65535` between DC IPv4 addresses (`192.0.2.10` and `198.51.100.10`).
2. Trigger immediate KCC topology recalculation and replication sync:
```powershell
repadmin /kcc DC02.corp.contoso.com
repadmin /syncall DC02.corp.contoso.com /AdeP
```

### Scenario C: Entra Connect Stuck Delta Sync or Password Hash SyncLag
Trigger an authoritative Delta Synchronization cycle and verify Password Hash Synchronization (PHS) heartbeat:
```powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

---

## 5. Verification & Post-Incident Validation

1. **Zero Replication Errors:**
   ```powershell
   repadmin /replsummary
   ```
   Confirm `0` failures and `0` largest delta warnings across all naming contexts (`DC=corp,DC=contoso,DC=com`, `CN=Configuration`, `CN=Schema`).
2. ** Core DCDIAG Validation:**
   ```powershell
   dcdiag /s:DC02.corp.contoso.com /test:Replications /test:Advertising /test:NetLogons
   ```
3. **Entra ID Cloud Sync Timestamp:**
   Verify in **Microsoft Entra Admin Center > Hybrid management > Microsoft Entra Connect > Cloud sync / Connect Sync** that `Last Directory Sync` and `Last Password Sync` occurred within the last 30 minutes.

---

## 6. Escalation & RCA Criteria

Before escalating persistent replication divergence (such as USN rollback or lingering object lockouts):
- Never demote a Domain Controller with `-ForceRemoval` without first transferring or seizing FSMO roles (`netdom query fsmo`) and cleaning metadata.
- Attach outputs of `repadmin /showrepl * /verbose`, `dcdiag /v /c /d /e`, and exported `Directory Service` event logs.
