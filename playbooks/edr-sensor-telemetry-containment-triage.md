# PB-SEC-003: EDR Sensor Health, Telemetry Loss & Network Containment Validation

- **Document ID:** PB-SEC-003
- **Version:** 1.2.1
- **Domain:** Security Operations & Incident Response (MDE / CrowdStrike Falcon)
- **Target OS:** Windows 10 / 11 Enterprise & Windows Server 2016+

---

## 1. Incident Scope & Symptoms

During active incident response or routine SOC posture monitoring, two critical operational scenarios require immediate intervention:
1. **Sensor Telemetry Loss (Silent Host):** An endpoint stops reporting process/network telemetry to Microsoft Defender for Endpoint (MDE) or CrowdStrike Falcon for >24 hours while remaining active on the corporate network (`192.0.2.0/24`), creating a blind spot or indicating defense evasion (`T1562.001`).
2. **Containment Verification Failure:** A compromised host (`WKSTN-MKT-12.corp.contoso.com`, `192.0.2.45`) is placed into **Network Containment / Device Isolation** in the EDR console, but the SOC requires verification that lateral SMB/RDP/WinRM traffic is strictly blocked at the Windows Filtering Platform (WFP) layer while preserving EDR cloud heartbeat channels.

---

## 2. Architecture & Failure Points

```text
[Kernel Drivers: CSAgent.sys / WdFilter.sys]
                     │
                     ▼
[User-Mode Services: CSFalconService / Sense]
                     │
                     ▼
[Windows Filtering Platform (WFP) Callout Drivers]
                     │
                     ▼
[TLS 1.2/1.3 Egress (TCP 443) ──► EDR Cloud Endpoints]
```

| Platform | Kernel Driver | Service Name | Common Failure / Tampering Vector |
| :--- | :--- | :--- | :--- |
| **Microsoft Defender for Endpoint** | `WdFilter.sys`, `MsSecFlt.sys` | `Sense`, `WinDefend` | SSL inspection breaking certificate pinning to `*.atp.azure.com`, corrupted `Cyber` telemetry queue, or Tamper Protection bypass attempt. |
| **CrowdStrike Falcon** | `csagent.sys` | `CSFalconService` | Missing DigiCert root CA certificates, proxy authentication (`407`) blocking `ts01-b.cloudsink.net`, or reduced functionality mode (RFM). |

---

## 3. Diagnostic Triage Procedure

### Step 3.1: Verify EDR Service & Kernel Driver State
Run via WinRM, Intune remediation, or local administrative PowerShell:
```powershell
# Check both MDE (Sense / WinDefend) and CrowdStrike Falcon (CSFalconService)
Get-Service -Name Sense, WinDefend, CSFalconService -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, Status, StartType

# Verify kernel minifilter drivers are loaded and attached
fltmc filters | Select-String -Pattern "WdFilter|csagent|MsSecFlt"
```

### Step 3.2: Audit Microsoft Defender for Endpoint (MDE) Onboarding & Cloud Connectivity
```powershell
# Check MDE onboarding registry state (OnboardingState 1 = onboarded; OrgId must be populated)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue |
    Select-Object OnboardingState, OrgId, LastConnected
```
Test connectivity to the Defender for Endpoint service URLs with the **MDE Client Analyzer**, a separate download from Microsoft ([aka.ms/mdeanalyzer](https://aka.ms/mdeanalyzer)); it can also be collected through Live Response:
```cmd
C:\Tools\MDEClientAnalyzer\MDEClientAnalyzer.cmd
```
Review `MDEClientAnalyzerResult.txt` for failed service URLs and proxy discovery problems.

Inspect the `SENSE` Operational log for connection events. Event 4 is informational, so filter by ID rather than by level:
```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-SENSE/Operational'; Id = 4, 5 } -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message
```
- **Event ID 4:** The service contacted the Defender for Endpoint server (healthy).
- **Event ID 5:** The service failed to connect to the server; check proxy, firewall and TLS inspection for the URL named in the message.

### Step 3.3: Audit CrowdStrike Falcon Sensor Health & RFM State
```powershell
# Driver service state (the kernel component of the Falcon sensor)
sc.exe query csagent

# Customer ID (CID) the sensor was installed with: confirms the host reports to the right tenant
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim" /v CU

# Installed sensor version, to compare with the sensor update policy
(Get-Item "$env:ProgramFiles\CrowdStrike\CSFalconService.exe").VersionInfo.ProductVersion
```
- Agent ID (AID), Reduced Functionality Mode (RFM) state and last-seen time are confirmed in the Falcon console (**Host management**), not from a local registry value.
- Verify outbound TLS connectivity on TCP `443` to the cloud sink endpoints without SSL decryption:
```powershell
Test-NetConnection -ComputerName "ts01-b.cloudsink.net" -Port 443
```

### Step 3.4: Validate Host Network Containment (WFP Filter Audit)
When a host is isolated in MDE or CrowdStrike Falcon, the sensor injects dynamic block rules into the **Windows Filtering Platform (WFP)** so only EDR cloud broker IPs (and optionally DNS/DHCP) are permitted:
```powershell
# Export current WFP filters to XML and confirm active isolation filters
$wfpOut = "$env:TEMP\wfp_filters.xml"
netsh wfp show filters file="$wfpOut" | Out-Null
Select-String -Path $wfpOut -Pattern "CrowdStrike|Sense|Defender" | Select-Object -First 20
Remove-Item -LiteralPath $wfpOut -Force
```

---

## 4. Remediation & Recovery

### Scenario A: SSL/TLS Inspection Blocking EDR Cloud Telemetry
EDR sensors enforce strict certificate pinning. If a corporate firewall or secure web gateway (SWG) intercepts TLS traffic from `MsSense.exe` or `CSFalconService.exe`, the sensor drops the connection immediately.
1. Add SSL inspection bypass exclusions for official Microsoft MDE (`*.atp.azure.com`, `*.events.data.microsoft.com`) and CrowdStrike domains (`*.cloudsink.net`).
2. Restart the MDE telemetry service (`Sense` is protected by PPL; trigger re-registration via `MpCmdRun`):
```powershell
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ValidateMapsConnection
```

### Scenario B: Sensor in Reduced Functionality Mode (RFM) After OS Kernel Patch
1. Identify the exact Windows build (`[System.Environment]::OSVersion.Version`) on the affected host.
2. Push the certified N-1 or N sensor build update policy from the Falcon / Intune console.

### Scenario C: Emergency Local Host Isolation (When EDR Cloud Channel is Unreachable)
If an active compromise is detected on `192.0.2.45` and the host cannot receive cloud containment commands, enforce Windows Firewall containment via Live Response or WinRM while keeping the management jump host (`192.0.2.100`) reachable.

Changing only the default action is **not** containment: every allow rule that is already enabled keeps working (Windows ships many, and software adds more). Save the current state, disable the existing allow rules, then allow only the jump host:
```powershell
$irDir = Join-Path $env:ProgramData 'SecOps\IR'
New-Item -ItemType Directory -Path $irDir -Force | Out-Null

# 1. Record the current state so containment can be reversed exactly
Get-NetFirewallProfile | Export-Clixml (Join-Path $irDir 'fw-profiles.xml')
$enabledAllow = Get-NetFirewallRule -Enabled True -Action Allow -PolicyStore ActiveStore
$enabledAllow | Select-Object Name, DisplayName, Direction, PolicyStoreSource | Export-Csv (Join-Path $irDir 'fw-allow-rules-disabled.csv') -NoTypeInformation

# 2. Allow only the management jump host (created first so the session survives)
New-NetFirewallRule -DisplayName 'IR-Emergency-Allow-JumpHost-In' -Direction Inbound -RemoteAddress 192.0.2.100 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName 'IR-Emergency-Allow-JumpHost-Out' -Direction Outbound -RemoteAddress 192.0.2.100 -Action Allow | Out-Null

# 3. Disable every pre-existing local allow rule and block by default in all profiles
Get-NetFirewallRule -Enabled True -Action Allow -PolicyStore PersistentStore |
    Where-Object { $_.DisplayName -notlike 'IR-Emergency-*' } | Disable-NetFirewallRule
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
```
- Allow rules delivered by Group Policy or Intune (`PolicyStoreSource` other than `PersistentStore` in the CSV) cannot be disabled locally and stay active. Review the CSV; if any remain, contain at the switch/VLAN or with the EDR once it is reachable.
- **Release:** re-enable the rules listed in `fw-allow-rules-disabled.csv` (`Enable-NetFirewallRule -Name <Name>`), restore the profile defaults from `fw-profiles.xml`, and remove the two `IR-Emergency-*` rules.

---

## 5. Verification & Post-Incident Validation

1. **Containment Effectiveness Check:**
   From a peer workstation on `192.0.2.0/24`, confirm SMB (`445`), RDP (`3389`), and WinRM (`5985`) connections to the isolated host (`192.0.2.45`) time out:
   ```powershell
   Test-NetConnection -ComputerName 192.0.2.45 -Port 445
   ```
   From the contained host itself, confirm outbound traffic is blocked while the jump host still answers:
   ```powershell
   Test-NetConnection -ComputerName 198.51.100.24 -Port 443   # expected: TcpTestSucceeded False
   Test-NetConnection -ComputerName 192.0.2.100 -Port 5985    # expected: TcpTestSucceeded True
   ```
2. **Volatile Forensic Collection:**
   While the host is contained, execute [`IR-Triage-Collector`](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector) (`Invoke-IRTriage.ps1 -HashBinaries`) over the active RTR / Live Response session and verify the `.sha256` sidecar hash before releasing containment.

---

## 6. Escalation & RCA Criteria

- If `Sense` or `CSFalconService` is stopped and Tamper Protection was disabled prior to the outage, treat the host as a **High-Severity Defense Evasion Incident (`T1562.001`)**, isolate at the network switch/VLAN layer, and preserve full memory and event log evidence.
