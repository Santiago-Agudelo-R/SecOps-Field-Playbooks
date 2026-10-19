# PB-END-001: Intune MDM Sync & BitLocker Key Escrow Remediation

- **Document ID:** PB-END-001
- **Version:** 1.0.0
- **Domain:** Endpoint Security & Compliance (Microsoft Intune / Entra ID)
- **Target OS:** Windows 10 / Windows 11 Enterprise

---

## 1. Incident Scope & Symptoms

Enterprise endpoints managed via Microsoft Intune (Cloud Native or Hybrid Entra Joined) are flagged as **NonCompliant** in the Intune compliance dashboard and blocked by Conditional Access policies requiring a compliant device.

### Common Observable Indicators
- Intune Compliance reason: `Require device encryption: Not compliant` or `BitLockerNotActive`.
- Volume `C:` is either unencrypted, stuck in `Encryption In Progress`, or encrypted locally without a recovery password escrowed to Microsoft Entra ID.
- Windows Event Viewer (`Microsoft-Windows-BitLocker-API/Management`) logs:
  - **Event ID 851:** Failed to enable Silent Encryption (Group Policy / MDM conflict or incompatible DMA/PCR7 state).
  - **Event ID 845:** Recovery key backup to Entra ID failed (network/TLS proxy block or stale Primary Refresh Token).
- Device Management logs (`Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin`) show OMA-DM sync failures (`0x87d1fde8` or `0x80190190`).

---

## 2. Architecture & Failure Points

Silent BitLocker deployment via Intune relies on four sequential layers:

```text
[TPM 2.0 & UEFI Secure Boot]
             │
             ▼
[OMA-DM BitLocker CSP (/Vendor/MSFT/BitLocker)]
             │
             ▼
[Entra ID Device Registration + PRT Token]
             │
             ▼
[Key Escrow to Entra ID + Intune Compliance Evaluation]
```

| Layer | Component | Typical Root Cause |
| :--- | :--- | :--- |
| **Hardware / Firmware** | TPM 2.0 + PCR7 / Secure Boot | TPM not ready, CSM/Legacy BIOS active, or unallowed DMA devices blocking PCR7 binding. |
| **Policy Conflict** | Registry `HKLM\SOFTWARE\Policies\Microsoft\FVE` | Legacy GPO settings (`UseAdvancedStartup`) conflicting with Intune silent enablement (`RequireDeviceEncryption`). |
| **Identity / PRT** | `dsregcmd /status` | Broken Entra join state (`AzureAdJoined: NO` or `AzureAdPrt: NO`) preventing key backup to Graph endpoint. |
| **Encryption State** | `manage-bde` / `Get-BitLockerVolume` | Drive encrypted manually before enrollment without `RecoveryPassword` protector or with `ProtectionStatus: Off` (suspended). |

---

## 3. Diagnostic Triage Procedure

Execute the following checks in an elevated PowerShell session (or via Intune Device Query / EDR Live Response) on the affected workstation (e.g., `WKSTN-FIN-04.corp.contoso.com`).

### Step 3.1: Verify Hybrid / Entra ID Join & Primary Refresh Token (PRT)
```powershell
dsregcmd /status
```
- Confirm `AzureAdJoined : YES` (or `DomainJoined : YES` for Hybrid).
- Confirm `AzureAdPrt : YES` under SSO State. If `NO`, the device cannot authenticate to escrow the recovery key to Entra ID.

### Step 3.2: Inspect TPM 2.0 Readiness
```powershell
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, LockedOut
```
- All four readiness flags (`TpmPresent`, `TpmReady`, `TpmEnabled`, `TpmActivated`) must evaluate to `True`.

### Step 3.3: Audit Current BitLocker Volume & Key Protectors
```powershell
$vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
$vol | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod
$vol.KeyProtector | Select-Object KeyProtectorId, KeyProtectorType
```
- Check if `ProtectionStatus` is `Off` while `VolumeStatus` is `FullyEncrypted` (indicates suspended protection after BIOS/firmware update).
- Verify that a `RecoveryPassword` (48-digit numerical password) and `Tpm` protector exist in `$vol.KeyProtector`.

### Step 3.4: Inspect BitLocker & MDM Event Logs for Root Cause
```powershell
# Query last 15 BitLocker Management errors/warnings
Get-WinEvent -LogName "Microsoft-Windows-BitLocker-API/Management" -MaxEvents 15 |
    Where-Object { $_.LevelDisplayName -in @('Error', 'Warning') } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message

# Query last 15 Intune MDM policy errors
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 15 |
    Where-Object { $_.LevelDisplayName -eq 'Error' } |
    Select-Object TimeCreated, Id, Message
```

### Step 3.5: Check for Conflicting Legacy GPO Registry Keys
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
```
- If `UseAdvancedStartup = 1` and `EnableBDEWithNoTPM = 1` are enforced by an on-premises GPO requiring a startup PIN, Intune silent encryption (`AllowWarningForOtherDiskEncryption = 0`) will fail with Event ID `851`.

---

## 4. Remediation & Recovery

### Scenario A: Protection Suspended (`FullyEncrypted` + `ProtectionStatus: Off`)
Resume protection immediately and trigger an Intune sync:
```powershell
Resume-BitLocker -MountPoint $env:SystemDrive
```

### Scenario B: Drive Encrypted Locally, Missing `RecoveryPassword` or Not Escrowed to Entra ID
Deploy the following remediation script (locally or via **Intune Proactive Remediations** running as `SYSTEM`):

```powershell
# Ensure RecoveryPassword protector exists and escrow to Entra ID
$ErrorActionPreference = 'Stop'
$mount = $env:SystemDrive
$blv = Get-BitLockerVolume -MountPoint $mount

$recProtector = $blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
if (-not $recProtector) {
    $null = Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPasswordProtector
    $blv = Get-BitLockerVolume -MountPoint $mount
    $recProtector = $blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
}

BackupToAAD-BitLockerKeyProtector -MountPoint $mount -KeyProtectorId $recProtector.KeyProtectorId
```

### Scenario C: Conflicting Legacy GPO Blocking Silent Encryption
1. Remove the endpoint from the legacy on-premises BitLocker GPO scope (or configure `MDMWinsOverGP` via the Policy CSP `/Vendor/MSFT/Policy/Config/ControlPolicyConflict/MDMWinsOverGP = 1`).
2. Clear stale FVE policy values and force an OMA-DM sync:
```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask
```

---

## 5. Verification & Post-Incident Validation

1. **Local Event Confirmation:**
   Verify Event ID **846** (*"The BitLocker volume recovery information for volume C: was backed up successfully to your Microsoft Entra ID"*) in `Microsoft-Windows-BitLocker-API/Management`:
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName = 'Microsoft-Windows-BitLocker-API/Management'
       Id      = 846
   } -MaxEvents 1
   ```
2. **Entra ID & Intune Portal Confirmation:**
   - Navigate to **Microsoft Intune Admin Center > Devices > All devices > [Device Name] > Recovery keys** and confirm the `Key ID` matches `$recProtector.KeyProtectorId`.
   - Confirm device compliance state transitions from `NonCompliant` to `Compliant` after the next IME/OMA-DM check-in cycle.

---

## 6. Escalation & RCA Criteria

If remediation fails, collect the following diagnostic bundle before escalating to L4 Endpoint Engineering:
- Exported MDM Diagnostic Report: `MdmDiagnosticsTool.exe -area "DeviceEnrollment;DeviceProvisioning;TPM" -zip C:\Temp\MDMDiag.zip`
- Output of `dsregcmd /status` and `Get-Tpm`
- Export of `Microsoft-Windows-BitLocker-API/Management.evtx`
