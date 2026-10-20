# PB-SOC-005: SentinelOne & Defender XDR Alert Triage, Chain-of-Custody & Executive Reporting

- **Document ID:** PB-SOC-005
- **Version:** 1.1.0
- **Domain:** SOC Operations, MSSP Co-Management & Legal/Regulated Chain of Custody
- **Platforms:** SentinelOne Singularity XDR, Microsoft Defender XDR, Microsoft Sentinel, Microsoft 365

---

## 1. Incident Scope & Operational Context

In regulated industries (Legal Practices, Financial Services, Healthcare), SOC analysts operating in co-managed MSSP environments must:
1. Validate escalations across **SentinelOne** and **Microsoft Defender XDR** to separate true positives (TP) from benign administrative activity (FP).
2. Enforce strict **Chain-of-Custody** and confidentiality controls when acquiring volatile evidence from custodian endpoints (attorneys, executives, finance).
3. Eliminate recurring alert fatigue through deterministic **Detection Tuning & Exclusion Governance** without introducing blind spots.
4. Deliver decision-ready **Weekly/Monthly Executive Security Reports** to the IT Director tracking MTTD, MTTR, incident scope, and control gaps.

---

## 2. Cross-EDR Triage Equivalence: SentinelOne (S1QL) vs. Microsoft Defender (KQL)

### 2.1 Hunting Encoded PowerShell & Suspicious Child Processes (`T1059.001`)

**SentinelOne Deep Visibility (S1QL v2.0):**
```sql
EventType = "Process Creation"
AND SrcProcName In Contains Anycase ("winword.exe", "excel.exe", "outlook.exe", "wmiprvse.exe")
AND TgtProcName In Contains Anycase ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe")
AND TgtProcCmdLine In Contains Anycase ("-enc", "-nop", "hidden", "downloadstring", "frombase64string", "http://", "https://")
```

**Microsoft Defender XDR / Sentinel (KQL):**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "wmiprvse.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("-enc", "-nop", "hidden", "downloadstring", "frombase64string", "http://", "https://")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

### 2.2 Hunting Credential Dumping & LSASS Memory Access (`T1003.001`)

**SentinelOne Deep Visibility (S1QL v2.0):**
```sql
(EventType = "Process Creation" AND TgtProcCmdLine Contains Anycase ("comsvcs.dll", "MiniDump", "sekurlsa", "procdump"))
OR (EventType = "Cross Process" AND TgtProcName = "lsass.exe" AND SrcProcSignedStatus != "signed")
```

**Microsoft Defender XDR / Sentinel (KQL):**
```kql
DeviceEvents
| where ActionType in ("OpenProcessApiCall", "CreateRemoteThreadApiCall")
| where FileName =~ "lsass.exe"
| where InitiatingProcessSignerType != "Windows"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 3. True Positive vs. False Positive Validation Workflow

When an alert is escalated by the MSSP or triggered in the EDR console, complete the **5-Point Validation Matrix** within 15 minutes (SLA P1/P2):

| Validation Step | Verification Question | Technical Verification Method |
| :--- | :--- | :--- |
| **1. Process Lineage** | Is the parent-child relationship expected? | Inspect process tree (`svchost.exe` must descend from `services.exe`; Office apps spawning `cmd`/`powershell`/`wscript` = high risk). |
| **2. Binary Integrity** | Is the binary signed and running from a standard directory? | Verify `SHA256` reputation, Authenticode signature, and path (`\AppData\`, `\Users\Public\`, `\Temp\` = anomalous). |
| **3. Identity Context** | Did the user perform an interactive login or was the token stolen? | Correlate with Entra ID `SigninLogs` (Conditional Access status, ASN/Geo, MFA method, Device Compliance state). |
| **4. Network Egress** | Did the process initiate outbound C2 or exfiltration traffic? | Inspect outbound connections to non-RFC1918 IPs, uncategorized domains, or cloud storage (`mega.nz`, personal OneDrive/Dropbox). |
| **5. Persistence** | Did the process create a Registry Run key, Scheduled Task, or Service? | Run [`IR-Triage-Collector`](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector) (`Invoke-IRTriage.ps1 -HashBinaries`) via SentinelOne Remote Shell or Defender Live Response. |

---

## 4. Defensible Incident Timeline & Chain-of-Custody Standard

In legal and financial environments, every true-positive incident ticket must include a **UTC-normalized Incident Timeline** and **Chain-of-Custody Record** before closure:

### 4.1 Incident Timeline Template (Ticket Closure Notes)
```markdown
### Incident Summary & Scope
- **Ticket / Alert ID:** INC-2026-1042 (SentinelOne Threat ID: 194827104)
- **Classification:** True Positive - Phishing Macro Execution Attempt (Blocked)
- **Affected Asset(s):** WKSTN-LEGAL-08.corp.contoso.com (192.0.2.88)
- **Affected Identity:** m.counsel@contoso.com (Legal Practice Group)
- **Data Exfiltration / Lateral Movement:** None detected (0 bytes transferred; child process terminated by EDR behavioral engine).

### Chronological Timeline (All Timestamps Strictly ISO 8601 UTC)
- **2026-10-18T14:02:11Z [Initial Access]:** User opened attachment `Subpoena_Amend_04.docm` delivered via external sender `records@external-counsel-example.com`.
- **2026-10-18T14:02:14Z [Execution & Detection]:** `WINWORD.EXE` (PID 6120) spawned `powershell.exe -NoP -W Hidden -Enc ...` (PID 8844). SentinelOne Behavioral AI triggered policy action `Kill & Quarantine`.
- **2026-10-18T14:06:00Z [MSSP Escalation]:** Alert escalated to internal SOC queue as Priority 2.
- **2026-10-18T14:09:30Z [Containment]:** Host `WKSTN-LEGAL-08` placed in Network Containment via EDR console; Entra ID user session revoked (`Revoke-MgUserSignInSession`).
- **2026-10-18T14:15:12Z [Forensic Triage]:** Executed `Invoke-IRTriage.ps1 -HashBinaries`. Verified zero persistence in Registry Run keys, Scheduled Tasks, or Services.
  - **Evidence Artifact:** `Triage_WKSTN-LEGAL-08_20261018_141512.json`
  - **SHA256 Integrity Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **2026-10-18T14:32:00Z [Eradication & Recovery]:** Purged sender email across tenant via Exchange Online Content Search; released host network containment after confirming clean state.
```

---

## 5. Alert Noise Reduction & Exclusion Governance

Never create broad path-only exclusions (such as `C:\Program Files\*` or `C:\Temp\*`). When tuning recurring benign alerts from internal line-of-business (LOB) or RMM tools:
1. **Preferred Control:** Exclude by **Certificate Signer + File Hash (`SHA256`) + Initiating Parent Process**.
2. **Compensating Control:** Document the business justification, approving manager, and a 90-day expiration review date in the SOC Exclusion Register.

---

## 6. IT Director Weekly / Monthly Executive Report Template

```markdown
## Executive Security Operations Summary — Period: YYYY-MM-DD to YYYY-MM-DD

### 1. Key Performance Indicators (KPIs)
| Metric | Current Period | Previous Period | Target SLA |
| :--- | :--- | :--- | :--- |
| **Total Alerts Ingested (EDR + M365 + SIEM)** | 148 | 172 | — |
| **Confirmed True Positives (Security Incidents)** | 2 | 3 | — |
| **Benign True Positives (Authorized Admin Activity)** | 19 | 28 | — |
| **False Positives (Tuned / Suppressed)** | 127 | 141 | < 15% MoM |
| **Mean Time to Acknowledge / Validate (MTTA)** | 8 min | 11 min | < 15 min |
| **Mean Time to Contain (MTTC - High Severity)** | 14 min | 19 min | < 30 min |

### 2. Control Gaps Identified & Remediation Actions
1. **Control Gap:** 14 legacy guest accounts in SharePoint Online exceeded 90 days of inactivity.
   - **Action Taken:** Executed `Invoke-M365EntraAudit.ps1` and disabled stale external guests; enforced 60-day Entra Access Review policy.
2. **Control Gap:** 3 workstations reported suspended BitLocker protection following BIOS updates.
   - **Action Taken:** Deployed Intune Proactive Remediation (`Detect-BitLockerEscrow.ps1` / `Remediate-BitLockerEscrow.ps1`) restoring 100% encryption compliance.
```
