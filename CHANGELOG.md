# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.3] - 2026-11-21

### Fixed
- `PB-SEC-003`: Emergency firewall containment only changed the default action, so every allow rule already enabled on the host kept working. The procedure now saves the firewall state, allows the jump host, disables existing local allow rules, documents that Group Policy and Intune rules cannot be disabled locally, and includes release and outbound verification steps.
- `PB-SEC-003`: `MsSense.exe -version` was described as the MDE Client Analyzer; the playbook now uses the actual Client Analyzer (`MDEClientAnalyzer.cmd`). The SENSE log query filters by event ID, because the healthy event 4 is informational and was hidden by the error/warning filter; the undocumented event 401 was removed.
- `PB-SEC-003`: The CrowdStrike `CU` registry value is the Customer ID (CID), not the sensor version, AID or RFM state. The step now reads the CID and the installed version, and points to the Falcon console for AID and RFM.

## [1.2.2] - 2026-11-21

### Fixed
- `PB-SEC-006`: Inbox rules and mailbox forwarding are exported to JSON with a SHA256 file before any rule is removed, the unified audit log search is paginated instead of stopping at 100 results, and the access-token lifetime after session revocation (and the role of Continuous Access Evaluation) is documented.

## [1.2.1] - 2026-11-13

### Fixed
- `PB-SEC-006`: Non-interactive sign-ins are now queried through the beta endpoint (`Get-MgBetaAuditLogSignIn`); the v1.0 cmdlet returns interactive sign-ins only, so token replay was not visible.
- `PB-SEC-006`: Replaced the non-existent audit operation `Add-OAuth2PermissionGrant` with `Add delegated permission grant`, and scoped the search with `-UserIds`.
- `PB-SEC-006`: Replaced the deprecated `Get-MessageTrace` with `Get-MessageTraceV2`.
- `PB-VULN-007`: The KQL query sorted by `ExposureLevel` after projecting it away, which fails; the column is now kept.
- `PB-VULN-007`: Corrected the NIST CSF 2.0 reference from `PR.IP` (CSF 1.1) to `PR.PS`, fixed a typo, and aligned the metadata header with the other playbooks.

## [1.2.0] - 2026-11-13

### Added
- `PB-SEC-006` (`playbooks/m365-bec-aitm-phishing-and-inbox-rule-triage.md`): Field-experience incident response runbook for Business Email Compromise (BEC), Adversary-in-the-Middle (AiTM) session cookie theft, Mimecast / Defender for Office 365 phishing triage, hidden Exchange Online Inbox rules (`Get-InboxRule -IncludeHidden`), illicit OAuth grants, and Continuous Access Evaluation (CAE) session revocation (`Revoke-MgUserSignInSession`).
- `PB-VULN-007` (`playbooks/enterprise-vulnerability-management-kev-sla-triage.md`): Field-experience vulnerability management runbook covering multi-factor CVE prioritization (CVSS v3.1 + CISA KEV + EPSS + asset exposure), PowerShell host patch/UBR verification, SLA exception governance with compensating controls (ISO 27001 `A.8.8` / CIS Control 7 / NIST CSF), and executive KPI reporting (MTTR, SLA compliance, KEV burn-down).

## [1.1.1] - 2026-11-09

### Changed
- Marked `PB-CLOUD-004` and `PB-SOC-005` as self-directed lab playbooks (not production-validated) and added a `Basis` column to the catalog.
- Labeled SentinelOne queries in `PB-SOC-005` as S1QL 1.0 syntax.

### Fixed
- Replaced a public IP address in `PB-CLOUD-004` with RFC 5737 documentation range `203.0.113.0/24`.
- Replaced an invalid EC2 instance ID (non-hex characters) with a valid example ID.
- `PB-END-001`: `Get-WinEvent` now uses the BitLocker channel name `Microsoft-Windows-BitLocker/BitLocker Management` (the Event Viewer path BitLocker-API > Management is a display name), and the evidence bundle points to the correct `.evtx` file.

## [1.1.0] - 2026-10-20

### Added
- `PB-CLOUD-004` (`playbooks/aws-ssm-vpc-iam-endpoint-triage.md`): Operational runbook for diagnosing AWS Systems Manager (SSM) lost connectivity, IMDSv2 token/proxy conflicts, IAM Instance Profile permissions, and VPC Interface Endpoints.
- `PB-SOC-005` (`playbooks/sentinelone-defender-alert-triage-and-chain-of-custody.md`): SOC analyst playbook covering SentinelOne Deep Visibility (S1QL) vs. Defender XDR (KQL) alert validation, false-positive exclusion governance, legal/regulated chain-of-custody timelines, and IT Director KPI reporting templates.

## [1.0.1] - 2026-10-18

### Fixed
- **PB-END-001 (`playbooks/intune-bitlocker-escrow-remediation.md`):** Corrected inverted BitLocker Management Event IDs (`Event ID 845` = successful recovery key backup to Entra ID; `Event ID 846` = failed recovery key backup to Entra ID).
- Added explicit PowerShell commands for clearing stale `HKLM:\SOFTWARE\Policies\Microsoft\FVE` registry policies and triggering `PushLaunch` OMA-DM synchronization in Scenarios A and C.

## [1.0.0] - 2026-10-18

### Added
- `PB-END-001` (`playbooks/intune-bitlocker-escrow-remediation.md`): Operational runbook for diagnosing and remediating Microsoft Intune MDM policy synchronization failures, silent BitLocker enablement blocks, TPM 2.0 readiness issues, and Entra ID recovery key escrow gaps.
- `PB-ID-002` (`playbooks/active-directory-replication-rpc-triage.md`): Operational runbook for isolating Active Directory replication failures (`repadmin`, `dcdiag`), RPC Error `1722` (`RPC_S_SERVER_UNAVAILABLE`), DNS SRV record drift, and Entra Connect staging/synchronization bottlenecks.
- `PB-SEC-003` (`playbooks/edr-sensor-telemetry-containment-triage.md`): Operational runbook for verifying CrowdStrike Falcon and Microsoft Defender for Endpoint (MDE) sensor health, diagnosing cloud telemetry blackouts, and validating Windows Filtering Platform (WFP) host network containment.
