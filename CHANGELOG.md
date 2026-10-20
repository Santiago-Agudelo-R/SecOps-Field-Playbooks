# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
