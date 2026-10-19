# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-18

### Added
- `PB-END-001` (`playbooks/intune-bitlocker-escrow-remediation.md`): L3 operational runbook for diagnosing and remediating Microsoft Intune MDM policy synchronization failures, silent BitLocker enablement blocks, TPM 2.0 readiness issues, and Entra ID recovery key escrow gaps.
- `PB-ID-002` (`playbooks/active-directory-replication-rpc-triage.md`): L3 operational runbook for isolating Active Directory replication failures (`repadmin`, `dcdiag`), RPC Error `1722` (`RPC_S_SERVER_UNAVAILABLE`), DNS SRV record drift, and Entra Connect staging/synchronization bottlenecks.
- `PB-SEC-003` (`playbooks/edr-sensor-telemetry-containment-triage.md`): L3 operational runbook for verifying CrowdStrike Falcon and Microsoft Defender for Endpoint (MDE) sensor health, diagnosing cloud telemetry blackouts, and validating Windows Filtering Platform (WFP) host network containment.
