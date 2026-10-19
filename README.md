# SecOps-Field-Playbooks

Enterprise L3 operational runbooks and root-cause analysis (RCA) playbooks for Incident Response, Microsoft Intune, Hybrid Active Directory, and Endpoint Detection & Response (EDR).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/SecOps-Field-Playbooks?color=success)](https://github.com/Santiago-Agudelo-R/SecOps-Field-Playbooks/releases)
[![Scope: Enterprise SecOps](https://img.shields.io/badge/Scope-Enterprise_SecOps_%26_Infra-0078D4.svg)](https://github.com/Santiago-Agudelo-R/SecOps-Field-Playbooks)

---

## Overview

During high-severity infrastructure incidents or security operations escalations, engineers require deterministic, repeatable diagnostic procedures rather than ad-hoc troubleshooting. `SecOps-Field-Playbooks` contains production-tested L3 operational runbooks covering endpoint encryption compliance, hybrid directory synchronization, and EDR containment verification across distributed enterprise environments.

All hostnames, IPv4 addresses, tenant identifiers, and domain names strictly follow RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) and RFC 2606 (`contoso.com`, `corp.contoso.com`) anonymization standards.

---

## Playbook Catalog

| Playbook ID | Title | Primary Domain | Target Technologies |
| :--- | :--- | :--- | :--- |
| [**PB-END-001**](playbooks/intune-bitlocker-escrow-remediation.md) | Intune MDM Sync & BitLocker Key Escrow Remediation | Endpoint Security & Compliance | Microsoft Intune, Entra ID, BitLocker, TPM 2.0, Windows Event Logs |
| [**PB-ID-002**](playbooks/active-directory-replication-rpc-triage.md) | Hybrid AD DS Replication, RPC 1722 & Entra Connect Triage | Hybrid Identity & Directory Services | Windows Server AD DS, `repadmin`, `dcdiag`, DNS, Entra Connect |
| [**PB-SEC-003**](playbooks/edr-sensor-telemetry-containment-triage.md) | EDR Sensor Health, Telemetry Loss & Network Containment Validation | Security Operations & Incident Response | Microsoft Defender for Endpoint (MDE), CrowdStrike Falcon, WFP |

---

## Structure of Each Playbook

Every playbook in this repository follows a standardized six-stage engineering format:

1. **Incident Scope & Symptoms:** Observable alerts, compliance failures, and exact error codes (`0x80180014`, `0x87d1fde8`, RPC `1722`, Event IDs).
2. **Architecture & Failure Points:** Underlying system components, communication ports, registry keys, and policy evaluation paths.
3. **Diagnostic Triage Procedure:** Step-by-step non-destructive verification commands (PowerShell, CLI, Event Viewer channels) to isolate the root cause.
4. **Remediation & Recovery:** Deterministic fix actions for local hosts and mass deployment (Intune Proactive Remediations / GPO / RTR).
5. **Verification & Post-Incident Validation:** Positive confirmation checks ensuring telemetry, compliance state, or replication convergence is restored.
6. **Escalation & RCA Criteria:** Evidence collection requirements before escalating to vendor support or L4 architecture teams.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
