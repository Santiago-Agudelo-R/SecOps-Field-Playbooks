# SecOps-Field-Playbooks

Operational runbooks and root-cause analysis (RCA) playbooks for Incident Response, Vulnerability Management, Microsoft 365 / Entra ID, Microsoft Intune, Hybrid Active Directory, and Endpoint Detection & Response (EDR).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/SecOps-Field-Playbooks?color=success)](https://github.com/Santiago-Agudelo-R/SecOps-Field-Playbooks/releases)
[![Scope: Enterprise SecOps](https://img.shields.io/badge/Scope-Enterprise_SecOps_%26_Infra-0078D4.svg)](https://github.com/Santiago-Agudelo-R/SecOps-Field-Playbooks)

---

## Overview

During infrastructure incidents or security operations escalations, engineers require deterministic, repeatable diagnostic procedures rather than ad-hoc troubleshooting. `SecOps-Field-Playbooks` contains operational runbooks covering endpoint encryption compliance, hybrid directory synchronization, EDR containment verification, Business Email Compromise (BEC) / AiTM session containment, and risk-based vulnerability management across distributed enterprise environments.

All hostnames, IPv4 addresses, tenant identifiers, and domain names strictly follow RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 1918 private ranges, and RFC 2606 (`contoso.com`, `corp.contoso.com`) anonymization standards.

---

## Playbook Catalog

| Playbook ID | Title | Primary Domain | Target Technologies | Basis |
| :--- | :--- | :--- | :--- | :--- |
| [**PB-END-001**](playbooks/intune-bitlocker-escrow-remediation.md) | Intune MDM Sync & BitLocker Key Escrow Remediation | Endpoint Security & Compliance | Microsoft Intune, Entra ID, BitLocker, TPM 2.0, Windows Event Logs | Field experience |
| [**PB-ID-002**](playbooks/active-directory-replication-rpc-triage.md) | Hybrid AD DS Replication, RPC 1722 & Entra Connect Triage | Hybrid Identity & Directory Services | Windows Server AD DS, `repadmin`, `dcdiag`, DNS, Entra Connect | Field experience |
| [**PB-SEC-003**](playbooks/edr-sensor-telemetry-containment-triage.md) | EDR Sensor Health, Telemetry Loss & Network Containment Validation | Security Operations & Incident Response | Microsoft Defender for Endpoint (MDE), CrowdStrike Falcon, WFP | Field experience |
| [**PB-CLOUD-004**](playbooks/aws-ssm-vpc-iam-endpoint-triage.md) | AWS Systems Manager (SSM), VPC Endpoints & IAM Instance Profile Triage | Cloud Infrastructure & SecOps | AWS EC2, Systems Manager, VPC Endpoints, IAM, IMDSv2 | Self-directed lab |
| [**PB-SOC-005**](playbooks/sentinelone-defender-alert-triage-and-chain-of-custody.md) | SentinelOne & Defender XDR Alert Triage, Chain-of-Custody & Executive Reporting | SOC Operations & MSSP Co-Management | SentinelOne (S1QL), Microsoft Defender XDR (KQL), M365 | Self-directed lab |
| [**PB-SEC-006**](playbooks/m365-bec-aitm-phishing-and-inbox-rule-triage.md) | Business Email Compromise (BEC), AiTM Session Hijack & Inbox Rule Triage | Identity & Email Incident Response | Microsoft Entra ID, Exchange Online, Defender for Office 365, Mimecast, PowerShell | Self-directed lab |
| [**PB-VULN-007**](playbooks/enterprise-vulnerability-management-kev-sla-triage.md) | Enterprise Vulnerability Management Lifecycle, CISA KEV Prioritization, SLA Exceptions & Remediation Verification | Vulnerability Management & Compliance | Defender Vulnerability Management (MDVM), Intune, WUfB, PowerShell, CIS/NIST CSF | Self-directed lab |

---

**Basis:** *Field experience* playbooks come from day-to-day work in enterprise environments. *Self-directed lab* playbooks come from personal lab work and vendor documentation, and are marked as not yet production-validated.

---

## Structure of Each Playbook

Every playbook in this repository follows a standardized six-stage engineering format:

1. **Incident Scope & Symptoms:** Observable alerts, compliance failures, and exact error codes (`0x80180014`, `0x87d1fde8`, RPC `1722`, Event IDs).
2. **Architecture & Failure Points:** Underlying system components, communication ports, registry keys, and policy evaluation paths.
3. **Diagnostic Triage Procedure:** Step-by-step non-destructive verification commands (PowerShell, KQL, CLI, Event Viewer channels) to isolate the root cause.
4. **Remediation & Recovery:** Deterministic fix actions for local hosts, cloud tenants, and mass deployment (Intune Proactive Remediations / GPO / RTR).
5. **Verification & Post-Incident Validation:** Positive confirmation checks ensuring telemetry, compliance state, or replication convergence is restored.
6. **Escalation, Governance & KPI Criteria:** Evidence collection requirements, SLA exception governance, and executive reporting metrics.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
