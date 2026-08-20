# Security Engineering Portfolio

Detection engineering, threat hunting, and identity/cloud security work — built primarily on Microsoft Defender XDR, Sentinel, Entra ID, and Azure.

I focus on closing the loop between threat intelligence, hunting, and detection engineering: using intel and hunt findings to drive new detections, and using detection telemetry to inform the next hunt.

## Case Studies

Investigation write-ups from real detection and IR work.

| Title | Focus | ATT&CK Mapping |
|---|---|---|
| [Quishing Detection: Nested QR-Code Phishing](case-studies/quishing-detection-nested-eml-pdf.md) | Detection engineering | T1566 |
| [BEC Investigation: Malicious Inbox Rules](case-studies/bec-inbox-rule-root-cause.md) | Incident response | T1114.003 |

## Frameworks

Reference guides and governance templates for security architecture and risk decisions.

| Title | Focus |
|---|---|
| [AI TRiSM Implementation Guide](frameworks/ai-trism-implementation-guide.md) | Mapping Gartner AI TRiSM to Microsoft Defender/Purview |
| [STRIDE+MAESTRO Threat Model Template](frameworks/stride-maestro-threat-model-template.md) | Threat modeling for agentic AI systems on Azure AI Foundry |
| [Workload Identity Risk Tiering & Control Mapping](frameworks/workload-identity-risk-tiering-and-controls.md) | Critical/High app classification, Workload ID CA vs. MDCA scoping |

## Tools & Projects

Standalone, cloneable projects — linked here, maintained in their own repos.

| Project | Description |
|---|---|
| [pan_rule_validator](https://github.com/wendyrojas7-cyber/pan_rule_validator) | PAN-OS Panorama rule validation: XML API collection → deterministic analysis → (Phase 2) AI narrative layer |

## Core Skills

- **Detection Engineering:** KQL custom detection rules, Advanced Hunting, MITRE ATT&CK-aligned rule design
- **Threat Hunting & Intel:** hypothesis-driven hunting, IOC pipeline management, CVE-driven detection prioritization
- **Identity & Cloud Security:** Entra ID Conditional Access, PIM/PIM for Groups, Managed Identities, least-privilege architecture
- **Governance:** Microsoft Purview role design, Defender for Cloud Apps, AI/agent governance (Copilot Studio)
- **AI Threat Modeling & Risk Management:** STRIDE + MAESTRO agentic AI threat modeling, Gartner AI TRiSM implementation, MITRE ATLAS-mapped detection engineering
- **Tooling:** Microsoft Defender XDR, Sentinel, Rapid7 InsightIDR/InsightConnect, Nessus, Azure AI Foundry

## Note on content

Case studies describe real detection engineering work. Organization names, exact IOCs, hashes, domains, and other identifying details have been generalized or omitted; the technical methodology and reasoning are accurate.
