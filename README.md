# Security Engineering Portfolio

Detection engineering, threat hunting, and identity/cloud security work — built primarily on Microsoft Defender XDR, Sentinel, Entra ID, and Azure.

I focus on closing the loop between threat intelligence, hunting, and detection engineering: using intel and hunt findings to drive new detections, and using detection telemetry to inform the next hunt.

## Case Studies

| Case Study | Focus | ATT&CK |
|---|---|---|
| [Detecting a Nested QR-Code Phishing Campaign](case-studies/quishing-detection-nested-eml-pdf.md) | Custom Defender XDR detection for a nested `.eml`/PDF quishing evasion technique that bypassed native QR scanning | T1566.001 |
| [Business Email Compromise: Inbox Rule Discovery to Reusable Root-Cause Tooling](case-studies/bec-inbox-rule-root-cause.md) | Five-vector BEC root-cause investigation, plus a reusable investigation notebook and Sentinel workbook built from it | T1114.003, T1098, T1556 |

*More case studies in progress — PAN-OS GlobalProtect exploit detection, Copilot Studio governance.*

## AI Security Governance & Tooling

| Project | Focus |
| --- | --- |
| [AI TRiSM Implementation Guide](case-studies/ai-trism-implementation-guide.md) | Maps Gartner's AI TRiSM framework to specific Microsoft Defender XDR and Purview capabilities for Azure AI Foundry agents, with a phased implementation plan and MAESTRO-layer-to-tooling crosswalk |
| [Combined STRIDE + MAESTRO Threat Model Template](case-studies/stride-maestro-threat-model-template.md) | Reusable threat-modeling template for agentic AI systems — MAESTRO's seven layers decompose the attack surface, STRIDE applies systematically within each, pre-populated threats mapped to MITRE ATT&CK/ATLAS |
| [pan_rule_validator](https://github.com/wendyrojas7-cyber/pan_rule_validator) | Python tool for deterministic Panorama firewall rulebase validation (shadowing, redundancy, permissiveness checks), 23 passing tests — AI narrative layer planned for Phase 2 |

## Core Skills

- **Detection Engineering:** KQL custom detection rules, Advanced Hunting, MITRE ATT&CK-aligned rule design
- **Threat Hunting & Intel:** hypothesis-driven hunting, IOC pipeline management, CVE-driven detection prioritization
- **Identity & Cloud Security:** Entra ID Conditional Access, PIM/PIM for Groups, Managed Identities, least-privilege architecture
- **Governance:** Microsoft Purview role design, Defender for Cloud Apps, AI/agent governance (Copilot Studio)
- **AI Threat Modeling & Risk Management:** STRIDE + MAESTRO agentic AI threat modeling, Gartner AI TRiSM implementation, MITRE ATLAS-mapped detection engineering
- **Tooling:** Microsoft Defender XDR, Sentinel, Rapid7 InsightIDR/InsightConnect, Nessus, Azure AI Foundry

## Note on content

Case studies describe real detection engineering work. Organization names, exact IOCs, hashes, domains, and other identifying details have been generalized or omitted; the technical methodology and reasoning are accurate.
