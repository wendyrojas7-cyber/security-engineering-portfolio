# AI TRiSM Implementation Guide

**Focus:** Operationalizing AI Trust, Risk, and Security Management (Gartner AI TRiSM) for Azure AI Foundry agents using Microsoft Defender XDR and Microsoft Purview, aligned to STRIDE and the MAESTRO agentic AI threat model.

**Scope:** Azure AI Foundry agents, Defender XDR, Defender for Cloud, Microsoft Purview, Entra ID

**MAESTRO / AI TRiSM**

---

Personal project mapping the Gartner AI TRiSM framework's four functional layers (Governance, Runtime Monitoring, Security & Infrastructure, Privacy & Data Protection) to specific, actionable Microsoft Defender and Purview capabilities — with a phased implementation plan, a MAESTRO-layer-to-tooling crosswalk, and licensing prerequisites. Written to close the gap between "we did a threat model" and "the controls the threat model called for are actually running in production."

*Note on content: This is a personal, self-directed project built to explore AI governance tooling in depth — it was not produced as deliverable work for an employer, and does not reference any specific organization's environment, licensing, or configuration. Technical details reflect Microsoft Defender/Purview capabilities as of mid-2026 and should be verified against current Microsoft Learn documentation before use, as this space moves quickly.*

---

**AI TRiSM Implementation Guide**

*Operationalizing Trust, Risk, and Security Management using Microsoft
Defender and Microsoft Purview, aligned to STRIDE and the MAESTRO
agentic AI threat model*

Scope: Azure AI Foundry agents, Defender XDR, Defender for Cloud,
Microsoft Purview, Entra ID

Prepared: July 2026

## 1. What AI TRiSM Is, in One Page

AI TRiSM (AI Trust, Risk, and Security Management) is Gartner's
framework and set of technical capabilities for keeping AI systems
trustworthy, secure, and compliant through continuous monitoring,
validation, and enforcement, rather than one-time policy sign-off. The
operating idea: policies describe expectations, but only runtime
controls enforce them once a model or agent is live, so AI TRiSM embeds
monitoring and enforcement directly into the AI stack.

It is commonly organized into four functional layers:

- Governance — inventory of every model, agent, and application (an AI
  catalog), plus ongoing model validation so performance doesn't
  silently degrade.

- Runtime monitoring — watching live behavior for policy violations,
  anomalous outputs, and content that looks off.

- Security & infrastructure — the cloud, compute, and deployment layer
  the AI runs on, held to the same standards as the rest of the security
  program.

- Privacy & data protection — governance over the data feeding and
  flowing through AI pipelines, including what leaves the organization
  through prompts and responses.

## 2. How STRIDE, MAESTRO, and AI TRiSM Fit Together

Quick recap since this shapes the plan below:

- STRIDE — classic per-component threat categorization (Spoofing,
  Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege).
  A companion STRIDE threat model for the Azure AI Foundry agents in scope is assumed as a prerequisite (see the STRIDE+MAESTRO Threat Model Template in this portfolio).

- MAESTRO — the Cloud Security Alliance's seven-layer threat modeling
  framework purpose-built for agentic AI (Foundation Models, Data
  Operations, Agent Frameworks, Deployment Infrastructure, Evaluation &
  Observability, Orchestration, Ecosystem). It extends STRIDE rather
  than replacing it, adding the agent-specific risks STRIDE alone
  misses: goal misalignment, tool misuse, multi-agent collusion.

- AI TRiSM — the governance program that keeps both of the above alive
  in production: the continuous catalog → monitor → enforce → audit
  loop, rather than a point-in-time threat model.

This document focuses on which Microsoft Defender (and Purview) capabilities implement each piece, and in what order.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Read this before you build anything: the Agent 365
licensing transition</strong></p>
<p>Effective July 1, 2026, AI agent discovery, posture management, and
threat detection for Microsoft Foundry agents and third-party cloud
agents moved out of Defender for Cloud and Defender for Cloud Apps and
into Microsoft Agent 365 licensing. This already took effect.</p>
<p>Defender CSPM still discovers Foundry accounts and projects at the
account level, but agent-level inventory, posture, and detections now
require an Agent 365 license.</p>
<p>The AI agent inventory table in Advanced Hunting is moving from
AIAgentInfo to a new Agentsinfo table; AIAgentInfo will be deprecated.
Existing agent-specific alerts in Defender for AI Services are being
replaced by detections over Agent 365 observability logs, recorded in a
new BehaviorInfo table.</p>
<p>Defender for AI Services continues to cover Foundry Models (e.g.,
Azure OpenAI) directly — that part is unaffected.</p>
<p>Bottom line for planning: Defender for Cloud and Purview remain the
backbone for workload posture, data protection, and model-level threat
protection. Agent-level inventory and behavioral detection for Foundry
agents specifically now depends on Agent 365 licensing. Confirm
licensing status before committing to the agent-level steps in Phase 1
and Phase 3 below.</p></td>
</tr>
</tbody>
</table>

## 3. The Toolset Mapped to AI TRiSM's Four Layers

| **TRiSM Layer**           | **Purpose**                                            | **Primary Defender Capability**                                                                                                                                                                                                   | **Primary Purview Capability**                                                                                                                          |
|---------------------------|--------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Governance                | Know what AI exists and whether it's configured safely | Defender for Cloud CSPM — AI workload discovery & AI BOM (models, agents, data, artifacts) across Azure, AWS, GCP                                                                                                                 | Purview DSPM → Discover → Apps and agents dashboard; AI Observability inventory (1st + 3rd party agents)                                                |
| Runtime monitoring        | Catch bad behavior while it's happening                | Defender for Cloud AI threat protection (jailbreak / prompt-injection alerts on Foundry); Defender XDR AI Agent Protection (Copilot Studio + Foundry agents, real-time blocking); Advanced Hunting over Agentsinfo / BehaviorInfo | Purview Activity Explorer — AI activities tab (prompts, responses, DLP matches); Communication Compliance for AI interactions                           |
| Security & infrastructure | Harden what the AI runs on                             | Defender for Cloud CWP (runtime workload protection); AI model scanning in Azure ML registries (serialization flaws, malware); Entra ID + PIM for agent/service identities; Key Vault, Private Link, managed VNets                | Purview Information Protection sensitivity labels enforced at the infrastructure boundary via DLP integration                                           |
| Privacy & data protection | Control what data the AI can see or leak               | Defender for Cloud → enable data security for AI interactions (requires Purview license)                                                                                                                                          | Purview DSPM for AI one-click DLP policies; Data Risk Assessments (oversharing); Purview Audit for AI interactions; Data Lifecycle Management retention |

## 4. Where Purview Fits — Directly Answering That Question

Purview is not a bolt-on here — it is the Privacy & Data Protection
pillar of AI TRiSM, and it also does most of the heavy lifting for
Runtime Monitoring on the data side. Defender answers “is the AI
workload and its infrastructure secure and is it under attack”; Purview
answers “what data is this AI touching, and is it leaking, oversharing,
or violating policy.” Concretely:

- Purview DSPM (the current unified experience) replaces the older
  separate “DSPM” and “DSPM for AI (classic)” views, giving one place to
  see sensitive-data risk across both traditional data stores and AI
  apps/agents.

- Its Apps and agents view shows, per agent, what sensitive data it
  accessed and which Purview policies protect it — the natural evidence
  source for your MAESTRO Data Operations and Ecosystem layers.

- Activity Explorer's AI activities tab captures prompts and responses,
  flags sensitive-information matches, and shows DLP rule matches during
  AI interactions — direct input to your STRIDE Information Disclosure
  findings.

- One-click DSPM for AI policies give you fast wins: detect sensitive
  info pasted into third-party AI sites, block sensitive info from being
  sent to AI sites (with Adaptive Protection override for risky users),
  and capture prompts/responses from enterprise AI apps connected via
  Entra ID or Foundry for eDiscovery and retention.

- A hard dependency to flag: Defender for Cloud's “user prompt evidence”
  feature (which enriches jailbreak/prompt-injection alerts with the
  actual suspicious prompt text) requires a Purview license — it isn't
  included in the Defender for AI Services plan by itself. Also note
  Purview's Foundry integration currently covers user-context API calls;
  it does not yet capture data or context from Foundry agents
  specifically — track this gap in your threat register rather than
  assuming coverage.

## 5. Phased Implementation Plan

### Phase 1 — Foundational Visibility (Governance layer)

1.  Enable Defender for Cloud on the subscription(s) hosting Azure AI
    Foundry, then enable the CSPM plan and the AI workloads plan
    (Environment Settings → Defender plans → toggle AI services on).

2.  Confirm Agent 365 licensing for anyone who needs agent-level
    inventory, posture, or threat detection on Foundry agents — this is
    no longer optional as of the July 2026 transition. Without it,
    Defender CSPM still shows Foundry accounts/projects but not
    individual agents.

3.  Turn on Microsoft Purview Audit for the tenant (prerequisite for
    almost everything downstream).

4.  Stand up Purview DSPM and review the Objectives / Get started
    checklist — this is the fastest path to a working AI data inventory.

5.  Use the Purview ‘Apps and agents’ dashboard and the Defender AI BOM
    together to produce a single reconciled AI asset inventory — feed
    this straight into your existing STRIDE/MAESTRO threat register as
    the authoritative “what exists” layer.

### Phase 2 — Data Protection Guardrails (Privacy layer)

6.  Turn on Purview DSPM for AI's one-click policies: detect sensitive
    info in AI prompts, block sensitive info from being pasted/uploaded
    to third-party AI sites, and capture prompt/response interactions
    for enterprise AI apps connected through Entra ID or Foundry.

7.  Run a Data Risk Assessment focused on the SharePoint/OneDrive
    locations your Foundry agents are grounded against, to catch
    oversharing before an agent can surface it.

8.  Extend existing sensitivity labels and DLP policies so labeled
    content is respected inside AI prompts/responses, not just email and
    files.

9.  In Defender for Cloud, toggle ‘Enable data security for AI
    interactions’ and ‘Enable user prompt evidence’ (both require the
    Purview license) so jailbreak/prompt-injection alerts in Defender
    correlate directly with Purview Audit records of the same
    interaction.

10. Configure Foundry guardrail policies (content filtering, abuse
    monitoring) at the subscription or resource-group level so every
    model deployment inherits a minimum safety baseline before it ever
    reaches Defender's detection layer.

### Phase 3 — Runtime Detection Engineering (Monitoring layer — your home
turf)

11. Enable threat protection for AI services in Defender for Cloud to
    get jailbreak and prompt-attack alerts on Foundry's managed
    inference endpoints.

12. If Agent 365 is licensed, build Advanced Hunting KQL against the new
    Agentsinfo (inventory) and BehaviorInfo (real-time protection
    telemetry) tables — this replaces the deprecated AIAgentInfo table
    existing queries may still reference. Audit and update any
    saved queries or automation now.

13. Extend an existing MITRE ATT&CK-aligned KQL rule pack with an
    agentic-threat sibling set: anomalous tool-call sequences, excessive
    agent-to-agent calls, and out-of-policy output content, tagged
    separately as ‘agentic’ vs. ‘traditional’ threats the way MAESTRO's
    own tooling does — this keeps the register honest about what's
    genuinely new risk vs. reused endpoint/identity detections.

14. Correlate Defender jailbreak/prompt-injection alerts with Purview
    Activity Explorer's AI activities tab so an incident responder can
    see the flagged prompt, the sensitive-data classification, and the
    DLP outcome in one investigation.

15. Route all of the above into Defender XDR incidents so agent-related
    alerts sit in the same investigation queue as your existing identity
    and endpoint detections rather than a separate silo.

### Phase 4 — Governance Cadence (closing the loop)

16. Quarterly: reconcile Defender for Cloud AI security recommendations
    and Purview DSPM Objectives against your STRIDE/MAESTRO threat
    register, the same cadence used for an Azure AI Foundry hardening checklist.

17. Track the Agent 365 transition as a standing agenda item until fully
    migrated — licensing gaps here directly translate into
    governance-layer blind spots.

18. Track the Purview–Foundry agent-context gap (no agent-level prompt
    capture yet) as an open risk item rather than assuming Purview
    covers agents the same way it covers Copilot.

## 6. MAESTRO Layer → Microsoft Tool Crosswalk

| **MAESTRO Layer**          | **What It Covers**                                       | **Defender / Purview Signal Source**                                                                                      |     |
|----------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|-----|
| Foundation Models          | Prompt injection, jailbreaks, model-level abuse          | Defender for Cloud AI threat protection (jailbreak/prompt alerts); Defender for AI Services (Foundry Models/Azure OpenAI) |     |
| Data Operations            | Poisoned/oversharing data feeding the model or RAG index | Purview DSPM Data Risk Assessments; Activity Explorer AI activities tab                                                   |     |
| Agent Frameworks           | Tool misuse, goal hijacking, unauthorized function calls | Defender XDR AI Agent Protection; Agent 365 Agentsinfo/BehaviorInfo (licensed)                                            |     |
| Deployment Infrastructure  | Container, IAM, network, secrets around the agent        | Defender for Cloud CWP; Entra ID + PIM; Key Vault; Private Link/managed VNets                                             |     |
| Evaluation & Observability | Drift, hallucination rate, output monitoring             | Foundry Control Plane observability (OpenTelemetry) + Defender/Purview alert correlation                                  |     |
| Orchestration              | Multi-agent coordination, A2A/MCP trust boundaries       | Agent 365 behavioral analytics; custom Advanced Hunting KQL                                                               |     |
| Ecosystem                  | Third-party plugins, external data sources, compliance   | Purview DSPM external data source connectors; Purview Audit; Communication Compliance                                     |     |

## 7. Quick-Reference: Licensing Prerequisites

- Defender for Cloud CSPM plan — account/project-level AI discovery
  (Azure, AWS incl. Vertex AI, GCP).

- Defender for Cloud AI workloads / Defender for AI Services plan —
  jailbreak & prompt-attack threat protection on Foundry Models.

- Microsoft Agent 365 — required (as of July 1, 2026) for agent-level
  discovery, posture, and behavioral threat detection on Foundry and
  Copilot Studio agents.

- Microsoft Purview license — required for DSPM/DSPM for AI, and
  required to unlock ‘user prompt evidence’ and ‘data security for AI
  interactions’ inside Defender for Cloud.

- Microsoft Entra ID authentication with user-context tokens — required
  for Purview to attach Data Security Policies to individual Foundry API
  interactions; other auth patterns only surface in Purview Audit and
  Activity Explorer, not the enforcement path.

*Sources: Microsoft Learn (Defender for Cloud AI security posture, AI
threat protection, Foundry compliance/security docs, Agent 365
transition guidance), Microsoft Purview documentation (DSPM, DSPM for
AI), Gartner AI TRiSM guidance, Cloud Security Alliance MAESTRO
framework publications. Verify exact toggle names and licensing terms
against current Microsoft Learn pages before rollout, as this space is
changing quickly.*
