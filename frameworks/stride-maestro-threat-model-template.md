# Combined STRIDE + MAESTRO Threat Model Template

**Focus:** A reusable threat-modeling template for agentic AI systems, combining STRIDE (systematic per-component threat categorization) with MAESTRO (the Cloud Security Alliance's seven-layer framework purpose-built for agentic AI) into a single working document.

**MAESTRO / STRIDE / MITRE ATT&CK / MITRE ATLAS**

---

Traditional STRIDE was built for deterministic software with fixed trust boundaries — it has no native vocabulary for autonomous decision-making, dynamic tool use, or multi-agent interaction. This template closes that gap: MAESTRO's seven layers (Foundation Models, Data Operations, Agent Frameworks, Deployment Infrastructure, Evaluation & Observability, Security & Compliance, Agent Ecosystem) decompose the AI-specific attack surface, STRIDE is applied systematically within each layer, and a dedicated cross-layer pass hunts cascading attack chains STRIDE alone can't express (e.g., data poisoning → model behavior → tool action).

The template is pre-populated with common AI-specific threats (model substitution, RAG poisoning, prompt injection, tool-call privilege escalation, and more) mapped to MITRE ATT&CK and ATLAS technique IDs for detection-engineering traceability, plus pre-production security gates and detection stubs meant to be operationalized as Sentinel/Defender XDR KQL rules.

*Note on content: This is a personal, self-directed template built to formalize a repeatable threat-modeling process for agentic AI — it is intentionally generic and fillable, with no system-specific or organizational data. Field values are left blank for reuse on any agentic AI deployment.*

---

**COMBINED STRIDE + MAESTRO**

Threat Model Template for Agentic AI Systems

System / Agent Name:
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ Version:
\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_\_

> **How this template works:** MAESTRO's seven layers decompose the AI-specific attack surface; STRIDE is applied within each layer for systematic categorization; a dedicated cross-layer pass hunts cascading attack chains; MITRE ATT&CK and ATLAS technique IDs anchor each threat to detection engineering work.

## 1. Methodology Overview

Traditional frameworks like STRIDE were built for deterministic software
with fixed trust boundaries. Agentic AI systems introduce autonomous
decision-making, dynamic tool use, and multi-agent interaction that
STRIDE has no native vocabulary for. MAESTRO (Multi-Agent Environment,
Security, Threat, Risk, and Outcome) fills that gap by decomposing the
system into seven layers, each with its own threat landscape. This
template applies both in sequence:

|                         |                                                                                                                                                                         |                                                  |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| **Step**                | **Action**                                                                                                                                                              | **Framework Contribution**                       |
| **1. Decompose**        | Map the system's actual architecture onto MAESTRO's seven layers.                                                                                                       | MAESTRO — defines the AI-specific attack surface |
| **2. Categorize**       | Apply STRIDE to every component identified within each layer.                                                                                                           | STRIDE — systematic, repeatable threat coverage  |
| **3. Hunt cross-layer** | Trace chains where a threat in one layer cascades into another (e.g., data poisoning → model behavior → tool action).                                                   | MAESTRO — the piece STRIDE cannot express alone  |
| **4. Score & mitigate** | Rate likelihood/impact; assign controls, split between traditional (RBAC, network, logging) and AI-specific (groundedness checks, output filtering, tool allowlisting). | Combined — risk matrix + layered controls        |

## 2. System Decomposition — MAESTRO Layer Mapping

Before threat modeling begins, map the actual system architecture onto
the seven MAESTRO layers. This becomes the scope boundary for the threat
register in Section 3.

|           |                                 |                                                                                    |                                            |
|-----------|---------------------------------|------------------------------------------------------------------------------------|--------------------------------------------|
| **Layer** | **Name**                        | **Definition**                                                                     | **Components in This System**              |
| **L1**    | **Foundation Models**           | Base LLM(s), fine-tuned models, embeddings models — the reasoning core.            | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L2**    | **Data Operations**             | Training data, RAG corpora, vector stores, labeling pipelines, data ingestion.     | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L3**    | **Agent Frameworks**            | Orchestration logic, planning/reasoning loop, tool/function dispatch, memory.      | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L4**    | **Deployment & Infrastructure** | Compute hosting, containers, networking, managed identities, secrets.              | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L5**    | **Evaluation & Observability**  | Logging, monitoring, guardrails, red-teaming (PyRIT/Garak), telemetry.             | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L6**    | **Security & Compliance**       | RBAC/governance, content safety policy, regulatory controls, DLP.                  | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| **L7**    | **Agent Ecosystem**             | Multi-agent (A2A) interactions, MCP tool servers, third-party plugins/marketplace. | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |

**2.1 Tool / Function Manifest**

Every tool or function the agent can invoke, regardless of layer, should
be inventoried here. This is the primary attack surface for
prompt-injection-driven privilege escalation (see T6, T8).

|                              |                              |                              |                              |                   |
|------------------------------|------------------------------|------------------------------|------------------------------|-------------------|
| **Tool / Function**          | **Purpose**                  | **Permissions Granted**      | **Data Accessed**            | **MAESTRO Layer** |
| \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | L3 / L7           |
| \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | L3 / L7           |
| \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | L3 / L7           |

## 3. Layer-by-Layer STRIDE Threat Register

Each row applies one STRIDE category to a specific component within a
specific MAESTRO layer. IDs marked in the ATT&CK / ATLAS column
reference MITRE ATT&CK (conventional infrastructure/identity TTPs) or
MITRE ATLAS (adversarial ML / AI-specific TTPs) for detection
engineering traceability. Pre-populated with common AI-specific threats
— edit, remove, or add rows as the system dictates.

| **ID**  | **Layer** | **Component**            | **STRIDE**                 | **Threat Description**                                                                                             | **ATT&CK / ATLAS** | **Like.** | **Imp.** |
|---------|-----------|--------------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------|--------------------|-----------|----------|
| **T1**  | **L1**    | Foundation Model         | **Spoofing**               | Model substitution — a malicious or downgraded model is swapped in place of the approved deployment.               | ATLAS AML.T0010    | **Med**   | **High** |
| **T2**  | **L1**    | Foundation Model         | **Tampering**              | Training/fine-tuning data poisoning skews model reasoning or embeds a backdoor trigger.                            | ATLAS AML.T0020    | **Med**   | **High** |
| **T3**  | **L1**    | Foundation Model         | **Info Disclosure**        | Model inversion / membership inference extracts memorized training data.                                           | ATLAS AML.T0024    | **Low**   | **High** |
| **T4**  | **L2**    | Data Operations          | **Tampering**              | RAG corpus poisoning — malicious documents injected into the retrieval index alter agent output.                   | ATLAS AML.T0059    | **High**  | **High** |
| **T5**  | **L2**    | Data Operations          | **Info Disclosure**        | Sensitive data leakage through embeddings or an under-scoped vector store.                                         | ATT&CK T1530       | **Med**   | **High** |
| **T6**  | **L3**    | Agent Framework          | **Elevation of Privilege** | Prompt injection causes unauthorized or out-of-scope tool invocation.                                              | ATLAS AML.T0051    | **High**  | **High** |
| **T7**  | **L3**    | Agent Framework          | **Repudiation**            | Agent actions lack sufficient audit trail to attribute a decision to a specific instructing user or upstream call. | ATT&CK T1562.002   | **Med**   | **Med**  |
| **T8**  | **L3**    | Agent Framework          | **Tampering**              | Unintended tool use — the model calls a tool with manipulated or incorrect parameters.                             | ATLAS AML.T0053    | **High**  | **High** |
| **T9**  | **L3**    | Agent Framework          | **Denial of Service**      | Recursive planning loop or unbounded agent-to-agent delegation exhausts compute/token budget.                      | ATT&CK T1499       | **Med**   | **Med**  |
| **T10** | **L4**    | Deployment/Infra         | **Elevation of Privilege** | Over-privileged managed identity or service principal attached to agent compute.                                   | ATT&CK T1078.004   | **Med**   | **High** |
| **T11** | **L4**    | Deployment/Infra         | **Spoofing**               | Missing mutual authentication between the agent and downstream APIs/tool endpoints.                                | ATT&CK T1557       | **Med**   | **Med**  |
| **T12** | **L5**    | Evaluation/Observability | **Repudiation**            | Incomplete logging of the model's reasoning/tool-call chain blinds incident response.                              | ATT&CK T1070       | **Med**   | **High** |
| **T13** | **L5**    | Evaluation/Observability | **Tampering**              | Guardrail/evaluation bypass via adversarial prompt suffixes or encoding tricks.                                    | ATLAS AML.T0043    | **Med**   | **High** |
| **T14** | **L6**    | Security/Compliance      | **Info Disclosure**        | Missing content-safety/DLP policy allows sensitive data to exfiltrate through agent output.                        | ATT&CK T1567       | **Med**   | **High** |
| **T15** | **L6**    | Security/Compliance      | **Elevation of Privilege** | Inadequate RBAC segregation between agent dev, test, and production environments.                                  | ATT&CK T1078       | **Med**   | **High** |
| **T16** | **L7**    | Agent Ecosystem          | **Spoofing**               | Malicious or rogue agent impersonates a trusted peer in an A2A/MCP exchange.                                       | ATLAS AML.T0048    | **Med**   | **High** |
| **T17** | **L7**    | Agent Ecosystem          | **Tampering**              | Compromised third-party tool or plugin sourced from an agent marketplace.                                          | ATT&CK T1195       | **Med**   | **High** |

## 4. Cross-Layer Cascade Analysis

This is the analysis STRIDE cannot perform alone. A weakness in one
layer often becomes exploitable only once chained through another — the
most severe agentic AI incidents follow one of these paths rather than a
single-layer failure.

|          |                  |                                                                                                                                                         |                                                                                                                                          |
|----------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| **Path** | **Layer Chain**  | **Description**                                                                                                                                         | **Example Scenario**                                                                                                                     |
| **CL1**  | **L2 → L1 → L3** | RAG corpus poisoning skews model reasoning, which drives the agent to invoke a destructive or unauthorized tool action.                                 | Poisoned support-doc index causes the agent to "confirm" a refund/delete action a policy would normally block.                           |
| **CL2**  | **L1 → L3 → L4** | A crafted prompt (injection) triggers an unauthorized tool call, which escalates using an over-privileged managed identity at the infrastructure layer. | Injected instruction in retrieved content causes the agent to call a storage-delete function using its own over-scoped identity.         |
| **CL3**  | **L7 → L3 → L6** | A compromised external agent feeds malicious instructions to the internal orchestrator, bypassing compliance logging designed for direct user input.    | A partner agent in an A2A workflow returns a manipulated "task result" that the orchestrator treats as trusted, skipping DLP inspection. |
| **CL4**  | **L4 → L2 → L1** | Infrastructure compromise (e.g., over-permissioned storage) allows exfiltration of fine-tuning data or model weights.                                   | A misconfigured storage account exposes the fine-tuning dataset, enabling downstream model extraction or replication.                    |

## 5. Identity & Access (Layers 4, 6)

Full RBAC inventory for every identity that can act on or through the
agent. Favor Managed Identities and PIM-eligible roles over standing
credentials; segregate dev/test/prod scopes explicitly (see T15).

|                        |                              |                              |                              |
|------------------------|------------------------------|------------------------------|------------------------------|
| **Identity**           | **Role Assigned**            | **Scope**                    | **Justification**            |
| Agent managed identity | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| Dev team (build)       | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| Ops/Security (monitor) | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ | \_\_\_\_\_\_\_\_\_\_\_\_\_\_ |

## 6. Network & Deployment Security Checklist (Layer 4)

**☐** Agent compute isolated via private endpoints; no public inbound
exposure.

**☐** APIM (or equivalent) gateway enforces rate limiting and auth in
front of the agent endpoint.

**☐** Managed Identity used for all downstream calls — no static keys or
embedded secrets.

**☐** Mutual TLS or signed-request verification between agent and
tool/plugin endpoints (T11).

**☐** Network segmentation separates agent runtime from data ingestion
pipelines.

## 7. Prompt Injection & Input Validation (Layers 1–3)

**☐** Untrusted content (retrieved documents, tool outputs, external
agent responses) is explicitly delimited and never concatenated into
system-level instructions.

**☐** Content-safety / groundedness filtering applied to both inputs and
outputs.

**☐** Tool-call parameters validated against an allowlist/schema before
execution (T8).

**☐** Adversarial testing performed with PyRIT / Garak (or equivalent)
prior to production release (T13).

**☐** RAG ingestion pipeline requires provenance/approval before
documents enter the retrieval index (T4).

## 8. Logging, Detection & Evaluation Coverage (Layer 5)

Detection stubs below map directly to threat register entries and are
intended to be operationalized as KQL rules in Sentinel / Defender XDR.

|        |           |                                                      |                                         |                                                                                                              |                  |
|--------|-----------|------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------------------------------------------------------|------------------|
| **ID** | **Layer** | **Detection Name**                                   | **Data Source**                         | **Logic Summary**                                                                                            | **Mapped ID**    |
| **D1** | **L1/L3** | **Anomalous tool-call rate per session**             | Sentinel / Defender XDR agent telemetry | Flag sessions where tool invocations exceed baseline p95 within a rolling window.                            | ATLAS AML.T0051  |
| **D2** | **L2**    | **RAG source drift detection**                       | Vector store ingestion logs             | Alert on new/modified documents entering the retrieval index outside the approved ingestion pipeline.        | ATLAS AML.T0059  |
| **D3** | **L3**    | **Prompt injection signature match**                 | App/agent request logs                  | Pattern + heuristic match on known injection markers and instruction-override phrasing in retrieved content. | ATLAS AML.T0051  |
| **D4** | **L4**    | **Managed identity privilege escalation**            | EntraIdSignInEvents / AuditLogs         | Alert on role assignment changes granting the agent identity new high-privilege scopes.                      | ATT&CK T1078.004 |
| **D5** | **L5**    | **Guardrail bypass / repeated content-safety block** | Azure AI Content Safety logs            | Alert on repeated blocked completions from a single session, indicating adversarial probing.                 | ATLAS AML.T0043  |
| **D6** | **L7**    | **Unrecognized peer agent in A2A exchange**          | Agent orchestration/API gateway logs    | Alert when a task result arrives from an agent identity not on the approved peer allowlist.                  | ATLAS AML.T0048  |

## 9. Pre-Production Security Gates

All items require sign-off before an agent progresses from staging to
production.

**Layers 1–2 (Model & Data)**

**☐** Model provenance and version pinned; substitution risk assessed
(T1).

**☐** Training/fine-tuning and RAG data sources reviewed for poisoning
risk (T2, T4).

**☐** Data classification applied to all sources the agent can retrieve
from (T5).

**Layer 3 (Agent Framework)**

**☐** Tool manifest reviewed and least-privilege scoped per tool (T6,
T8).

**☐** Loop/recursion limits and token budget caps enforced (T9).

**☐** Human-in-the-loop gate defined for high-impact/irreversible
actions.

**☐** Audit logging captures full reasoning + tool-call chain,
attributable to originating user (T7).

**Layer 4 (Deployment)**

**☐** Managed Identity scoped to least privilege; PIM used for any
elevated access (T10).

**☐** Private endpoints and network segmentation validated (Section 6).

**☐** Mutual auth confirmed between agent and all downstream tool
endpoints (T11).

**Layer 5 (Evaluation)**

**☐** Adversarial red-team pass completed and findings remediated (T13).

**☐** Detection rules (Section 8) deployed and validated against test
cases.

**Layer 6 (Compliance)**

**☐** Content-safety / DLP policy applied to agent output path (T14).

**☐** Dev/test/prod RBAC segregation verified (T15).

**Layer 7 (Ecosystem)**

**☐** Peer-agent allowlist defined for any A2A/MCP interaction (T16).

**☐** Third-party tools/plugins reviewed for supply-chain risk (T17).

**☐** Rollback/kill-switch procedure documented and tested.

## 10. Residual Risk & Sign-Off

Document any accepted residual risk with compensating controls and an
owner. Review this threat model on the cadence below or upon material
architecture change (new tool, new model version, new agent peer).

> **How this template works:** MAESTRO's seven layers decompose the AI-specific attack surface; STRIDE is applied within each layer for systematic categorization; a dedicated cross-layer pass hunts cascading attack chains; MITRE ATT&CK and ATLAS technique IDs anchor each threat to detection engineering work.

|                           |          |               |          |
|---------------------------|----------|---------------|----------|
| **Role**                  | **Name** | **Signature** | **Date** |
| Security Engineering Lead |          |               |          |
| AI/Agent Owning Team Lead |          |               |          |
| Platform/Infra Owner      |          |               |          |
