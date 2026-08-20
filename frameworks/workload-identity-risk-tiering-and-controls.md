# Workload Identity Risk Tiering & Control Mapping
### Classifying Enterprise Apps / Service Principals as Critical/High, and Choosing Between Workload ID Conditional Access and Microsoft Defender for Cloud Apps (MDCA)

---

## 1. Purpose

Not all app registrations and service principals carry the same blast radius. Before applying Conditional Access for Workload Identities or Microsoft Defender for Cloud Apps (MDCA) controls, every enterprise app needs a documented risk tier. This guide defines:

1. A repeatable scoring rubric for tiering enterprise apps as **Critical / High / Standard**.
2. The exact scope and licensing boundaries of Conditional Access for Workload Identities.
3. Where MDCA (App Governance, Cloud Discovery, App Control) picks up the coverage gap Workload ID CA cannot reach.
4. A decision matrix mapping tier → control.

---

## 2. Risk Tiering Rubric

Score each service principal against the factors below. An app that hits **any single Critical trigger** is automatically Critical, regardless of its score elsewhere — privilege ceiling and business dependency override aggregate scoring.

| Factor | Standard | High | Critical |
|---|---|---|---|
| **API permission type** | Delegated only, narrow scope | Delegated with broad scope, or Application permissions limited to a single resource | Application permissions with `*.All` Graph scope (e.g. `Mail.ReadWrite.All`, `Sites.FullControl.All`) |
| **Privilege ceiling** | No directory or role access | Read access to directory data | Can read/write directory data, assign roles, or modify Entra/CA configuration itself (`Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`) |
| **Blast radius** | Single downstream system | Multiple internal systems | Tenant-wide reach, or multi-tenant/third-party SaaS with broad consent |
| **Business dependency** | Non-production or low-impact | Supports a business process | Production/revenue-generating dependency (auth infra, ERP, plant-floor/OT integration) |
| **Credential model** | Managed identity | Certificate-based app registration | Client secret, especially long-lived or shared across environments |
| **Ownership hygiene** | Documented owner, admin-consented | Documented owner, some scope drift | No accountable owner, or user-consented shadow IT |
| **Sign-in pattern** | Predictable, scheduled | Mostly predictable | Irregular, interactive, or unbaselined |

**Tiering outcome:**
- **Critical** — tenant-admin-equivalent Graph/Azure RM permissions, or a production auth dependency.
- **High** — broad `*.All` application permissions without directory-write, or unclear ownership on a business-critical integration.
- **Standard** — narrow, single-resource delegated permissions with a known owner.

---

## 3. Conditional Access for Workload Identities — Scope & Fit

### 3.1 Hard scope limits

Conditional Access for workload identities **only applies to single-tenant service principals registered in your own tenant**. Third-party SaaS, multi-tenant apps, and managed identities are explicitly out of scope — managed identities can't be targeted by policy at all, and third-party/multi-tenant apps have no policy surface here. This is the single most important scoping fact for your documentation: **it does not cover most vendor OAuth integrations.**

### 3.2 Licensing

Workload Identities Premium licensing is required to **create or modify** Conditional Access policies scoped to service principals. Existing policies in unlicensed directories continue to function but can't be changed — confirm licensing coverage before scoping new policies to your Critical tier.

### 3.3 Supported conditions

- **Location** — block service principal sign-ins from outside known public IP ranges (e.g., your Azure egress ranges, CI/CD runner ranges).
- **Risk** — block or restrict based on service principal risk level from Identity Protection (`servicePrincipalRiskLevels`: low/medium/high).
- **Authentication context** — combine with sensitive-action gating.

### 3.4 Continuous Access Evaluation (CAE) bonus

For service principals calling **Microsoft Graph specifically**, CAE for workload identities adds real-time enforcement of location/risk policy plus instant token revocation on:
- Service principal disable
- Service principal delete
- High service principal risk detected by Identity Protection

This is worth enabling as a hardening layer on top of CA for any Critical-tier app that talks to Graph.

### 3.5 When to apply

Apply Workload ID CA to any **single-tenant, internally-owned** service principal scored Critical or High **that has a boundable execution environment** — a known Azure region/egress range, a fixed CI/CD runner IP range, or another constrained location. If the app can't be pinned to a location, the location condition adds no value; rely on risk-based blocking alone in that case.

---

## 4. MDCA — Where It Covers the Gap

MDCA is not a substitute for Workload ID CA; it covers the identities and access patterns Workload ID CA structurally cannot reach.

| MDCA Capability | What it's for | When to use it |
|---|---|---|
| **App Governance (OAuth app monitoring)** | Evaluates permission scope, flags over-permissioned or anomalous OAuth apps, can auto-remediate (revoke consent, disable) | Any Critical/High app that is **third-party or multi-tenant** — i.e., explicitly excluded from Workload ID CA scope |
| **Cloud Discovery risk scoring** | Risk-scores apps discovered via network/log traffic (shadow IT) | Use as an input to initial tiering for apps that surfaced outside a formal registration process |
| **Conditional Access App Control (session policies)** | Proxies **interactive user browser sessions** into SaaS apps | Only relevant when a Critical app also has an interactive admin console accessed by humans — **not** for the app's own machine-to-machine calls. This is a common scoping mistake worth calling out explicitly in review. |

**Trigger for MDCA/App Governance**: any Critical/High app that is third-party, multi-tenant, or otherwise has no Workload ID CA control point — which in practice is most vendor SaaS integrations with Graph or M365 access.

---

## 5. Decision Matrix

| App characteristics | Control |
|---|---|
| Single-tenant, internally owned, Critical/High tier, boundable location | Workload ID CA — location + risk-based policy |
| Single-tenant, internally owned, Critical/High tier, no boundable location | Workload ID CA — risk-based policy only |
| Single-tenant, calls Microsoft Graph, Critical tier | Add CAE for workload identities on top of CA |
| Third-party / multi-tenant SaaS, Critical/High tier | MDCA App Governance (permission + anomaly monitoring) |
| Discovered via shadow IT, tier unknown | Cloud Discovery risk score → feed into Section 2 rubric |
| Critical app with an interactive admin console used by humans | Conditional Access App Control (session policy) — in addition to, not instead of, the above |
| Managed identity | Not covered by either policy surface — rely on scoped RBAC/least-privilege role assignment instead |

---

## 6. Open Items to Track

- [ ] Confirm current Workload Identities Premium license coverage against the count of Critical/High single-tenant SPs identified
- [ ] Build the CI/CD runner and Azure egress IP ranges as named locations for the location condition
- [ ] Inventory third-party/multi-tenant OAuth apps with `*.All` application permissions for App Governance onboarding
- [ ] Establish an owner-of-record requirement for any new Critical/High app registration (governance gap = automatic High tier)

---

*References: Microsoft Learn — Conditional Access for workload identities; Continuous access evaluation for workload identities; Microsoft Graph `conditionalAccessConditionSet` resource type.*
