# Incident Case Study: Intra-Org Spoofed Phishing Email Bypassing DMARC Enforcement

## Summary

A phishing email was delivered to a shared mailbox, spoofing the mailbox's own address as the sender. The message claimed an account/agreement expiry from 2023 and contained a malicious link. While the phishing content itself was low-effort (spelling error, generic pretext), header analysis revealed the message failed both SPF and DMARC authentication — yet was still delivered to the inbox rather than quarantined, despite an org-wide DMARC policy of `p=quarantine`. Root cause investigation pointed to an SCL override (`SCL:-1`) consistent with an intra-org/anti-spoof exemption path taking precedence over DMARC enforcement action.

This case is notable not for the phishing lure itself, but for the **mail flow gap** it surfaced: authentication explicitly failed, and the message was delivered anyway.

## Timeline

| Time | Event |
|---|---|
| T+0 | Shared mailbox receives email; sender display name and From address match the mailbox's own address |
| T+0 | Message flagged "Unverified" by Outlook client-side anti-spoofing UI |
| T+X | Analyst reviews message details; From/Return-Path both show internal domain, prompting deeper header review |
| T+X | Full header analysis performed (Authentication-Results, Received chain, X-Forefront-Antispam-Report) |
| T+X | Root cause identified: DMARC fail, SCL -1, delivery action inconsistent with configured quarantine policy |

## Indicators

| Type | Value | Notes |
|---|---|---|
| Sending IP | `31.57.201.24` | No reverse DNS (`PTR:InfoDomainNonexistent`) |
| ASN / Hosting provider | GOLD IP (goldipv4.com) | Budget NL-based hosting, not flagged on AbuseIPDB at time of review |
| HELO/EHLO | `[127.0.0.1]` | Localhost HELO — consistent with direct-inject phishing infrastructure, not legitimate MTA behavior |
| Spoofed sender | Org's own shared mailbox address | Both From and Return-Path forged to match |
| SPF | `fail` | Sending IP not authorized for org domain |
| DKIM | `none` | No signature present |
| DMARC | `fail` | Alignment failure on both SPF and DKIM |
| SCL | `-1` | Message explicitly exempted from spam/phish filtering pipeline |

## Root Cause Analysis

The header trail shows a single `Received` hop with no evidence of transit through legitimate mail infrastructure — consistent with direct SMTP injection from external infrastructure rather than a relayed or spoofed-but-routed message. `AuthAs:Anonymous` in the X-MS-Exchange-Organization headers confirms the message did not originate from any authenticated path within the tenant, ruling out genuine internal-to-internal delivery.

**Confirmed root cause: anti-phish policy scoping gap excluding unlicensed mailboxes.**

The org's anti-phishing policy correctly honors DMARC (`p=reject` → reject, `p=quarantine` → quarantine) — this was verified directly in the policy configuration. However, the policy's recipient scope is a group built around licensed users (E5/F3), since spoof intelligence and impersonation protection are Defender for Office 365 (Plan 1/2) capabilities gated to licensed seats. Shared mailboxes hold no license and are not members of that group, so they fall outside the policy's scope entirely.

Practical effect: for this recipient, no anti-phish policy evaluated the message, so no quarantine action was ever triggered — regardless of the DMARC fail. The DMARC failure itself is a domain-level DNS check and was still observable in the raw headers/Authentication-Results, but a failed check with no policy watching the recipient produces no enforcement action. This is distinct from — and a more complete explanation than — the initial working hypothesis below.

**Ruled-out hypothesis (documented for investigative trail):**
Initial analysis of the `SCL:-1` value in the X-Forefront-Antispam-Report suggested a possible mail flow rule or connector override exempting the message from scoring. This was a reasonable read of the header in isolation, but the confirmed policy-scoping gap is sufficient on its own to explain the outcome — no override needed. SCL -1 in this context most likely reflects the message being evaluated by a filtering pipeline that had no applicable phish/quarantine policy to enforce for this recipient, rather than an explicit trust override. This is noted here as an example of why header-level evidence should be corroborated against actual policy configuration before being treated as root cause.

**On the spoofing itself:** the forged From address matching the org's own domain is not, by itself, evidence of a misconfiguration — SMTP does not validate the From header, so setting it to any address is trivial for a sender. The purpose of SPF/DKIM/DMARC and anti-phish policy evaluation is specifically to detect and act on this exact scenario. The failure here is not that spoofing was possible (it always is, for any domain), but that the control designed to catch it was not applied to this recipient.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Gather Victim Org Information: Domain Properties | T1590.001 |
| Resource Development | Compromise Accounts / Email Accounts (spoofed identity infrastructure) | T1586.002 |
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Defense Evasion | Impersonation | T1656 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |

## Detection Engineering Response

Built Advanced Hunting KQL queries to:
1. Hunt for additional mail from the same IP/ASN across the org (30-day lookback)
2. Detect the specific bypass condition going forward — own-domain sender, DMARC/SPF fail, delivered rather than blocked
3. Identify the HELO-localhost / missing-PTR signature as a general low-cost phishing infrastructure indicator
4. Correlate any delivered messages matching this pattern with subsequent SafeLinks click events

These queries are designed to serve both as retrospective hunting and as candidate scheduled analytics rules for ongoing detection.

## Remediation & Recommendations

1. **Priority — close the anti-phish policy scoping gap.** Either add shared mailboxes (and other unlicensed/resource mailboxes) to the existing policy's scoped group, broaden the policy scope to the full accepted domain rather than a license-tied group, or stand up a dedicated anti-phish policy covering all non-licensed mailbox types.
2. **Audit anti-spam and other Defender for Office 365 policies for the same scoping pattern** — if the anti-phish policy scope was built around licensed users, spam/bulk and other protections may have the identical gap for shared, resource, and equipment mailboxes.
3. **Inventory all unlicensed mailboxes** (shared, resource, room/equipment) org-wide and confirm each is covered by at least a baseline protection policy.
4. **Block sending IP** `31.57.201.24` and monitor the GOLD IP (goldipv4.com) ASN for recurrence.
5. **Report the IP** to AbuseIPDB and the hosting provider's abuse contact.
6. Convert the hunting queries into scheduled analytics rules in Sentinel for ongoing coverage of DMARC-fail-but-delivered patterns, since policy scoping gaps of this kind can recur across other unlicensed recipients even after this specific mailbox is fixed.

## Lessons Learned

- Client-side "Unverified" tags and matching From/Return-Path addresses are not sufficient evidence to clear a message — full header authentication review (SPF/DKIM/DMARC, SCL, Received chain) is necessary any time a message claims to originate from an org's own domain.
- A failed DMARC check does not guarantee enforcement; delivery action must be verified against actual policy scope and configuration, not just the domain's published DMARC record. A correctly configured policy provides no protection to recipients outside its scope.
- **Security policy scoping tied to license groups creates blind spots for non-interactive mailboxes.** Shared, resource, and equipment mailboxes don't hold licenses and can be silently excluded from protections (anti-phish, anti-spam, and potentially others) if scoping groups are built around licensed-user populations rather than the full accepted domain. This is a pattern worth checking across all Defender for Office 365 policies, not just the one that surfaced it here.
- Low-effort phishing content (spelling errors, generic pretext) should not be treated as a signal of low risk — this message's real significance was the mail flow control gap it exposed, not the lure itself.
- Header-level evidence (like an SCL value) should be corroborated against actual policy configuration before being treated as root cause. The initial SCL-override hypothesis was reasonable given the data available at the time, but the confirmed policy scoping gap was the actual mechanism — a useful reminder to verify configuration directly rather than resting on inference alone.
