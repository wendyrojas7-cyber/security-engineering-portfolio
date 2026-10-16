# Runbook: Heuristic/ML Malware Alert on a Packed Helper Dropped by Signed Vendor Software

**Scenario:** Defender (or VirusTotal) flags a generically named executable with a generic ML/heuristic detection (for example `Trojan:Win32/Wacatac.*!ml`). The file is written to a user Temp folder by a signed commercial application, typically industrial or diagnostic software that uses a software-protection or licensing wrapper.

**Outcome this runbook supports:** confirm false positive with evidence, or escalate. Never close on vendor name alone.

**MITRE ATT&CK context (why these files get flagged):**

| Behavior seen in sandbox / static analysis | Technique | Why it appears in benign software |
|---|---|---|
| Obfuscated or packed binary | T1027 Obfuscated Files or Information | License/copy-protection wrappers encrypt the executable |
| Debugger and environment checks | T1497 Virtualization/Sandbox Evasion | Anti-cracking checks look identical to malware evasion |
| Idle/user-input checks | T1497.002 User Activity Based Checks | Protection runtimes wait for real interaction |
| Drops files to Temp at runtime | T1105 / T1036 (superficially) | Self-extracting or generated helper files |

---

## 1. Read the detection correctly

- [ ] Note the threat name. The `!ml` suffix marks a machine-learning detection, not a named family.
- [ ] On VirusTotal, check **which** engines flag it. A handful of heuristic/static-ML hits with no family name and no major-vendor consensus leans false positive.
- [ ] Note the sandbox tags (obfuscated, detect-debug-environment, checks-user-input, idle). These fit protection wrappers **and** malware, so they are not proof either way.
- [ ] Treat sandbox network and dropped-file counts as noisy. Confirm behavior on the real device.

## 2. Identify the parent

- [ ] Find the initiating process for the flagged file (`InitiatingProcessFileName`, `InitiatingProcessSHA256`).
- [ ] Confirm the parent is **signed** and the signer matches the expected vendor (not just any valid signature).
- [ ] Compare the parent hash to the vendor package or a known-good install.
- [ ] Check the parent hash is clean and identical across other devices with the same software.

## 3. Hunt by device, not by hash alone

```kusto
let TargetDevice = "<device name>";
let FlaggedSha = "<sha256>";
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName =~ TargetDevice or SHA256 == FlaggedSha
| where FileName startswith "<filename prefix>" or SHA256 == FlaggedSha
| summarize Names=dcount(FileName), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, FolderPath, InitiatingProcessFileName,
       InitiatingProcessSHA256, InitiatingProcessVersionInfoCompanyName
| order by Last desc
```

Run the same filter against:
- `DeviceProcessEvents` for execution, command line, and child `cmd`/`powershell`/`msiexec`
- `DeviceNetworkEvents` for outbound connections from the flagged process
- `DeviceImageLoadEvents` for unexpected DLL loads

Note: `WasExecutingWhileDetected` describes only the moment of detection. Confirm execution separately.

## 4. Decision table

| Evidence | Lean |
|---|---|
| Signed vendor parent, same hash on many devices, writes only to Temp, no unexpected network or child processes | False positive |
| Same hash across many names but one consistent signed parent | False positive (generated helper copies) |
| Parent unsigned, signer mismatch, or hash differs from vendor package | Escalate |
| Single device only, no one can confirm who installed the software | Escalate |
| Outbound connections to unfamiliar hosts, or child shells spawned by the helper | Escalate |
| Download source is not the vendor (email, ad, lookalike domain) | Escalate |

## 5. Closure for a confirmed false positive

- [ ] Confirm with the business or production owner that the software is sanctioned and in use.
- [ ] Add a **file hash allow indicator** for the specific SHA256. Do not exclude the Temp folder.
- [ ] Write a justification in the indicator description and set an expiry or review date.
- [ ] Submit the file to Microsoft as a suspected false positive, including the signer and product details.
- [ ] Notify the owner that the alert was benign.
- [ ] Record the pattern for faster triage next time.

## 6. Lessons

- Vendor name in a filename or parent proves nothing by itself. Signature and origin do.
- An unsigned helper dropped by a signed parent is consistent with runtime-generated protection files.
- Avoid path-based exclusions in user-writable locations. Prefer a hash indicator scoped to one file.
- Verify against your own telemetry before relying on sandbox network or dropped-file counts.
- Production-impacting software means no hash block or quarantine until the owner is consulted.
