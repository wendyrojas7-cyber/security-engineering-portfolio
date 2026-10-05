# Investigation: Wacatac detection with ScreenConnect.ClientSetup.exe in Downloads

**Status:** Closed
**Platform:** Microsoft Defender XDR (Advanced Hunting, Live Response)
**Related work:** Builds on a known-malware hash triage workflow (a TamperedChef installer case) and an RMM detection-rule review. The runbook that came out of this case is [remote-access-installer-guidebook.md](../runbooks/remote-access-installer-guidebook.md).

## Summary

**Classification:** True positive, malicious installer, launched and stopped, prevented with no compromise (outcome two in the companion guidebook).

Defender detected `Trojan:Win32/Wacatac.C!ml` on `ScreenConnect.ClientSetup.exe` in a user's Downloads folder. The installer was downloaded by Edge from a non-vendor lookalike domain, reached through a search ad, and was launched once. Defender stopped and removed it (`WasExecutingWhileDetected` false, `WasRemediated` true). Process, network, service, file, registry, and software-inventory telemetry showed no child processes, no relay connection, and no ScreenConnect client install. A tenant sweep found no other device, click, or email with the domain, and the account sign-in review was clean. Once the device was back online, Live Response confirmed no ScreenConnect service or install folder. The domain and SHA256 are blocked. The user said no one had instructed them to download the file and that they ran nothing else and entered no information; they did not say what they searched for or whether they meant to install a remote-access tool.

## Scenario

Defender blocked an active Wacatac detection on an endpoint. The alert showed that the user also had `ScreenConnect.ClientSetup.exe` in the Downloads folder. This is a different case from the TamperedChef triage: ScreenConnect is a legitimate, commonly abused remote access tool, so a hash reputation lookup is not enough to classify the file. The key questions are what Wacatac fired on, whether the installer ran, and whether anything connected to a ScreenConnect relay.

## Placeholders

Queries use `<device>` and `<user>` placeholders. No device, user, or tenant identifiers are published. The indicators below (domain, URL) are defanged; file hashes are left as-is.

## Workflow and differences from the known-malware (TamperedChef) triage

| # | Step | Same as known-malware triage? | Difference to track | Status | Finding |
|---|---|---|---|---|---|
| 1 | Alert details: flagged file, hashes, `WasExecutingWhileDetected`, `WasRemediated` | Same | Confirm Wacatac fired on the installer itself or on a separate file | Done | Wacatac fired on `ScreenConnect.ClientSetup.exe` itself. No other files in the alert, all evidence from one machine |
| 2 | Process execution on the device (90 days) | Same | Look for ScreenConnect client processes and `msiexec.exe` children | Partial | No `msiexec.exe`. One process-creation row for `ScreenConnect.ClientSetup.exe` (FileName and ProcessCommandLine both the installer name), initiated by `msedge.exe`. The installer was launched. Follow-up query shows no child processes. No SmartScreen, antivirus, or network protection events in the window |
| 3 | `AntivirusDetection` by device and time window | Same | Query by device, not by hash or filename | Done | `Trojan:Win32/Wacatac.C!ml`; `WasExecutingWhileDetected` false; `WasRemediated` true |
| 4 | File lifecycle and origin | Same | `FileOriginUrl` and referrer matter more: legitimate vendor or MSP vs malvertising or phishing | Done | Downloaded by `msedge.exe` from `connect[.]nexorainstaller[.]com`, a non-vendor domain. Events: FileCreated, FileRenamed, FileDeleted |
| 5 | Network activity | New emphasis | Relay host/IP from the installer or service; hash reputation will not settle this because the installer is per-instance | Done | No results from any ScreenConnect process |
| 6 | Persistence | Different checks | Look for a `ScreenConnect Client (<instance ID>)` service and a `Program Files (x86)\ScreenConnect Client (...)` folder, not `node.exe`, Run keys, or GUID-named tasks | Done | No `ScreenConnect Client` service key, no `ServiceInstalled` events after the launch, no ScreenConnect client files, and no ScreenConnect or ConnectWise software in inventory. Live Response `services` and `Program Files (x86)` output showed nothing named `ScreenConnect Client` |
| 7 | Live Response | Same caveat | Use explicit `C:\Users\<user>\...` paths; `%LOCALAPPDATA%` resolves to SYSTEM | Done | Device was offline after the event, so this ran once it reconnected; services and Program Files checks clean |
| 8 | User and identity review | Same | Recent sign-ins, other alerts, and the mail or web path that led to the download | Done | Sign-in review clean |
| 9 | Cleanup and blocking | Partly different | OneDrive cleanup only if Downloads is synced (known folder move); block the file hash and origin domain; add the relay host as an indicator if one is found | Done | `nexorainstaller[.]com` and the SHA256 are blocked. No relay host found |
| 10 | Tenant sweep | Same | Sweep for ScreenConnect client processes, the installer name, and the relay host | Done | Only this device and event |

## Queries

### Step 1: Alert details

```kql
AlertEvidence
| where Timestamp > ago(3d)
| where Title has "Wacatac"
| where EntityType in ("File", "Process")
| project Timestamp, AlertId, Title, DeviceName, FileName, FolderPath, SHA1, SHA256, ProcessCommandLine
```

### Step 2: Process execution

```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where DeviceName =~ "<device>"
| where FileName startswith "ScreenConnect"
    or InitiatingProcessFileName startswith "ScreenConnect"
    or ProcessCommandLine has "ScreenConnect"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
```

### Step 3: Antivirus detections for the device

```kql
DeviceEvents
| where Timestamp > ago(3d)
| where DeviceName =~ "<device>"
| where ActionType startswith "Antivirus"
| extend ad = parse_json(AdditionalFields)
| project Timestamp, ActionType, FileName, FolderPath, SHA1,
          ThreatName = tostring(ad.ThreatName),
          WasExecutingWhileDetected = tostring(ad.WasExecutingWhileDetected),
          WasRemediated = tostring(ad.WasRemediated)
| order by Timestamp asc
```

### Step 4: File lifecycle and origin

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "<device>"
| where FileName =~ "ScreenConnect.ClientSetup.exe"
| project Timestamp, ActionType, FileName, FolderPath, SHA1, SHA256,
          FileOriginUrl, FileOriginReferrerUrl, FileOriginIP,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

### Step 5: Network activity

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "<device>"
| where InitiatingProcessFileName startswith "ScreenConnect"
| project Timestamp, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### Step 6: Persistence

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "<device>"
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services\ScreenConnect Client"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

Live Response console commands (the console is not a PowerShell prompt; commands run as SYSTEM, so use explicit paths):

```
services
persistence
processes
connections
scheduledtasks
startupfolders
dir "C:\Program Files (x86)"
dir "C:\Users\<user>\Downloads"
findfile ScreenConnect.ClientSetup.exe
registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
```

Review the `services` and `dir "C:\Program Files (x86)"` output for anything named `ScreenConnect Client (<instance ID>)`. If PowerShell is needed, upload a `.ps1` to the Live Response library and run it with `run <script>.ps1`.

## Findings log

### Steps 1 and 3

- Flagged file: `ScreenConnect.ClientSetup.exe` in the user's Downloads folder
- SHA1: `49d54b55e38b57eca3ff0aec6b5df546e58e8eb2`
- SHA256: `98c841b0b17370cd6a6a263cc79bba002577c64250893b300564340de66e4d5d`
- Threat name: `Trojan:Win32/Wacatac.C!ml` (the `!ml` suffix marks a machine-learning detection)
- `WasExecutingWhileDetected`: false
- `WasRemediated`: true
- Alert evidence covered one device and one file only
- Wacatac fired on the ScreenConnect installer itself, so this is not a separate-file case

### Steps 2, 4, 5, 6

- Step 2: no `msiexec.exe` activity. One row came back with initiating command line `"msedge.exe" --no-startup-window --win-session-start`, which is how Edge launches in the background at sign-in. (corrected below: this row was the installer's own process-creation event)
- Step 4: `FileOriginUrl` is `hxxps://www[.]connect[.]nexorainstaller[.]com/downloads/ScreenConnect.ClientSetup.exe`, `FileOriginReferrerUrl` is `hxxps://www[.]connect[.]nexorainstaller[.]com/`, initiating process `msedge.exe`
- Step 4 file events: FileCreated, FileRenamed, FileDeleted (consistent with a browser download followed by Defender remediation; timestamps and the deleting process still to confirm)
- Step 5: no network results from any ScreenConnect process
- Step 6: no `ScreenConnect Client` service registry key
- Domain check: a web search found no public reporting on `nexorainstaller[.]com`. The vendor's own site is `screenconnect.com`, so this is not an official ScreenConnect or ConnectWise domain. No public reporting is not evidence the domain is safe

### Follow-up

- Correction: the Step 2 row is a process-creation event for `ScreenConnect.ClientSetup.exe` itself, launched from `msedge.exe`. The `--no-startup-window --win-session-start` text is the parent Edge process command line. So the installer was started, and the earlier reading that it never ran does not hold. `WasExecutingWhileDetected` false and `WasRemediated` true suggest Defender stopped it, which the next steps need to confirm
- Tenant sweep for `nexorainstaller` across network events, URL clicks, and email URLs: only this one device and event
- Event time: Advanced Hunting returns UTC, so convert any local portal time to UTC before setting the query window

### Follow-up queries A, B, C

- Query A (Edge connections before the download): the path to the site was a search ad
- Query B (installer process tree): no child processes
- Query C (SmartScreen, antivirus, network protection events): empty. This alone does not show the user was not warned
- Live Response could not be run because the device is offline. Persistence checks fall back to telemetry until it reconnects

### Persistence telemetry checks

- No `ServiceInstalled` events on the device after the launch
- No ScreenConnect client files created (file events query empty)
- No ScreenConnect or ConnectWise software in the vulnerability management inventory
- Device is onboarded; exposure level medium (a vulnerability exposure rating, not an indicator of compromise)
- The user is in a remote location and is being contacted by email to ask what they searched for, what they intended to install, and whether anyone asked them to download it
- `nexorainstaller[.]com` and the SHA256 are blocked in Defender

### Closing checks

- Live Response connected after the device had been offline since the event. Output of `services` and `dir "C:\Program Files (x86)"` showed nothing named `ScreenConnect Client`
- The user replied to the email: no to "did anyone contact you and ask you to download or run something" and no to "did you run anything else from that site or enter passwords or personal information"
- The user did not answer what they searched for or whether they meant to install a remote-access tool. Intent remains unknown; the search ad found in the network telemetry explains the path to the site
- After the domain block, Defender raised a "Connection to a custom network indicator" alert (SmartScreen, `msedge.exe`). It came from the same device after it reconnected, consistent with Edge retrying a restored session. The block worked and nothing was reached
- The queued investigation package and full antivirus scan completed after the device reconnected; both were clean

## Classification and closure criteria

Close only when all of these are true:

- The Wacatac detection is explained (which file, remediated or not).
- No ScreenConnect process execution, service, or install folder exists on the device, or any that does exist is confirmed as sanctioned.
- No outbound connection to a ScreenConnect relay.
- The origin of the download is identified.
- The hash and origin domain are blocked, and the tenant sweep is clean.

## Actions taken

- Blocked `nexorainstaller[.]com` and the installer SHA256 in Defender indicators
- Emailed the user to ask about their search, intent, and whether anyone instructed them to install it; they answered no to being instructed and no to running anything else or entering information
- Live Response run after the device reconnected: no ScreenConnect service or install folder
- Pending: none required for closure; the user's search term and intent are unanswered

## Lessons learned and detection ideas

- A process-creation row for the installer is the evidence of launch. The parent's command line (a background Edge process) is easy to misread as the installer's.
- `WasExecutingWhileDetected` false only describes the moment of detection; confirm launch from process telemetry.
- Hash reputation is weak for per-instance remote-access installers. The download origin (a non-vendor domain reached through a search ad) was the strongest signal.
- Live Response cannot be queued and the console is not a PowerShell prompt. Telemetry (service installs, file events, registry, software inventory) covers persistence while a device is offline.
- Candidate detections: a browser download of `ScreenConnect.ClientSetup.exe` where `FileOriginUrl` is not on an approved vendor or MSP domain list; launch of `ScreenConnect.ClientSetup.exe` from a Downloads path by a browser parent.
- Candidate controls: web content filtering or URL indicators for newly seen lookalike installer domains; an application control policy that allows only sanctioned remote-support tools; user guidance on installing software from search ads.
