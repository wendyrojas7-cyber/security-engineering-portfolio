**Use this when:** Defender XDR blocks or quarantines a remote-access or RMM installer (for example `ScreenConnect.ClientSetup.exe`), or flags a file with a generic detection such as `Trojan:Win32/Wacatac.C!ml`, and the file sits in a user's Downloads folder or another user-writable location.

**Do not use this for:** a known-bad hash with a named malware family (use the known-malware triage guidebook), or an RMM tool that is sanctioned in your environment and used by IT (verify with IT first).

## Why this differs from a known-malware triage

- A remote-access installer is a legitimate tool when it comes from the right source. A hash lookup often says nothing, because many installers are generated per server instance, may carry a valid signature, and have a unique hash.
- A generic machine-learning detection (the `!ml` suffix) is heuristic. It can fire on a legitimate but unusual installer, so it supports a decision but should not make it.
- The questions that decide severity are: where did the file come from, was it launched, and did anything connect to a relay or install a service.
- Persistence looks different. The signs are a `ScreenConnect Client (<instance ID>)` service and a `Program Files (x86)\ScreenConnect Client (...)` folder, not startup entries or scheduled tasks.

## Placeholders

Replace `<device>`, `<user>`, `<user UPN>`, and `t` (the event time, in UTC; Advanced Hunting returns UTC) before running anything.

## Step 1: Read the alert

Record the flagged file, SHA1, SHA256, folder path, threat name, and the device. Confirm whether the detection was on the remote-access installer itself or on a different file.

```kql
AlertEvidence
| where Timestamp > ago(3d)
| where Title has "<threat name>"
| where EntityType in ("File", "Process")
| project Timestamp, AlertId, Title, DeviceName, FileName, FolderPath, SHA1, SHA256, ProcessCommandLine
```

## Step 2: Antivirus detections for the device

Query by device and time window, not by hash or filename, because hash and filename filters miss events.

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

`WasExecutingWhileDetected` false means the file was not running at the moment of detection. It does not mean the file never ran. Do not stop here.

## Step 3: Was the installer launched?

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

How to read it:

- A row where `FileName` is the installer means it was launched. The `InitiatingProcessCommandLine` belongs to the parent (for example a background Edge process), not to the installer.
- No `msiexec.exe` and no child processes is a good sign. Check children explicitly:

```kql
let t = datetime(<event time UTC>);
DeviceProcessEvents
| where Timestamp between (t - 30m .. t + 2h)
| where DeviceName =~ "<device>"
| where FileName =~ "ScreenConnect.ClientSetup.exe"
    or InitiatingProcessFileName =~ "ScreenConnect.ClientSetup.exe"
    or InitiatingProcessParentFileName =~ "ScreenConnect.ClientSetup.exe"
| project Timestamp, FileName, ProcessCommandLine, ProcessId, ProcessIntegrityLevel, InitiatingProcessFileName, AccountName
```

## Step 4: Where did the file come from?

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

- The vendor's own site is `screenconnect.com`. A different domain, especially a lookalike "installer" domain, is a strong sign of a malicious source.
- FileCreated, FileRenamed, FileDeleted from a browser is the normal pattern of a download that was then removed by Defender. Confirm which process did the delete.
- Web-search the domain, but treat missing reports as unknown, not safe. Do not browse to it from a work machine.

How the user reached the site (the ten minutes before the download):

```kql
let t = datetime(<event time UTC>);
DeviceNetworkEvents
| where Timestamp between (t - 15m .. t + 5m)
| where DeviceName =~ "<device>"
| where InitiatingProcessFileName =~ "msedge.exe" and isnotempty(RemoteUrl)
| summarize FirstSeen=min(Timestamp), Hits=count() by RemoteUrl
| order by FirstSeen asc
```

Look for a search engine, an ad redirect, or an email link before the download. Adjust the browser process name for your environment.

## Step 5: Network activity

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "<device>"
| where InitiatingProcessFileName startswith "ScreenConnect"
| project Timestamp, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Any connection from a ScreenConnect process means a possible relay connection. Record the host and treat it as an indicator.

## Step 6: Persistence

### From telemetry (works when the device is offline)

```kql
let t = datetime(<event time UTC>);
union
(DeviceEvents
 | where Timestamp > t - 30m and DeviceName =~ "<device>"
 | where ActionType == "ServiceInstalled"
 | project Timestamp, Kind="ServiceInstalled", Detail=tostring(AdditionalFields), FileName, FolderPath),
(DeviceFileEvents
 | where Timestamp > t - 30m and DeviceName =~ "<device>"
 | where FolderPath has "ScreenConnect Client" or FileName startswith "ScreenConnect."
 | project Timestamp, Kind=ActionType, Detail=InitiatingProcessFileName, FileName, FolderPath)
| order by Timestamp asc
```

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "<device>"
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services\ScreenConnect Client"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

```kql
DeviceTvmSoftwareInventory
| where DeviceName =~ "<device>" and SoftwareName has_any ("screenconnect", "connectwise")
| project DeviceName, SoftwareName, SoftwareVersion
```

### Live Response (when the device is online)

The Live Response console is not a PowerShell prompt. PowerShell only runs through an uploaded script (`run script.ps1`). Commands run as SYSTEM, so use explicit `C:\Users\<user>\...` paths, because `%LOCALAPPDATA%` resolves to the SYSTEM profile and gives false negatives.

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

Look for a service or folder named `ScreenConnect Client (<instance ID>)`.

### If the device is offline

- Queue an investigation package and a full antivirus scan from the portal. Both run when the device reconnects.
- Live Response cannot be queued, so repeat the console checks manually once the device is online.
- Check `DeviceInfo` for the last time it reported in. If it has not been on since the event, say so in the notes.

## Step 7: Tenant sweep

```kql
union
(DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has "<domain keyword>"
 | project Timestamp, Source="Network", DeviceName, Account=InitiatingProcessAccountName, Detail=RemoteUrl),
(UrlClickEvents | where Timestamp > ago(30d) | where Url has "<domain keyword>"
 | project Timestamp, Source="UrlClick", DeviceName="", Account=AccountUpn, Detail=Url),
(EmailUrlInfo | where Timestamp > ago(30d) | where UrlDomain has "<domain keyword>"
 | project Timestamp, Source="EmailUrl", DeviceName="", Account="", Detail=Url)
| order by Timestamp asc
```

Also sweep for the installer name and any relay host found in Step 5.

## Step 8: Review the account

Check sign-ins around and after the event, and other alerts on the account. Adjust the table to your setup (`SigninLogs` in Sentinel, or `EntraIdSignInEvents` in Defender XDR).

```kql
SigninLogs
| where TimeGenerated > ago(5d)
| where UserPrincipalName =~ "<user UPN>"
| summarize Attempts=count(), Failures=countif(ResultType != "0"),
            IPs=make_set(IPAddress, 10), Countries=make_set(tostring(LocationDetails.countryOrRegion), 10),
            Apps=make_set(AppDisplayName, 10) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

Look for new countries or IPs, failures followed by successes, and sign-ins that do not fit the user's normal pattern.

## Step 9: Contact the user

Ask four things, in neutral wording that does not blame:

1. Did you search for something and click a result or ad around that time, and what were you looking for?
2. Were you trying to install a remote support or remote access tool?
3. Did anyone contact you (call, chat, email, pop-up) and ask you to download or run something?
4. Did you run anything else from that site, or enter any passwords or personal information?

A "yes" to question 3 or 4 changes the classification: treat it as social engineering or credential exposure, reset credentials, and review sessions. If there is no reply, try another channel (phone, manager) and set a deadline in the ticket.

## Step 10: Contain and block

- Add a Defender URL or domain indicator for the whole domain, not only the subdomain.
- Add a file hash indicator (block and remediate) for the SHA256.
- Add the relay host as an indicator if one was found.
- If Downloads is synced to OneDrive (known folder move), remove the cloud copy and empty the recycle bins. Otherwise skip this.
- Report the malicious ad or domain through the search engine's and registrar's abuse channels if your process allows it.
- Consider isolating the device while checks are pending, particularly if it is offline and cannot be verified.

## Classification

Decide using these outcomes, in order.

1. **Blocked before launch.** No process-creation event for the installer; file quarantined. Classify as true positive, malware or PUA, prevented. Close after blocks and tenant sweep.
2. **Launched and stopped.** Process-creation event for the installer, but no child processes, no network from ScreenConnect processes, no service, no client files, and a clean account review. Classify as true positive, malicious installer, prevented with no compromise. Close only after the user is contacted and, if the device was offline, the Live Response or package check is clean.
3. **Installed or connected.** Any of: a ScreenConnect service or folder, child processes, a connection to a relay, or credentials entered on the site. Treat as a compromise. Isolate the device, collect an investigation package, reset credentials, review the account and any other systems the user can reach, and escalate to incident response.
4. **Sanctioned tool.** The file came from the correct vendor or from a known IT or MSP source and the user or IT confirms it. Record the source, decide whether the detection is a false positive or a PUA to allowlist, and document the approval.

If any check could not be run, say so in the notes and keep the case open until it is run or a reviewer accepts the gap.

## Closure criteria

Close only when all of these are true:

- The detection is explained: which file, and whether it was remediated.
- Whether the installer was launched is established from process telemetry.
- No ScreenConnect service, client files, child processes, or relay connections exist, or any that exist are confirmed as sanctioned.
- The download source is identified and the domain and hash are blocked.
- The tenant sweep is complete.
- The account review is clean.
- The user has been contacted, or the escalation path was followed.
- Live Response or an investigation package has been run, or the gap has been recorded and accepted.

## Incident notes template

`<Threat name>` detection on `<file name>` (SHA1 `<hash>`, SHA256 `<hash>`) on `<device>` in `<folder path>`. The file came from `<origin domain>` after `<search ad / email / other>`. `WasExecutingWhileDetected` was `<value>` and `WasRemediated` was `<value>`. The installer `<was / was not>` launched at `<time>`. No child processes, network activity from ScreenConnect processes, service installs, or client files were found `<or: describe findings>`. Tenant sweep: `<result>`. Account review: `<result>`. User contact: `<summary>`. Live Response or investigation package: `<result or pending>`. Actions: domain and SHA256 blocked `<other actions>`. Classification: `<outcome from this guidebook>`.

## Changes from the known-malware triage guidebook

| Area | Known-malware triage | This guidebook |
|---|---|---|
| Starting point | Hash with a named family | Generic detection plus a remote-access installer |
| Hash lookup | Informative | Often uninformative (per-instance installers) |
| Key question | Did the file run | Where did it come from, did it launch, did anything connect |
| Persistence signs | Startup entries, scheduled tasks, dropped runtimes | ScreenConnect service and install folder, relay connections |
| Cloud cleanup | OneDrive copy and recycle bins | Only if Downloads is synced |
| Offline device | Not covered | Telemetry fallback and queued actions |
| User contact | Source of the download | Search ad, intent, and whether anyone instructed the download |
