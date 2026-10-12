# Runbook: Signed PUA Updater Loading a Miner-Flagged File

Triage and cleanup procedure for Microsoft Defender XDR when a coin-miner detection fires on a file that belongs to an updater or bundled software, often signed by its publisher.

**Candidate ATT&CK mappings:** T1496 (Resource Hijacking), T1053.005 (Scheduled Task), T1105 (Ingress Tool Transfer, if the updater pulls payloads)

## Why this needs its own runbook

A "CoinMiner prevented, file quarantined" alert looks like a closed case. For one-off dropper cases it often is. When the flagged file belongs to an updater, it usually is not:

| One-off prevented file | Updater or bundled software |
|---|---|
| One file on one device | Installed for months or years, on several devices |
| Download has a `FileOriginUrl` | Empty `FileOriginUrl`, because an installer dropped the files |
| Quarantine ends it | Quarantine removes one file. The updater, browser and tasks remain |
| `WasExecutingWhileDetected` shows state | That field only describes the moment of detection. The file may have loaded dozens of times |
| Signature hints at legitimacy | A signature only names the publisher |

## Principles

- Query by device and time window, not by hash or filename. Advanced Hunting keeps 30 days, so use `ago(30d)`.
- Prove execution with `DeviceImageLoadEvents`, not with the detection fields.
- An empty `RemoteUrl` can hide miner traffic. Summarize by `RemoteIP` and `RemotePort` as well.
- A detection on one device does not cover sibling hashes on other devices. Look up every hash.
- Software older than 30 days needs Live Response for install dates.

## Triage

### 1. Alert evidence
Record the flagged file path, hashes, `ThreatName`, `WasRemediated` and signer. Note the vendor folder in the user profile and which process loads the file.

### 2. Footprint and scope
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "<vendor folder>" or FileName =~ "<updater>.exe"
| summarize Devices=dcount(DeviceId), Users=make_set(InitiatingProcessAccountName) by FolderPath, SHA256
```
Also check `DeviceTvmSoftwareInventory` for the vendor and product name.

### 3. Persistence
```kql
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ScheduledTaskCreated"
| where AdditionalFields has "<vendor>"
| project Timestamp, DeviceName, AdditionalFields, InitiatingProcessFileName
```
Read the task name and command. A task that only starts the browser at login is unwanted-software persistence. Anything else needs a closer look.

### 4. Execution
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d) and FileName =~ "<flagged file>"
| summarize Loads=count(), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, SHA256, InitiatingProcessFileName
```
A load by the updater means the file ran. Compare hashes across devices, because devices can hold different builds of the same file.

### 5. Child processes and injection
```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and InitiatingProcessFileName =~ "<updater>.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256

DeviceEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("<updater>.exe", "<browser>.exe")
| where ActionType has_any ("Injection", "RemoteThread", "VirtualMemory", "ProcessHollowing")
```

### 6. Network
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d) and InitiatingProcessFileName =~ "<updater>.exe"
| summarize Conns=count(), First=min(Timestamp), Last=max(Timestamp), Actions=make_set(ActionType)
    by DeviceName, RemoteIP, RemotePort, RemoteUrl
```
Expected: the vendor's update domain only. Red flags: pool domains, raw public IPs with no URL, pool-style ports (3333, 4444, 5555, 7777, 14444, 8443), long-lived connections to one external IP, failed attempts to reach a pool.

Also hunt for miner command-line strings (`stratum+tcp`, `--donate-level`, `xmrig`). An empty result is weak evidence.

### 7. Reputation
Look up every hash in VirusTotal and the Defender file page. Treat an undetected hash with the same size and signer as part of the same threat. Submit missed detections to Microsoft. A long-lived vendor update domain may have little threat intelligence even though it delivers the unwanted software.

### 8. CPU and install date (Live Response)
Upload a script to the library and `run` it, since raw PowerShell does not work in the console. List top processes by CPU and compare cumulative CPU time to process start time for the updater and browser. For install dates, read the vendor folder creation time and the uninstall registry `InstallDate`.

### 9. Users and accounts
Ask the user where the software came from, in neutral language. Review sign-ins for accounts used in the affected browser and any internal application reached through it. Consider a credential reset.

## Decision table

| Finding | Classification | Action |
|---|---|---|
| Prevented, never loaded, no persistence | Low risk | Clean up and close |
| Loaded repeatedly, persistence present, no pool traffic, child processes or injection, normal CPU | Unwanted software with prevented miner payload | Remediate every device, close after clean re-sweep |
| Pool traffic, unexpected child process, injection or sustained high CPU | Possible compromise | Isolate, investigation package, Live Response |

## Containment

1. Block the updater domain as a custom network indicator.
2. Block every hash seen (flagged files, updater executables, installers).
3. Add a certificate indicator for the signer after comparing thumbprints.
4. Set PUA protection to block.
5. Collect an investigation package and run a full scan before cleanup.

## Remediation

The updater can relaunch an installer, so order matters: **block the domain, remove the scheduled tasks, then delete the folder.**

Run a Live Response script with a preview mode that lists what it would remove and changes nothing, then run it with a remove switch. The script should:

- stop processes running from the vendor folder
- unregister the tasks and delete their task folders
- delete the vendor folder in every profile under `C:\Users`
- remove Run key values that reference the vendor
- end with a section listing anything that remains

Uninstall registry entries can remain, so the device may stay in software inventory until they are removed.

## Verification

- The script's "remaining" section is empty on every device.
- No vendor folder, updater or flagged-file activity since the cleanup.
- A tenant re-sweep the next day is clean, and software inventory (which reports on a delay) clears.
- No new alerts on the software after cleanup.

Failed connections to the blocked domain shortly after cleanup are the block working. Continued attempts after cleanup mean something is still running.

## Closure criteria

Close only when all are true:

- No unexpected child processes or injection
- Network activity limited to the vendor domain
- Normal CPU on every device
- Tasks, folders and Run values removed on every device
- Hashes and domain blocked, re-sweep clean
- Install source identified, or documented as unknown

## Lessons learned

- A signed binary is not a clean binary. A PUA updater can ship miner-flagged payloads.
- Quarantine of one file is not closure when an updater and persistence remain.
- Detection fields describe the moment of detection. Image-load events show what ran.
- Sibling hashes can sit undetected on other devices. Look up every hash.
- Thirty days of hunting data cannot date a long-lived install. Use Live Response.

## Detection ideas

- Scheduled tasks created under a vendor-named task folder for known unwanted software
- Image loads of an updater-named DLL by its own updater from a user profile path
- An updater executable writing DLLs into its own user-profile folder

## Example indicators (defanged)

- Update domain from the original case: `swupdater[.]com`
- Pattern: browser-bundled updater in a user-profile folder, autostart scheduled task, signed DLL flagged as a coin miner
