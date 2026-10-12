# SWUpdater / CoinMiner Investigation Tracker

Living document. Update as each check is completed. Strip device, user and date details before publishing to the portfolio; use defanged indicators.

## Case summary

- **Trigger:** Defender alert, CoinMiner prevented, file `swupdater.dll` quarantined (`Trojan:Win64/CoinMiner!rfn`)
- **Software:** Wave Browser (publisher Wavesor Software / Eightpoint Technologies Ltd. SEZC), user-profile install under a `Wavesor Software` folder, signed
- **Scope:** 3 devices in the tenant
- **Working classification:** PUA with miner payload. No proof of mining yet (no pool traffic seen), but the updater has repeatedly loaded a miner-flagged DLL. The software has been installed for years on all three devices (2021 to 2025), and VT vendors have flagged both DLL hashes only since August
- **Status:** CLOSED as PUA removal with prevented miner payload on three devices. Install source recorded as unknown (installs date from 2021 to 2025, outside the 30-day hunting window). Post-cleanup activity query and next-day tenant sweep both returned nothing. Housekeeping items below remain open and are not blockers

## Why this differs from the Wacatac / TamperedChef cases

| Prior cases | This case |
|---|---|
| One file, one device, prevented before execution | Installed for years (2021 to 2025), persistent, running on 3 devices |
| Source was a download with `FileOriginUrl` | `FileOriginUrl` empty, so the installer dropped the files. Find the creating process instead |
| Quarantine closed the case | Quarantine removes only the DLL. EXE, browser and scheduled tasks remain |
| Detection field showed state | `WasExecutingWhileDetected = false` is misleading: DLL was loaded 27 to 34 times per device |

## Device table

| Device | Role | DLL hash(es) | Install | Activity | Detected | Remediated | Network (F) | Status |
|---|---|---|---|---|---|---|---|---|
| A | Alerting device | `b21f…` only (never had `fb24…`) | 12/27/2021 (Live Response). The Sept 15 events were task registration | Running through this month | `b21f…` only | Quarantine only. Cleanup pending | Only `swupdater[.]com` | Open |
| B | Second device | `fb24…` | 8/24/2025 | September only, nothing this month | No | No | Confirm per device | Open |
| C | Third device | `fb24…` | 12/28/2022 | Running | No | No | Confirm per device | Open |

## Hashes

| SHA256 | VT | Microsoft | Notes |
|---|---|---|---|
| `fb241530e3d716c753be0141376ab8974e812aa62facbfda251c67a60d7720a7` | 5/70, adware (applicunwnt) | Not detected | `swupdater.dll`, 1.02 MB, signed. Present on Devices B and C only. Both devices had it, and it was detected by VT vendors back in August |
| `b21f99f14b4ccc78c5e01c269a8eba83ae0c5912b46d8c1554f329a1076a7617` | 8/71, adware / miner / trojan | `Trojan:Win64/CoinMiner!rfn` | `swupdater.dll`, 1.02 MB, signed. Present on Device A only. Same size as `fb24…`, so likely a small variant. Also detected by VT vendors back in August |

Signer: Eightpoint Technologies Ltd. SEZC (branded Wavesor Software). Compare certificate thumbprints between the two DLLs before building the certificate indicator.

## Binaries spawned by swupdater.exe (Query E, hashes confirmed by matching VirusTotal lookups)

| SHA256 | Process | Command line | VT |
|---|---|---|---|
| `bacdf346ce1d095c00dcd58de15f00a5948f30d50c71fee979b7afd29843e08e` | `SWUpdater.exe` | `/ping`, `/cr` | 9/71, adware / PUA (wavebrowser family), 108 KB |
| `02f6094b5d14e880a1fb7eef90228dbb34102788b5e513836750f90894dde185` | `SWUpdater.exe` | `/ping`, `/cr` | 6/69, adware (wavebrowser family), 105 KB |
| `792257eefdbad7ceb22121f93e0f23a615eb347d743eb339413299c8642ea3b3` | `WaveInstaller-v1.5.26.3…` | (not shown) | 3/65, adware (adaptbrowser label), 107.57 MB. Sandbox Sigma matches: PE creation, new root/CA certificate added to store, proxy ZoneMap registry change |

## Indicators (defanged)

- Domain: `swupdater[.]com` (AWS-hosted, check IP `52.6.115.246` against TI)
- Scheduled task: `\Wavesor Software_<SID>\WaveBrowser-StartAtLogin`
- Folder: `C:\Users\<user>\Wavesor Software\`
- Process chain: `swupdater.exe` loads `swupdater.dll`

## Findings log

- Install on Device A and tasks created at install, then 2 more scheduled tasks about a week later (updater refreshing persistence)
- Registry key creation as SYSTEM
- `FileOriginUrl` empty on all three devices (dropped by an installer, not a browser download)
- Tenant sweep: two other users with the same software, several SHA256s
- `swupdater.exe` loaded the DLL, not the browser. Loads per device 27 to 34
- `WasExecutingWhileDetected` false, `WasRemediated` true, on Device A only
- Query B (Wave Browser and updater network): Google ranges, `gum[.]criteo[.]com`, internal host on port 10000, `swupdater[.]com` only for the updater. No pool domains
- Query C (miner command-line strings): empty
- Query F (all `swupdater.exe` destinations): only `swupdater[.]com`
- Hash distribution: Device A only ever had `b21f…`. Devices B and C had `fb24…`. No device shows a swap from one hash to the other, so there is no evidence the updater replaces DLLs after install (see corrections log)
- Two builds of the same signed DLL are in the tenant. Only `b21f…` is detected by Microsoft. `fb24…` is undetected by Microsoft but shares size and signer, so it is treated as the same threat until behavior says otherwise
- Browser used for webmail and an internal web app on port 10000
- Query E: `swupdater.exe` only spawned copies of itself (`/ping` and `/cr` switches) and a WaveInstaller binary. Nothing resembling a miner or shell
- Query G: empty, no injection events
- `WaveBrowser-StartAtLogin` command: `wavebrowser.exe --strtl=wts`. Ordinary browser autostart
- Hash lookups: both `SWUpdater.exe` copies and the installer are adware/PUA, not labeled miner. Only the `b21f…` DLL carries the miner label
- WaveInstaller appears only on B and C (the `fb24…` devices). Query E showed it was spawned from the updater's side, so it is probably an update or reinstall launched by the updater, not the original install source (assumption, to confirm with the parent process)
- Installer file activity: B on Sept 29, C on Oct 2, each with the same four events (file deleted, created, created, deleted). Pattern looks like drop, run, clean up
- Cleanup note: the updater can relaunch a full installer, so block `swupdater[.]com` and remove the tasks before deleting the folder, or it may reinstall
- Root/CA certificate query: empty. The sandbox Sigma match for the installer was not seen on the devices
- Installer parent and command line: `swupdater.exe`. Confirms it is updater-launched
- DLL hash unchanged on B and C after the installer ran, so reinstalls do not swap the DLL. The `fb24…` / `b21f…` difference between devices is still unexplained, and the original install source is still unknown
- First-seen event on the earliest device is Sept 15 with no `FileOriginUrl` or referrer, so the source was not a browser download
- TI on `swupdater[.]com`: Talos has nothing, VT has a single malicious verdict. Weak signal either way. The domain is the PUA vendor's own updater host, so intel feeds may not label it as C2
- First-seen file event creator was the Task Scheduler service. Likely a task definition file, so the original installer is still unidentified
- VT Relations tab was not available in the analyst's view, so domain relations are unchecked
- CPU snapshot on Device A (Live Response): top processes at 5% and 0%. `wavebrowser` running (multi-process, normal for a Chromium browser) but not a top consumer. Third device could not be reached
- WHOIS and reputation on `swupdater[.]com`: registered Dec 2020, Amazon Registrar, privacy-protected, high Tranco rank, Malwarebytes verdict unknown. Vendor-owned update host with a large installed base
- Task creation events carry no creator information. User-profile file creation rows exist only for B and C, so Device A's install likely predates the retention window
- Install dates from Live Response: Device A 12/27/2021. The other two devices: 12/28/2022 and 8/24/2025 (the 8/24/2025 one is the machine that had been offline). Device B is the 8/24/2025 install (the machine that had been offline) and Device C is the 12/28/2022 install. Likely the registry InstallDate field
- The installers launched by `swupdater.exe` on Sept 29 and Oct 2 are therefore updater-driven reinstalls on long-standing installs, not first installs
- CPU check clean on all three devices
- Cleanup script ran on all three devices and ended with "Done". EXE hashes are now blocked too. Post-cleanup verification (events since cleanup, software inventory, a later re-sweep) is pending
- Post-cleanup activity query returned nothing once enough time had passed. The earlier failed connections to the blocked domain were the tail of the cleanup. Software inventory still lists the three devices, which is expected from delayed reporting and from the uninstall registry entries not being removed
- Evidence so far leans PUA without active mining (no pool traffic, no child processes, no injection). Not yet closed: CPU check, remaining tasks, sibling hash lookups, per-device F on B and C

## Open checks

| # | Check | Status | Result |
|---|---|---|---|
| 1 | Creating process and parent on install day, per device (drop the date filter) | Open | |
| 2 | Query E: child processes of `swupdater.exe` | Done | Only 3 new SHA256s: two `SWUpdater.exe` copies launched with `/ping` and `/cr`, and one `WaveInstaller` binary. No shells, script hosts or miner-like processes |
| 3 | Query G: injection and memory events | Done | Empty. No injection or remote thread events from `swupdater.exe` or `wavebrowser.exe` |
| 2b | Look up the 3 spawned SHA256s (VT) | Done | All three adware/PUA (wavebrowser family, installer labeled adaptbrowser). None labeled miner. Defender file page still to check |
| 2c | WaveInstaller: creating process, parent, command line and any `FileOriginUrl` per device | Closed | Seen on Devices B and C only, not on A. File events on B: 4 events (deleted, created, created, deleted) on Sept 29. Same 4 events on C on Oct 2. Parent and command line confirmed as `swupdater.exe`, so the installer is updater-launched (update or reinstall), not the original install source. Still need FolderPath for the four file events |
| 2d | Root certificate check: did the installer or updater add certificates to the machine root, AuthRoot or CA stores (queries below) | Done | Query returned nothing. No root, AuthRoot or CA changes from Wavesor processes |
| 2e | DLL hash vs installer run: on B and C, did the loaded DLL hash change after the installer ran | Done | No change. The updater-launched installer did not swap the DLL |
| 2f | Original install source per device: earliest file creation in the Wavesor folder, with creating process and parent. Save the output into this tracker | Done (source unknown) | Earliest device first seen Sept 15, inside the 30-day window. `FileOriginUrl` and referrer empty, so not a browser download. First-seen row creator is `svchost.exe -k netsvcs -p -s Schedule` (parent `services.exe`), the Task Scheduler service. That is probably the task definition file under System32\Tasks (path contains the vendor name), not the install itself. Confirm with the row's FolderPath. The `ScheduledTaskCreated` initiating-process query returned no creator information. The user-profile file query returned rows only for the non-alerted devices (B and C), which suggests Device A's profile-folder file creation predates the 30-day window. To get the true install date, read the folder creation time and the uninstall registry entry via Live Response. Result: install dates 12/27/2021 (Device A), 12/28/2022 and 8/24/2025 (the other two). All predate the 30-day window, so the original source is recorded as unknown unless Sentinel holds older telemetry. Advanced Hunting keeps 30 days, so the mid-Sept install events on A age out around Oct 15. Capture now. Use `arg_min` per device on file creation in the Wavesor folder, then list file events around that first timestamp. If the first-seen time sits at the very start of the 30-day window, the real install may predate it |
| 4 | Confirm Query F covered Devices B and C | Done | Result listed all three devices. Only `swupdater[.]com` on each |
| 5 | Name and command of all 4 scheduled tasks (`AdditionalFields`) | Done | All four task events run the same command, `wavebrowser.exe --strtl=wts` (browser autostart). No separate updater task seen. The repeat registrations (two at install, two about a week later) are probably the same autostart task being re-registered, so the earlier "updater refreshing persistence" reading is weaker than first thought |
| 6 | Why the builds differ: compare install dates and installer source per device (did A get a newer or different installer than B and C) | Closed, unexplained | Install dates differ by years (2021, 2022, 2025) and the source is unknown, so the reason the alerting device holds a different DLL build is not established. Treated as separate builds of the same signed component |
| 6b | Check whether any device's DLL hash changes over time (file writer history per device) | Closed | No hash change observed on B or C after the updater-launched installer ran. A only ever showed one hash within the window |
| 7 | CPU check or user report of slowness (Live Response / Task Manager) | In progress | Live Response: upload a .ps1 to the library, then `run` it (raw PowerShell does not work in the console). Device must be online. Compare cumulative CPU to process start time for `swupdater` and `wavebrowser`. Device A: one snapshot, top consumers at 5% and 0%, `wavebrowser` running but not a top consumer, no miner-like load. The other two devices (including the one that had been offline) were also checked later: nothing unusual. CPU check clean on all three |
| 8 | TI lookup: `swupdater[.]com`, its IP | Done (limited) | Talos: no data. VT: 1 vendor malicious. Malwarebytes: unknown verdict, domain ranked about #64,800 in Tranco. WHOIS: registered Dec 2020 through Amazon Registrar, privacy-protected, AWS nameservers. An established vendor update domain, not a throwaway. VT Relations tab was unavailable in the analyst's view |
| 9 | Submit `fb24…` to Microsoft as a missed detection | Open | |
| 10 | Compare certificate thumbprints for both DLLs | Open | |
| 11 | Internal app on port 10000: review that user's activity, consider credential reset | Open | |
| 12 | Neutral conversation with users about where the software came from | Open | |

## Actions

**Containment**
- [x] Custom network indicator for `swupdater[.]com`
- [x] File indicators: DLL and EXE hashes blocked
- [ ] Certificate indicator for the Eightpoint / Wavesor signer
- [ ] PUA protection set to block (Intune)

**Evidence first**
- [x] Investigation package on all 3 devices before cleanup
- [x] Full AV scan on all 3 devices

**Remediation (each device)**
- [x] Uninstall Wave Browser, delete the Wavesor folder (cleanup script, all three devices)
- [x] Remove `WaveBrowser-StartAtLogin` and the other Wavesor tasks (cleanup script)
- [x] Run key values removed by the script (loaded user hives and machine keys). Uninstall registry entries not touched
- [ ] Check profile and Temp for other leftovers
- [x] Device B: the previously offline install was cleaned when it came online

**Accounts**
- [ ] Password reset for accounts used in Wave Browser
- [ ] Sign-in log review for those accounts
- [ ] Review the port 10000 app for that user

## Closure criteria

Close as PUA removal with prevented miner only when all are true:

- [x] Queries E and G show no unexpected child processes or injection
- [x] Query F is clean on every device (only `swupdater[.]com`)
- [x] No miner-like CPU activity (checked on all three devices)
- [x] All tasks, folders and Run values are removed on all 3 devices (script verification section empty). Uninstall registry entries were not removed
- [x] Hashes and domain are blocked. The signer certificate indicator is not confirmed
- [x] Re-sweep shows nothing (post-cleanup query and next-day sweep both empty)
- [x] The install source is documented as unknown

**Housekeeping, not blockers:** certificate indicator for the signer, PUA protection in block mode, certificate thumbprint comparison, submitting the undetected DLL hash to Microsoft, credential reset and sign-in review for accounts used in the browser, review of the internal app reached through it, neutral conversation with the users, removal of leftover uninstall registry entries.

Escalate to compromise (isolate, Live Response) if any device shows pool traffic, an unexpected child process, injection, or high CPU from these processes.

## Lessons and detection ideas

- A signed binary is not a clean binary. A PUA updater signed by its publisher can ship miner payloads, and different devices may get different builds
- `WasExecutingWhileDetected` describes only the moment of detection. Use `DeviceImageLoadEvents` to see if a DLL ever ran
- An empty `FileOriginUrl` points to a dropped file. Query the creating process
- A detection on one device does not cover its sibling hash. Check VirusTotal and submit missed variants
- Empty `RemoteUrl` can hide pool traffic, so also query by IP and port
- Detection ideas: scheduled tasks under a `Wavesor` folder, image loads of `swupdater.dll`, `swupdater.exe` writing DLLs to its own folder
- Advanced Hunting keeps only 30 days. For the age and source of long-lived software, use registry InstallDate and folder creation time via Live Response, and check whether Sentinel holds older device telemetry

## Corrections log

- Earlier reading placed `fb24…` on the alerting device first, followed by a swap to `b21f…`. That was a misreading. Device A only ever had `b21f…`, and the `fb24…` devices are B and C. The "updater swaps the DLL" theory is withdrawn. It is still unknown why the builds differ between devices, and open check 6 covers it
- Earlier entries gave Device A an install date of mid-September. That came from Sept 15 file and task events, which turned out to be task registration by the Task Scheduler service. Device A's actual install date is unknown and probably older than 30 days. The device table is corrected
