# Sentinel Workbook — Entity Investigation

A parameter-driven pivot workbook: type in an account and host, and every panel below re-filters live against that entity. Where the [Detections Overview workbook](./detections-overview.json) answers "what's firing overall," this one answers "give me everything tied to *this specific account/host*" — the workbook an analyst opens mid-investigation after an incident lands in the queue.

**File:** [`entity-investigation.json`](./entity-investigation.json)
**Data source:** `soc-lab-sentinel-workspace` (Log Analytics, Analytics tier)
**Underlying tables:** `Event` (Windows Security/Sysmon), `Syslog` (Linux SSH auth + `auditd` via `audispd`)

## Parameters

- **Account** (required, text) — e.g. `Jackal`, `analyst`
- **Host** (text) — e.g. `WIN11-SOC-Endpoint`, `ubuntu-soc-agent`

Both parameters are substituted directly into every query below as `{Account}` / `{Host}`.

## Panels

### Sign-In Activity
Cross-platform union of authentication events: Windows EventID 4624 (Security log) and Linux SSH authentication (`Syslog`, `sshd`), covering both successful and failed logins on the Linux side. Two structurally different logging models — Windows event IDs vs. Linux `sshd` log lines — normalized into one common table (`TimeGenerated`, `Computer`, `Account`, `EventType`, `Detail`).

### Process Execution (Cross-Platform)
Cross-platform union of process creation: Windows Sysmon EventID 1 (filtered to the project's tracked LOLBIN set — `powershell.exe`, `cmd.exe`, `certutil.exe`, `rundll32.exe`) and Linux `auditd` execve events forwarded via `audisp-syslog` (filtered to `nc`, `curl`, `wget`, `python3`, `bash`). This is the panel that took real infrastructure work to make possible — see [Drill 4's write-up](../drills/drill-04-linux-lolbin.md) for the full story of building Linux process-level telemetry from nothing.

## Design Notes

- **Why parameters, not hardcoded entities:** this workbook is meant to be opened *during* an investigation, pivoting on whatever incident just fired — not rebuilt each time for a specific account/host pair.
- **Validated against two real entity pairs**, pulled from actual Phase E incidents: `Jackal` / `WIN11-SOC-Endpoint` (Incident 27, Drill 3) and `analyst` / `ubuntu-soc-agent` (Incident 20, Drill 1; also Drill 4's Linux LOLBIN activity).
- **KQL note:** both cross-platform queries use `has` for most substring checks, but the `has` operator is token-based and fails silently on unbroken/hex-encoded strings (discovered during Drill 4). Nothing in this workbook currently searches hex-encoded content, so `has` is safe here — but any future extension matching encoded payloads should use `contains` instead, per Drill 4's findings.
