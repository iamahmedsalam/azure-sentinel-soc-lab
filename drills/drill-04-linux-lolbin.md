# Drill 4 — Linux LOLBIN Execution & Reverse Shell Detection

## Why This Drill Exists

While building the Entity Investigation workbook (Phase E), a real gap surfaced: process-execution telemetry only existed for the Windows endpoint (Sysmon). The Ubuntu SOC Agent had strong authentication visibility (SSH sign-ins, via Syslog) but **no equivalent to Sysmon's EventID 1** — meaning an attacker who compromised the Linux host and ran `bash`, `nc`, `curl`, `wget`, or `python3` would have gone completely unseen at the process level, on both Wazuh and Sentinel.

This wasn't a deliberate scope decision — it was drift. Sysmon on Windows already existed richly instrumented from earlier phases, so every new Windows-side detection built naturally on data that was already flowing. Nobody asked "what's the Linux equivalent of Sysmon" until this drill's planning surfaced it directly. Given real enterprise environments run substantial Linux infrastructure, this was a legitimate blind spot worth closing rather than documenting away — so Project 5's scope was extended to build genuine Linux process-visibility, end to end, rather than settling for a Windows-only story.

## Infrastructure Built

### 1. Process-Level Auditing — `auditd`

Installed and configured on the Ubuntu SOC Agent VM, with an `execve` syscall rule (the Linux equivalent of Sysmon watching process creation):

```bash
sudo apt install auditd audispd-plugins -y
sudo auditctl -a always,exit -F arch=b64 -S execve -k lolbin_exec
```

Persisted via `/etc/audit/rules.d/audit.rules`. Log rotation capacity was increased (`max_log_file = 50`, `num_logs = 10`) after the original 8MB/5-file default filled within an hour under real system load — a legitimate operational tuning issue, not a security-relevant one. Notably: blanket-excluding noisy background processes (Azure Monitor Agent's constant `ps aux` health checks) was considered and rejected — `ps` enumeration is MITRE T1057 (Process Discovery), a real attacker technique, and suppressing it at the collection layer would blind detection for both noise and genuine attackers alike. Capacity was fixed at the infrastructure layer instead; alert-level noise reduction (if ever needed) belongs downstream, in rule logic — never in what gets recorded.

### 2. Local-to-Wazuh Pipeline

`auditd` writes directly to `/var/log/audit/audit.log`, tailed by the Wazuh agent via a new `<localfile>` block in `ossec.conf`. Wazuh's built-in `auditd` decoder parsed events automatically (confirmed working via its existing rule 92604, which already alerts on `ps` enumeration).

### 3. Local-to-Sentinel Pipeline

No built-in Sentinel ingestion path existed for `auditd` data. Rather than build new Azure infrastructure, the `audisp-syslog` plugin (part of `audispd-plugins`) was enabled to forward every audit event into local syslog under the `LOG_AUTH` facility — the same facility the existing Azure Monitor Agent pipeline already forwards (proven by SSH sign-in events reaching Sentinel's `Syslog` table since Drill 1). This let new telemetry ride existing infrastructure with zero new Azure-side configuration.

```
# /etc/audit/plugins.d/syslog.conf
active = yes
args = LOG_INFO LOG_AUTH
```

## Wazuh Custom Rules (100021–100025)

| Rule ID | Detects | MITRE | Level |
|---|---|---|---|
| 100021 | `nc`/`netcat` execution | T1105, T1219 | 12 |
| 100022 | `curl` execution | T1105 | 10 |
| 100023 | `wget` execution | T1105 | 10 |
| 100024 | `python3` execution | T1059.006 | 12 |
| 100025 | `bash` `/dev/tcp` reverse-shell pattern | T1059.004 | 14 |

**Design note on `bash`:** unlike `nc`/`curl`/`wget`/`python3` (rare enough that presence-based matching is reasonable), `bash` is the default interactive shell — matching on presence alone would fire constantly and become noise an analyst learns to ignore. Rule 100025 instead matches a known-malicious *pattern* (`/dev/tcp` — a bash built-in almost exclusively seen in reverse-shell one-liners) rather than mere invocation.

**Real bug found and fixed during build:** `auditd` hex-encodes any `EXECVE` argument containing shell metacharacters (`>`, `;`, quotes, etc.) — meaning the literal string `/dev/tcp/` never appears in plain text for a real reverse-shell command; it appears as `2F6465762F7463702F`. Rule 100025 matches both forms. This is also, notably, close to the common case for genuine attacks — a plain, unencoded `/dev/tcp` reference is the *unusual* case; real reverse shells almost always trigger the encoding.

**Second bug found and fixed:** the initial rule draft used `<field name="audit.execve.a0">`, which is only populated when Wazuh's decoder can parse a quote-wrapped value — unreliable across the `SYSCALL`/`EXECVE` record split. Rules were rewritten against `audit.command` (a `SYSCALL`-record field, reliably populated) and, for the reverse-shell pattern specifically, `<match>` against the full raw log text rather than a named field.

## Sentinel Query 7

Mirrors Query 3's sign-in correlation design, extended for Linux:

```kql
let LinuxSignins = Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted password"
| extend Account = extract(@"Accepted password for (\S+)", 1, SyslogMessage)
| project SignInTime = TimeGenerated, Computer, Account;
let LinuxLOLBIN = Syslog
| where ProcessName == "audispd"
| where SyslogMessage has "type=SYSCALL"
| where SyslogMessage has "success=yes"
| where SyslogMessage has_any ("comm=\"nc\"", "comm=\"curl\"", "comm=\"wget\"", "comm=\"python3\"", "comm=\"bash\"")
| extend Command = extract(@"comm=""(\w+)""", 1, SyslogMessage)
| extend DetectionType = "LOLBIN Execution"
| project ProcTime = TimeGenerated, Computer, Command, DetectionType, SyslogMessage;
let LinuxReverseShell = Syslog
| where ProcessName == "audispd"
| where SyslogMessage has "type=EXECVE"
| where SyslogMessage contains "/dev/tcp/" or SyslogMessage contains "2F6465762F7463702F"
| extend Command = "bash"
| extend DetectionType = "Reverse Shell (/dev/tcp)"
| project ProcTime = TimeGenerated, Computer, Command, DetectionType, SyslogMessage;
let AllDetections = union LinuxLOLBIN, LinuxReverseShell;
LinuxSignins
| join kind=inner (AllDetections) on Computer
| where ProcTime between (SignInTime .. SignInTime + 10m)
| project SignInTime, ProcTime, Computer, Account, Command, DetectionType, SyslogMessage
| order by ProcTime desc
```

Deployed as a Scheduled Analytics Rule (10-minute frequency, 1-hour lookback), tactics `InitialAccess`, `Execution`, `CommandAndControl`; techniques `T1078`, `T1059`, `T1105`, `T1219`.

**Real bug found during query validation:** KQL's `has` operator is token-based, splitting on non-alphanumeric characters — it does not substring-match inside a single unbroken token. The hex-encoded `/dev/tcp` payload has no delimiters, so it forms one continuous token; `has_any("2F6465762F7463702F")` silently never matched, since the search term was a *fragment* of the token, never the whole token. No error, no warning — just quiet, wrong results. Fixed by switching to `contains`, which performs genuine substring matching regardless of token structure. This is a sharp, specific KQL lesson: `has` is faster and generally preferred, but fails silently on exactly this class of unbroken/encoded string.

## Live Validation

**Wazuh — all 5 rules confirmed live-fire, real dashboard hits:**

| Rule | First confirmed hit (UTC) |
|---|---|
| 100021 (nc) | 14:23:15 |
| 100022 (curl) | 14:25:05 |
| 100023 (wget) | 14:25:05 |
| 100024 (python3) | 14:27:29 |
| 100025 (bash /dev/tcp) | 14:54:37 |

**Sentinel — Query 7 confirmed live, both detection branches:**

| SignInTime (UTC) | ProcTime (UTC) | DetectionType |
|---|---|---|
| 15:54:50 | 15:54:53 | Reverse Shell (/dev/tcp) |
| 15:54:50 | 15:54:57 | Reverse Shell (/dev/tcp) |
| 16:41:09 | 16:41:40 | Reverse Shell (/dev/tcp) |
| 16:41:09 | 16:41:09–16:41:40 | LOLBIN Execution (multiple: bash, python3) |

Query 7 deployed as a live Analytics Rule (ID `94497424-aa8c-419b-a9c0-8f96716f9d51`).

## A Real Infrastructure Fault, Found and Diagnosed — Not Assumed

The first several attempts to validate the reverse-shell detection in Sentinel returned nothing, despite Wazuh catching the identical event instantly every time. Rather than conclude "Sentinel/AMA can't reliably forward this kind of record" (a plausible-sounding but unverified explanation), the investigation traced it to hard evidence: Azure Monitor Agent's own diagnostic log (`mdsd.err`) showed continuous `401 TokenExpired` / `429 RequestThrottled` failures from **14:31:34 to 15:20:55 UTC** — precisely the window covering the first failed validation attempts. AMA's authentication was genuinely broken for ~50 minutes; it could not have reliably forwarded *anything* new during that time, regardless of pipeline design.

A second, distinct issue remained even after that outage resolved — traced separately to the `has`/`contains` KQL bug above, not a second infrastructure fault. Both root causes are now confirmed with primary-source evidence (log excerpts, precise timestamps), not inferred from absence.

## Wazuh vs. Sentinel — Honest Comparison

Unlike Drills 1–3 (mirroring existing rules), this drill was Linux-native on both platforms from the start, so there's no "which was faster to detect the same signature" comparison. The more meaningful comparison is architectural: Wazuh's local file-tailing has a completeness guarantee network-relayed forwarding doesn't automatically share — evidenced directly by the AMA outage window above. Sentinel's advantage remains what Drill 3 demonstrated: KQL's native `join`/`union` syntax makes cross-event, time-windowed correlation (sign-in → LOLBIN, joined by host) more natural to express than Wazuh's rule-chaining model.

## Known Limitations

- **False-positive surface**, same class as Query 3/Wazuh 100025: the LOLBIN Execution branch correlates *any* sign-in with *any* matching binary within 10 minutes — it will also fire on legitimate admin activity (confirmed: several of tonight's own diagnostic `bash`/`python3` commands, run during normal troubleshooting, correctly triggered the rule). Documented rather than tuned away, consistent with this project's approach elsewhere.
- **Entity extraction**: Query 7 does not yet populate a dedicated Sentinel entity for the correlated process (Command/DetectionType are plain columns, not mapped entities) — a refinement for a future pass, not required for this drill's validation.
