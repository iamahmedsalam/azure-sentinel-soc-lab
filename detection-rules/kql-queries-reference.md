# KQL Analytics Rules — Engineering Reference

## Overview

7 custom Sentinel detections, each written and validated from scratch — no templates. Five are deployed as live Scheduled Analytics Rules; two (Queries 4 and 5) have their mechanics fully proven against real data but are deliberately not deployed yet, because doing so with insufficient historical data would produce a rule that *looks* functional while actually being untrustworthy — worse than no rule at all. See "Queries 4 & 5" below for why that distinction matters.

## A Foundational Architecture Discovery

Before any of these queries could be trusted, a real, non-obvious finding had to be tracked down: **Azure's legacy `SecurityEvent` table is never populated by the modern Azure Monitor Agent (AMA).** Every one of these queries was originally designed against `SecurityEvent` — the table nearly every KQL tutorial online still references — and every single one silently returned nothing, for hours, with no error to explain why.

The real cause: `SecurityEvent` belongs to Azure's older Log Analytics agent generation (MMA). AMA — the modern agent, the one actually in use here — routes Windows Security log data through the same generic `Event` table as every other event source, Sysmon included. This wasn't a permissions issue, a DCR misconfiguration, or an agent health problem — all of which were investigated first — it was an incorrect table assumption baked into the design from the start. Every query below uses `Event`, filtered by `EventLog == "Security"` for native Windows Security events, or `Source == "Microsoft-Windows-Sysmon"` for Sysmon.

A second, related discovery: `EventID` and `EventCategory` are two genuinely separate fields. They coincidentally aligned for Sysmon (which is why early testing looked correct), but diverge for native Windows Security events — `EventID` is the correct, universal field, confirmed by direct comparison against real logon events (`EventID: 4624` vs. an unrelated `EventCategory: 12544` on the same row).

---

## Query 1 — SSH Brute Force (Linux)

**MITRE:** T1110.001 | **Status:** ✅ Deployed | **Live-fire validated:** [Drill 1](../drills/drill-01-ssh-bruteforce.md)

```kql
Syslog
| where SyslogMessage has "Failed password"
| extend Account = extract(@"for (invalid user )?(\S+)", 2, SyslogMessage)
| summarize FailCount = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailCount >= 8
```

**Design note:** originally built against `SecurityEvent` — a second, independent design flaw beyond the table-name issue above: SSH brute force is inherently a *Linux* scenario, but the query was written against Windows-only security-log semantics. Real SSH authentication data lives in `Syslog`, inside the raw `SyslogMessage` text, with no Windows-table equivalent at all. Rewritten from scratch against the actual Linux schema.

**Live result:** Wazuh detected in <1 second (real-time log tailing); Sentinel took ~9m19s (scheduled query interval) — a genuine architectural trade-off, not a fault on either side.

---

## Query 2 — Encoded PowerShell Command

**MITRE:** T1059.001 | **Status:** ✅ Deployed | **Live-fire validated:** [Drill 2](../drills/drill-02-encoded-powershell.md)

```kql
Event
| where EventLog == "Security" or Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription matches regex @"(?i)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}"
| extend EncodedPayload = extract(@"(?i)-e[a-z]*\s+([A-Za-z0-9+/=]{20,})", 1, RenderedDescription)
```

**Real bug found and fixed live:** the original version matched the literal string `"EncodedCommand"`. PowerShell accepts abbreviated flags (`-e`, `-en`, `-enc`, up through `-EncodedCommand`) as valid, unambiguous shorthand — and Sysmon logs the command line exactly as typed. A real attack using `-enc` (a known evasion technique, chosen specifically because naive detections hardcode the full flag name) produced a silent false negative. Rewritten as a regex matching any valid abbreviation, deployed as a live fix via `az rest` through Cloud Shell, and re-validated against a fresh attack run that produced a real incident.

---

## Query 3 — Sign-In Followed by LOLBIN Execution (Windows)

**MITRE:** T1078, T1059 | **Status:** ✅ Deployed | **Live-fire validated:** [Drill 3](../drills/drill-03-lolbin-execution.md)

```kql
let SignIns = Event
    | where EventLog == "Security"
    | where EventID == 4624
    | extend Account = extract(@"New Logon:.*?Account Name:\s*(\S+)", 1, RenderedDescription)
    | extend LogonId = extract(@"New Logon:.*?Logon ID:\s*(0x\S+)", 1, RenderedDescription)
    | where Account !in ("SYSTEM", "-")
    | project SignInTime = TimeGenerated, Computer, Account, LogonId;
let SuspiciousProcs = Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 1
    | where RenderedDescription has_any ("powershell.exe", "cmd.exe", "certutil.exe", "rundll32.exe")
    | extend Account = extract(@"User:\s*\S+\\(\S+)", 1, RenderedDescription)
    | extend LogonId = extract(@"LogonId:\s*(0x\S+)", 1, RenderedDescription)
    | where Account !in ("SYSTEM", "-")
    | project ProcTime = TimeGenerated, Computer, Account, LogonId, ProcessDescription = RenderedDescription;
SignIns
| join kind=inner (SuspiciousProcs) on Computer, LogonId
| where ProcTime between (SignInTime .. SignInTime + 10m)
```

**Design evolution — the cross-product bug:** an early version joined on `Computer` alone. In a single-VM lab, every sign-in shares the same `Computer` value as every process event, so the join produced a combinatorial explosion — one real `cmd.exe` execution matched against 4,459 unrelated sign-ins, most of them minutes or hours apart with no real connection. Fixed by joining on `Computer` **and** `LogonId` — a per-session identifier extracted from both the sign-in and process events — so the join only pairs events that genuinely share the same logon session, and the `10m` window then filters to temporal proximity within that session.

**Real bug found and fixed *before* running Drill 3:** the `has_any()` list originally only contained `powershell.exe`, `cmd.exe`, `certutil.exe` — `rundll32.exe`, one of the most commonly abused real-world LOLBINs, was missing. Caught by inspecting the live rule before running the drill, added, deployed, and validated live.

**No Wazuh equivalent:** this is a genuinely new, KQL-native detection — the cross-event, time-windowed join has no direct Wazuh XML rule counterpart. Confirmed by direct dashboard search finding no matching Wazuh rule for the identical behavior.

**Known limitation:** the rule has no behavioral filtering beyond "was a tracked binary launched after sign-in" — it also fires on ordinary admin activity (confirmed directly: a prior incident traced to nothing more than routine PowerShell administration).

---

## Query 4 — Rolling-Baseline Failed-Logon Anomaly

**MITRE:** T1110 | **Status:** 🟡 Mechanics validated, deployment deferred

```kql
let Baseline = Event
    | where EventLog == "Security"
    | where EventID == 4625
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | summarize HourlyCount = count() by Computer, HourOfDay = hourofday(TimeGenerated), Day = startofday(TimeGenerated)
    | summarize BaselineAvg = avg(HourlyCount) by Computer, HourOfDay;
let Today = Event
    | where EventLog == "Security"
    | where EventID == 4625
    | where TimeGenerated > ago(1d)
    | summarize TodayCount = count() by Computer, HourOfDay = hourofday(TimeGenerated);
Today
| join kind=inner (Baseline) on Computer, HourOfDay
| where TodayCount > BaselineAvg * 3
| project Computer, HourOfDay, TodayCount, BaselineAvg
```

**Concept:** rather than a fixed threshold ("8+ failures in 5 minutes," as Query 1 uses), this compares *today's* failed-logon count for a given hour against that host's own 7-day historical average for the same hour — flagging a host behaving unusually *for itself*, not against a one-size-fits-all number. This is a genuinely different class of detection than anything in the Wazuh ruleset, which has no built-in concept of historical-average comparison.

**Why it's not deployed:** the lab's real data history is only a few days deep. Deploying this rule now would mean its `BaselineAvg` is computed from almost no data — technically "working," but producing comparisons that don't mean anything real. Mechanics were validated by temporarily compressing the time windows (hours instead of days) against real data that does exist, confirming the aggregation/join logic executes correctly and produces sensibly-shaped output. The compressed-window version was discarded after validation; this is the real, final query, held for genuine deployment once sufficient lab history accumulates.

---

## Query 5 — Statistical Process-Count Anomaly

**MITRE:** T1055 | **Status:** 🟡 Mechanics validated, deployment deferred

```kql
let StartTime = ago(14d);
let EndTime = now();
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| make-series ProcessCount = count() on TimeGenerated from StartTime to EndTime step 1h by Computer
| extend (Anomalies, AnomalyScore, Baseline) = series_decompose_anomalies(ProcessCount)
| mv-expand TimeGenerated, ProcessCount, Anomalies, AnomalyScore, Baseline
| where Anomalies != 0
```

**Concept:** uses KQL's built-in `series_decompose_anomalies()` — real statistical time-series decomposition (trend, seasonality, residual) — to let the platform itself decide what counts as an unusual hourly process-creation rate per host, rather than a hand-built threshold formula. `make-series` here builds one row per host containing an entire ordered array of hourly counts across 14 days, which the decomposition function analyzes as a whole sequence.

**Why it's not deployed:** same reasoning as Query 4 — 14 days of real history doesn't exist yet. Mechanics validated with a compressed 6-hour/10-minute-bucket version against real Sysmon data, confirming the `make-series` → `series_decompose_anomalies()` → `mv-expand` pipeline executes correctly and genuinely flags anomalous points. This is the real, final version, held for deployment once real 14-day history exists.

---

## Query 6 — Rare/New Process Hunting Query

**MITRE:** T1036 | **Status:** ✅ Deployed (Hunting Query, not incident-generating)

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend ProcessName = extract(@"Image:\s*(\S+)", 1, RenderedDescription)
| summarize FirstSeen = min(TimeGenerated), TimesSeen = count() by Computer, ProcessName
| where FirstSeen > ago(7d)
| where TimesSeen <= 3
| sort by FirstSeen desc
```

**Concept:** surfaces processes that are both *new* (first seen within the last 7 days) and *rare* (seen 3 times or fewer) — a masquerading/unusual-binary hunting pattern, deployed as a Sentinel Hunting Query rather than an incident-generating Analytics Rule, since its purpose is proactive analyst review rather than automated alerting.

---

## Query 7 — Sign-In Followed by Linux LOLBIN / Reverse Shell

**MITRE:** T1078, T1059, T1105, T1219 | **Status:** ✅ Deployed | **Live-fire validated:** [Drill 4](../drills/drill-04-linux-lolbin.md)

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
```

**Concept:** the Linux counterpart to Query 3 — same sign-in-then-suspicious-activity correlation pattern, extended to cover both LOLBIN presence and the specific bash `/dev/tcp` reverse-shell signature, unioned into one rule with a `DetectionType` column so an analyst can immediately distinguish routine LOLBIN use from a high-confidence reverse shell.

**Real bug found and fixed live — `has` vs. `contains`:** KQL's `has` operator is **token-based**, splitting text on non-alphanumeric characters and matching only whole tokens. The hex-encoded `/dev/tcp` payload (`2F6465762F7463702F...`) has no delimiters, forming one continuous token — so `has_any("2F6465762F7463702F")` was asking "is there a token that *exactly equals* this string," when the string was only a *fragment* of a much longer token. No error, no warning — the query ran successfully and silently never matched. Fixed by switching to `contains`, which performs genuine substring matching regardless of token structure. `has` remains faster and is generally the right default; this is the specific class of case (unbroken, encoded, or concatenated strings) where it fails silently and `contains` is required instead.

**A real infrastructure fault, diagnosed rather than assumed:** early validation attempts returned nothing, which could easily have been mis-attributed to "Sentinel/AMA just can't reliably forward this." Instead, primary-source evidence was pulled — Azure Monitor Agent's own diagnostic log (`mdsd.err`) showed continuous authentication failures for ~50 minutes, precisely overlapping the failed attempts. The real cause was a genuine, time-bound AMA authentication outage, not a structural pipeline limitation — confirmed, not guessed.

**Deployment note:** Sentinel's Analytics Rule API requires every listed MITRE technique's parent tactic to also be explicitly present in the rule's `tactics` array — `T1105`/`T1219` required `CommandAndControl` added alongside `InitialAccess`/`Execution`, or the deployment is rejected outright.

---

## Deployment Method

All live rules were deployed via the Azure REST API (`az rest`) through Cloud Shell — pulling the existing rule JSON, editing the query field, stripping read-only fields (`lastModifiedUtc`), and PUTting the update back — rather than the Sentinel portal UI. This keeps every rule change scripted and reproducible, consistent with treating detection logic as infrastructure-as-code rather than manual configuration.
