# Drill 3 — Sign-In Followed by LOLBIN Execution (`rundll32.exe`)

## Purpose

Query 3 is a genuinely new, KQL-native detection (sign-in correlated with LOLBIN execution via `LogonId`, within a 10-minute window) — not a mirror of an existing Wazuh rule, unlike Drills 1 and 2. This drill swaps the LOLBIN from `certutil.exe` (original testing) to `rundll32.exe`, one of the most commonly abused living-off-the-land binaries in real attacks.

## Proactive Fix — Found Before Running the Drill

Before launching the attack, the rule's live KQL was pulled and inspected directly (same "check before assuming" discipline that paid off in Drill 2):

```kql
| where RenderedDescription has_any ("powershell.exe", "cmd.exe", "certutil.exe")
```

`rundll32.exe` was not in the list — running the drill as originally planned would have produced a silent false negative, identical in character to Drill 2's bug but a different root cause (a missing list entry vs. an overly narrow string match). Caught and fixed *before* running: added `rundll32.exe` to the `has_any()` list, deployed via Cloud Shell/REST API, same pattern as Drill 2.

## Attack

```cmd
rundll32.exe shell32.dll,Control_RunDLL
```

A legitimate Windows command (opens Control Panel) using the exact `rundll32.exe`-executing-a-DLL-export pattern attackers abuse to disguise malicious code execution.

## Live Validation

Confirmed via the rule's raw join query, not the portal's summary display (see below for why):

| Event | Time (UTC) |
|---|---|
| Sign-in | 15:41:00 |
| `rundll32.exe shell32.dll,Control_RunDLL` execution | 15:42:20 |
| Sentinel Incident 27 created | 15:57:22 |

**Detection latency: ~15 minutes** from actual attack to incident. Confirmed genuine — not a false positive — by pulling the rule's raw matched rows directly, which showed the exact `rundll32` execution (tagged by Sysmon itself with `technique_id=T1218.011, technique_name=rundll32.exe`) correlated to the sign-in via `LogonId 0x66EB7`.

## What Got Genuinely Confusing (Worth Naming Honestly)

Three separate issues compounded during validation, and disentangling them took real effort:
1. **Two separate `rundll32` executions** occurred in the same session (the timed drill, plus an unrelated later one from ongoing troubleshooting) — early checks were validated against the wrong one.
2. **Timezone conversion** — the Windows VM runs Eastern Time, not UTC; a "12:21 PM" timestamp needed manual conversion, and one conversion initially pointed at the wrong event.
3. **A Lucene-vs-DQL syntax mismatch** in the Wazuh dashboard search produced a false "no results," briefly read as evidence of a real forwarding gap in Wazuh, when it was actually a broken search query — not an infrastructure fault.

All three compounded to nearly convince us Wazuh had silently dropped the log; the real data had been present the entire time, just under a different timestamp than the one being checked. Documented here because misdiagnosis-recovery is as real a skill as detection-building.

## No Wazuh Equivalent Exists

Confirmed via direct Wazuh dashboard search (`rundll32`, correct time window): no Wazuh rule fires on this pattern. This is by design, not a gap — the correlation (sign-in + LOLBIN execution, joined by `LogonId`, within a time window) is a cross-event, time-windowed join, which KQL's native `let`/`join` syntax expresses naturally. Wazuh's rule engine isn't built for this class of correlation the same way.

## Known, Documented Limitation

The rule has no behavioral filtering beyond "was one of the tracked binaries launched after sign-in" — it will also fire on completely ordinary admin activity. Confirmed directly: an earlier incident (22) was traced to nothing more than normal PowerShell administration during unrelated troubleshooting. Left as a documented false-positive surface rather than tuned away, consistent with how this project handles known trade-offs elsewhere.
