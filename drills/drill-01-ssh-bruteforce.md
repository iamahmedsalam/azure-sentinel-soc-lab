# Drill 1 — SSH Brute Force (Medusa)

## Purpose

Re-run a proven attack scenario live, capturing the same attack landing in both Wazuh and Sentinel simultaneously, with real evidence — not two isolated tests run at different times. Attack tooling was deliberately varied from the original Wazuh-only testing (Project 1/3, which used Hydra) to Medusa, proving the detection triggers on the underlying failed-login *behavior*, not one specific tool's traffic fingerprint.

## Attack

```bash
medusa -h 192.168.56.104 -u analyst -P ~/wordlist.txt -M ssh -t 4
```

Launched from the Kali attacker VM against the Ubuntu SOC Agent, repeated failed-password attempts against a real account.

## A Real Timezone Discovery Along the Way

The Kali VM's clock is set to **America/New_York (EDT, UTC-4)** — unlike every other lab VM, which runs UTC. This wasn't known going in; it surfaced when Wazuh's displayed alert time and the attack's local timestamp appeared to match exactly (both were coincidentally rendering in EDT), which briefly looked like perfect real-time correlation but was actually two independently-offset clocks agreeing by coincidence. Cross-checking against Sentinel's raw UTC timestamp exposed the mismatch. Resolved by converting all timestamps to true UTC and flipping the Wazuh dashboard's display setting (`dateFormat:tz`) from `Browser` to `UTC` for the remainder of the project, so no future drill would hit the same ambiguity.

## Live Validation

| Event | Time (UTC) |
|---|---|
| Medusa attack launched | 10:37:11 |
| Wazuh alert (rule 5763, level 10) | 10:37:10 |
| Sentinel Incident 20 created | 10:46:29 |

**Wazuh detected in under 1 second** — real-time correlation as events are logged. **Sentinel took ~9 minutes 19 seconds** — not a fault, but the nature of Analytics Rules running on a scheduled query interval rather than event-driven correlation.

## Notable, Expected Non-Detection

The custom threat-intel-enriched rule (100011, from Project 3) did **not** fire. This is expected: that rule's enrichment pipeline checks source IPs against external reputation feeds, and Kali's address (`192.168.56.50`) is a private, internal IP with no external reputation data to check against — so it correctly stays silent for internal-to-internal traffic. A legitimate scope boundary, not a bug.

## Entity Data Gap Identified

Sentinel's Incident 20 populated **Account** and **Host** entities but not **Source IP** — meaning the attacking IP, while present in the raw log text, wasn't extracted into a structured Sentinel entity. Flagged at the time as a scope note for the Entity Investigation workbook (Phase E), which — as built — pivots on Account/Host, consistent with this finding.

## Wazuh vs. Sentinel — Honest Comparison

Real-time local correlation (Wazuh) vs. scheduled cloud-native analytics (Sentinel) is a genuine architectural trade-off, not a case of one tool being simply worse. Worth stating plainly rather than glossing over: Wazuh's speed advantage here is real, and it's the more meaningful finding than "both detected it."
