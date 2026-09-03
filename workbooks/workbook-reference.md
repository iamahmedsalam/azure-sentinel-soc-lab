# Sentinel Workbook — Detections Overview

A Microsoft Sentinel Workbook is the KQL-native equivalent of a Wazuh dashboard view: a JSON-defined canvas where each panel is a KQL query rendered as a chart, tile, or table. This workbook gives a triage-level snapshot of everything the [Analytics Rules and Hunting Query in Phase C](../detection-rules/) have caught over the past 7 days.

**File:** [`detections-overview.json`](./detections-overview.json)
**Data source:** `soc-lab-sentinel-workspace` (Log Analytics, Analytics tier)
**Underlying table:** `SecurityIncident`

## Panels

### Overview
- **Total Incidents (7d)** — single KPI tile, count of all incidents in the trailing 7-day window.
- **Incidents by Severity** — bar chart breakdown across High / Medium / Low / Informational, cross-validated against the total tile.

### Activity Timeline
- **Incidents over time** — time chart binning incidents into 1-hour buckets, showing detection volume rise and fall across the day rather than a flat aggregate number.

### Detections by Rule
- **Incidents by Title** — categorical bar chart grouping incidents by the Analytics Rule (or Hunting Query) that generated them, using `SecurityIncident.Title` as the rule name. This is the panel that shows *which* detection is doing the work, not just how many incidents exist in total.

## Deliberately Out of Scope

Entity-level views (top source IPs, top targeted accounts/hosts) are not included here by design — that's a different job for a different moment: investigating a specific incident, not triaging the queue. A separate **Entity Investigation** workbook is planned for Phase E, built alongside the live Wazuh-vs-Sentinel comparison drills, when there's an actual incident to pivot on.

Queries 4 (Rolling Baseline) and 5 (Statistical Anomaly) are not represented in this workbook yet. Both need 7–14 days of real historical data to produce a meaningful baseline — syntax and mechanics were validated in Phase C using compressed time windows, but they aren't deployed as live Analytics Rules pending sufficient lab history. This workbook reflects only the four fully-deployed, live-fire-validated detections.
