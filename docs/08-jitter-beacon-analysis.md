# Phase 3 — Jitter / Beacon Analysis Writeup

This is a focused writeup on the statistical detection method behind Phase 3, supplementing the narrative in [`05-phase3-execution-log.md`](05-phase3-execution-log.md) with the full dataset and supporting chart.

---

## The Core Idea

Command-and-control (C2) malware doesn't maintain a permanent open connection to its operator — it **beacons**: waking on a schedule, checking in briefly, then going quiet. Real C2 frameworks add **jitter** (small randomized variance) to that schedule specifically to defeat detection based on perfectly identical timing. Beacon/jitter analysis exploits the fact that even a jittered beacon still can't fully mimic organic traffic — the interval between connections remains far more consistent than anything a human or a normal application would produce.

The statistic used to measure this is the **coefficient of variation (CV)** — standard deviation divided by mean, expressed as a percentage. A low CV means tight, consistent timing (suspicious); a high CV means erratic, unpredictable timing (normal).

---

## Full Dataset (Combined Across Both Log Files)

The beacon ran for roughly 4 minutes and was captured across two of Zeek's hourly log rotations (`conn.16:00:00-17:00:00.log.gz` and `conn.17:00:00-18:00:00.log.gz`). Combining both gives the complete, most representative picture — five beacon connections, four measured intervals:

| Beacon # | Timestamp | Interval from previous |
|---|---|---|
| 1 | 16:58:43 | — |
| 2 | 16:59:48 | 65s |
| 3 | 17:00:44 | 56s |
| 4 | 17:01:48 | 64s |
| 5 | 17:02:50 | 62s |

**Mean interval:** 61.75s
**Standard deviation:** 4.03s
**Coefficient of variation:** **6.53%**

Against the project's 15% threshold, this is a comfortable, clear-cut flag — real human or application-driven traffic essentially never lands this consistently.

![Beacon interval analysis chart](evidence/phase3/11-beacon-jitter-analysis-chart.png)

---

## Note on the Earlier, Partial-File Measurement

During live execution ([`05-phase3-execution-log.md`](05-phase3-execution-log.md), Issue 4), the beacon's data initially had to be located across Zeek's hourly log rotation, and the first successful run of `beacon_jitter_check.py` was against only the `17:00:00-18:00:00` file — which happened to contain just 3 of the 5 beacon connections (2 intervals: 64.01s and 62.0s), giving a CV of 2.26%. That figure is accurate for the data it was measured against, but the **6.53% figure above, computed from the complete 5-beacon dataset spanning both log files, is the more representative and complete measurement** and is the one this project treats as authoritative. Both values comfortably clear the detection threshold; the difference simply reflects sample size, not a discrepancy in the underlying method.

---

## Why 6.53% (not 2.26%, not 0%) Is the Right Number to Expect

A perfectly rigid beacon with zero jitter would show a CV at or extremely close to 0%. This project's beacon script deliberately included **±10% jitter** on top of a 60-second base interval — meaning some natural variance was intentionally engineered in, mimicking a real C2 implant's own evasion behavior rather than a naive, unjittered one. A CV in the mid-single-digits is exactly what a *jittered but still fundamentally scheduled* process should produce: tighter than random human behavior, looser than a completely rigid, un-jittered beacon.

---

## Detection Script

The analysis is performed by [`scripts/beacon_jitter_check.py`](../scripts/beacon_jitter_check.py), which parses Zeek's `conn.log` (handling both live and rotated/gzipped files), isolates connections matching a specific source/destination/port triple, computes the interval deltas, and flags the result if the coefficient of variation falls under a configurable threshold (default: 15%).

```
$ sudo python3 beacon_jitter_check.py /opt/zeek/logs/2026-09-02/conn.17:00:00-18:00:00.log.gz
[*] Found 3 matching connections: 10.0.6.93 -> 10.0.10.178:443
[*] Intervals between connections (seconds): [64.01, 62.0]
[*] Mean interval: 63.01s
[*] Std deviation: 1.42s
[*] Coefficient of variation (jitter): 2.26%

[!] ALERT: Regular beaconing pattern detected (jitter 2.26% < 15% threshold)
[!] Possible C2 beacon: 10.0.6.93 -> 10.0.10.178:443 (T1071.001)
```

---

## MITRE ATT&CK Mapping

- **Technique:** T1071.001 — Application Layer Protocol: Web Protocols
- **Tactic:** Command and Control

## Interview Summary

*"We simulated a C2 beacon with a 60-second base interval and 10% jitter, then built a standalone Python script analyzing Zeek's connection logs to detect it — computing the coefficient of variation across connection intervals rather than matching a fixed signature. Our full dataset showed a 6.53% coefficient of variation, well under our 15% detection threshold, correctly flagging the beacon as non-organic, scheduled traffic. We chose this statistical approach specifically because it generalizes to detect any regularly-scheduled C2 communication, not just the one specific tool or payload we happened to simulate."*
