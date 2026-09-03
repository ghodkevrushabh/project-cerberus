#!/usr/bin/env python3
"""
Project Cerberus - Phase 3: C2 Beacon Jitter Detection
Parses Zeek's conn.log looking for regular, low-jitter connection patterns
between a specific source and destination - a signature of C2 beaconing (T1071.001).

Usage:
    sudo python3 beacon_jitter_check.py [path-to-conn.log-or-conn.log.gz]

If no path is given, defaults to /opt/zeek/logs/current/conn.log.
Note: Zeek rotates conn.log hourly - if analyzing a past beacon window, point
this at the correct archived, gzipped file under /opt/zeek/logs/<date>/ instead.
"""
import sys
import gzip
import statistics

ZEEK_CONN_LOG = sys.argv[1] if len(sys.argv) > 1 else "/opt/zeek/logs/current/conn.log"
SRC_IP = "10.0.6.93"       # Workstation (adjust to your environment)
DEST_IP = "10.0.10.178"    # Monitor (adjust to your environment)
DEST_PORT = "443"
JITTER_THRESHOLD_PCT = 15  # flag as beacon if coefficient of variation is below this


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt")
    return open(path, "r")


def main():
    timestamps = []
    with open_log(ZEEK_CONN_LOG) as f:
        for line in f:
            if line.startswith("#"):
                continue
            fields = line.strip().split("\t")
            if len(fields) < 8:
                continue
            ts, uid, src, sport, dst, dport = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
            proto = fields[6] if len(fields) > 6 else ""
            if src == SRC_IP and dst == DEST_IP and dport == DEST_PORT and proto == "tcp":
                timestamps.append(float(ts))

    timestamps.sort()
    print(f"[*] Found {len(timestamps)} matching connections: {SRC_IP} -> {DEST_IP}:{DEST_PORT}")

    if len(timestamps) < 3:
        print("[-] Not enough data points to analyze jitter (need at least 3 connections).")
        sys.exit(0)

    deltas = [round(timestamps[i+1] - timestamps[i], 2) for i in range(len(timestamps)-1)]
    print(f"[*] Intervals between connections (seconds): {deltas}")

    mean_delta = statistics.mean(deltas)
    stdev_delta = statistics.stdev(deltas) if len(deltas) > 1 else 0
    cv_pct = (stdev_delta / mean_delta) * 100 if mean_delta else 0

    print(f"[*] Mean interval: {mean_delta:.2f}s")
    print(f"[*] Std deviation: {stdev_delta:.2f}s")
    print(f"[*] Coefficient of variation (jitter): {cv_pct:.2f}%")

    if cv_pct < JITTER_THRESHOLD_PCT:
        print(f"\n[!] ALERT: Regular beaconing pattern detected (jitter {cv_pct:.2f}% < {JITTER_THRESHOLD_PCT}% threshold)")
        print(f"[!] Possible C2 beacon: {SRC_IP} -> {DEST_IP}:{DEST_PORT} (T1071.001)")
    else:
        print(f"\n[+] No regular beaconing pattern detected (jitter {cv_pct:.2f}% >= {JITTER_THRESHOLD_PCT}% threshold)")


if __name__ == "__main__":
    main()
