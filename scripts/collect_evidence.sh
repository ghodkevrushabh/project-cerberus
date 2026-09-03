#!/bin/bash
#
# Project Cerberus — IR Evidence Collection Script
# Captures a timestamped forensic snapshot: process list, active network connections,
# auditd log export, running services, and scheduled tasks/cron jobs.
#
# Usage: sudo ./collect_evidence.sh
# Output: cerberus_evidence_<UTC-timestamp>.tar.gz + a .sha256 checksum alongside it,
#         in the current working directory.

set -euo pipefail

TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
OUTDIR="cerberus_evidence_${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo "[*] Project Cerberus evidence collection started: $(date -u)"

echo "[*] Collecting process list..."
ps aux > "$OUTDIR/process_list.txt"

echo "[*] Collecting active network connections..."
if command -v ss &> /dev/null; then
    ss -tulnp > "$OUTDIR/network_connections.txt" 2>/dev/null
else
    netstat -tulnp > "$OUTDIR/network_connections.txt" 2>/dev/null
fi

echo "[*] Exporting auditd logs (today)..."
if command -v ausearch &> /dev/null; then
    ausearch -ts today > "$OUTDIR/auditd_today.txt" 2>/dev/null || echo "No auditd events found for today, or ausearch requires root." > "$OUTDIR/auditd_today.txt"
else
    echo "auditd/ausearch not installed on this host." > "$OUTDIR/auditd_today.txt"
fi

echo "[*] Collecting running services..."
systemctl list-units --type=service --state=running > "$OUTDIR/running_services.txt" 2>/dev/null || \
    service --status-all > "$OUTDIR/running_services.txt" 2>/dev/null || \
    echo "Could not enumerate services on this host." > "$OUTDIR/running_services.txt"

echo "[*] Collecting scheduled tasks / cron jobs..."
{
    for user in $(cut -f1 -d: /etc/passwd); do
        echo "== crontab for $user =="
        crontab -u "$user" -l 2>/dev/null || echo "(no crontab or no permission)"
        echo ""
    done
    echo "== /etc/cron.d/ =="
    ls -la /etc/cron.d/ 2>/dev/null || echo "(not present)"
    echo "== /etc/cron.daily/ =="
    ls -la /etc/cron.daily/ 2>/dev/null || echo "(not present)"
    echo "== /etc/cron.hourly/ =="
    ls -la /etc/cron.hourly/ 2>/dev/null || echo "(not present)"
} > "$OUTDIR/cron_jobs.txt"

echo "[*] Recording collection metadata..."
{
    echo "Hostname: $(hostname)"
    echo "Collected at (UTC): $(date -u)"
    echo "Collected by: $(whoami)"
    echo "Kernel: $(uname -a)"
} > "$OUTDIR/collection_metadata.txt"

echo "[*] Bundling into timestamped archive..."
tar -czf "${OUTDIR}.tar.gz" "$OUTDIR"
rm -rf "$OUTDIR"

echo "[*] Generating checksum..."
sha256sum "${OUTDIR}.tar.gz" > "${OUTDIR}.tar.gz.sha256"

echo "[+] Done. Evidence package: ${OUTDIR}.tar.gz"
echo "[+] Checksum file:          ${OUTDIR}.tar.gz.sha256"
