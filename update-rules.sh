#!/usr/bin/env bash
# Pull latest ET Open rules and hot-reload every sensor (USR2 = live rule
# reload, no packet loss). Both containers share ./suricata/rules, so the
# update runs once and each engine reloads from the same file.
set -euo pipefail
docker exec aisoc-suricata suricata-update -f
for c in aisoc-suricata aisoc-suricata-vpn; do
  docker kill -s USR2 "$c" 2>/dev/null || echo "sensor $c not running, skipped" >&2
done
