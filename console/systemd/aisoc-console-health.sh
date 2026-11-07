#!/usr/bin/env bash
# Liveness probe for the console backend. Restart=always in the unit brings back
# a process that *exits*; this catches a process that is alive but no longer
# serving (event-loop stall, deadlock). Two consecutive misses trigger a
# restart, so the ~5s RestartSec window doesn't cause a flap.
set -u

URL="http://127.0.0.1:${AISOC_PORT:-4319}/api/health"

healthy() {
  curl -fsS -m 4 "$URL" >/dev/null 2>&1
}

if healthy; then
  exit 0
fi
sleep 3
if healthy; then
  exit 0
fi

echo "console backend health check failed twice at $URL — restarting"
systemctl restart aisoc-console.service
