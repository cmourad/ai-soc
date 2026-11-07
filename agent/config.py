#!/usr/bin/env python3
"""Deployment-facing configuration for the agent and the modules it composes.

Every path, socket, threshold and feed pattern the agent honours is resolved
here, once. The systemd units inject the production values; the fallbacks are
what a developer gets running straight out of the repository.
"""

import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# comma-separated: one eve.json per sensor vantage point. The physical NIC only
# ever sees ciphertext while the WireGuard tunnel holds the default route, so
# the tunnel-side sensor is the one carrying real traffic.
EVE_PATHS = [p.strip() for p in
             os.environ.get("AISOC_EVE", os.path.join(BASE, "suricata/logs/eve.json")).split(",")
             if p.strip()]
# host-based signals (auditd-derived, JSONL in the same alert shape) tailed
# alongside eve.json; "" disables. Written by scripts/audit_tail.py as root.
HOST_EVENTS = os.environ.get("AISOC_HOST_EVENTS",
    "/var/lib/aisoc-host-events/host-events.jsonl"
    if os.path.isdir("/var/lib/aisoc-host-events") else "")
# the sandboxed service can only write its StateDirectory; fall back to the
# repo dir for manual/dev runs where /var/lib/aisoc doesn't exist
DECISIONS = os.environ.get("AISOC_DECISIONS",
    "/var/lib/aisoc/decisions.jsonl" if os.path.isdir("/var/lib/aisoc")
    else os.path.join(BASE, "suricata/logs/decisions.jsonl"))
# repeat-offender history survives agent restarts (escalation: 1h -> 24h -> 30d)
OFFENDER_DB = os.environ.get("AISOC_DB",
    "/var/lib/aisoc/offenders.db" if os.path.isdir("/var/lib/aisoc")
    else os.path.join(BASE, "suricata/logs/offenders.db"))
ALLOWLIST = os.path.join(BASE, "allowlist.txt")

# The console asks for blocks over this socket rather than running nft itself.
# One writer to the table means one Guard, one timeout ladder, one audit trail —
# a second writer with its own idea of what may be blocked is how a UI ends up
# firewalling the gateway. systemd's RuntimeDirectory= owns /run/aisoc.
CONTROL_SOCKET = os.environ.get("AISOC_CONTROL_SOCKET",
    "/run/aisoc/control.sock" if os.path.isdir("/run/aisoc")
    else os.path.join(BASE, "suricata/logs/control.sock"))
# Filesystem group ownership is a first gate; SO_PEERCRED below authorizes the
# exact dedicated core UID before a byte of request data is parsed.
CONTROL_GROUP = os.environ.get("AISOC_CONTROL_GROUP", "")
CONTROL_USERS = os.environ.get("AISOC_CONTROL_USERS", "")
CONTROL_MAX_REQUEST = 8192
# vpn_replace can run two bounded wg-quick commands (45s each). Control callers
# must wait for that result instead of receiving a false "agent busy" reply.
CONTROL_TIMEOUT = 100
CONTROL_MAX_BLOCK_SECS = 30 * 86400
CONTROL_MAX_CONNECTIONS = 16
CONTROL_MAX_QUEUE = 32
VPN_CONFIG_DIR = os.environ.get("AISOC_VPN_CONFIG_DIR", "/var/lib/aisoc/wg")
VPN_IFACE_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
VPN_HELPER_SOCKET = os.environ.get("AISOC_VPN_HELPER_SOCKET", "/run/aisoc-vpn/helper.sock")
PROCESS_HELPER_SOCKET = os.environ.get(
    "AISOC_PROCESS_HELPER_SOCKET", "/run/aisoc-process/helper.sock")

LLM_URL = os.environ.get("AISOC_LLM", "http://127.0.0.1:8082/v1/chat/completions")
LLM_MODEL = os.environ.get("AISOC_MODEL", "Qwen3.6-27B-MTP-Q4_K_S")
LLM_TIMEOUT = 180

# Optional fast tier: a small model clears obvious IGNOREs so the 27B sees
# fewer alerts. OFF by default — the 9B on :8084 is CPU-served (-ngl 0) and no
# faster than the 27B, while it swallowed a prompt-injected exploit alert as
# IGNORE@0.9 in eval. Only enable behind a GPU-resident small model that scores
# clean on scripts/eval_tiers.py.
FAST_LLM_URL = os.environ.get("AISOC_FAST_LLM", "")
FAST_MODEL = os.environ.get("AISOC_FAST_MODEL", "Qwen3.5-9B-Q8_0")
FAST_TIMEOUT = 60
FAST_MAX_TOKENS = 1024
# fast tier must be this sure before its IGNORE skips the 27B — a wrong
# accept on a real threat would evade triage, so err toward escalation
FAST_IGNORE_CONFIDENCE = 0.8

# agentic tool-calling triage: the model can pull threat intel mid-verdict.
# OFF by default — keep the verified single-shot path until keys are set.
TOOLS_ENABLED = os.environ.get("AISOC_TOOLS", "").lower() in ("1", "yes", "true", "on")

LOKI_URL = os.environ.get("AISOC_LOKI", "http://127.0.0.1:3100")  # "" disables

MAX_SEVERITY = int(os.environ.get("AISOC_MAX_SEVERITY", "2"))  # suricata: 1 = worst
COOLDOWN = 900          # s before re-triaging the same (sig, ip)
BLOCK_SECS = 3600       # first offense
BLOCK_SECS_REPEAT = 86400
BLOCK_SECS_THIRD = 30 * 86400  # escalation curve: 1h -> 24h -> 30d
BLOCK_SECS_QUIET = 90 * 86400  # this quiet makes a repeat offender a first one
MIN_CONFIDENCE = 0.7    # below this a BLOCK verdict is downgraded to WATCH
MAX_BLOCKS_PER_HOUR = 30  # a runaway/poisoned model must not firewall the world
MAX_HISTORY_IPS = 1000  # per-IP signature history kept for tool escalation

# curated IP-reputation feeds: block deterministically, no LLM in the loop
AUTOBLOCK = re.compile(os.environ.get("AISOC_AUTOBLOCK", r"^ET (DROP|CINS|COMPROMISED) "))
