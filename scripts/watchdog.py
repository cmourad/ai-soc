#!/usr/bin/env python3
"""Check that the SOC is actually working, and say so when it is not.

Every outage this system has had was silent. auditd was inactive for four days
while its unit reported active; the rule-update timer was disabled so
signatures froze; the digest had no push target so it reached nobody; the agent
triaged nothing for 21 hours because every alert was below its severity floor.
systemd reported all of it green, because "the process is running" and "the
process is doing its job" are different questions.

This asks the second question. Stdlib only, runs as root from a timer.

Exit 0 always: a failing watchdog unit is one more silent red light. The signal
is the push, and the journal line.
"""

import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import notify  # noqa: E402

log = logging.getLogger("watchdog")

EVE_PATHS = [p.strip() for p in os.environ.get(
    "AISOC_EVE",
    "/opt/aisoc/suricata/logs/eve.json,"
    "/opt/aisoc/suricata/logs-vpn/eve.json").split(",") if p.strip()]
DECISIONS = os.environ.get("AISOC_DECISIONS", "/var/lib/aisoc/decisions.jsonl")
RULES_FILE = os.environ.get(
    "AISOC_RULES", "/opt/aisoc/suricata/rules/rules/suricata.rules")
LLM_URL = os.environ.get("AISOC_LLM", "http://127.0.0.1:8082/v1/chat/completions")
CONSOLE_URL = os.environ.get("AISOC_CONSOLE", "http://127.0.0.1:4319/api/health")
STATE = os.environ.get("AISOC_WATCHDOG_STATE", "/var/lib/aisoc/watchdog.state")

UNITS = ["aisoc-agent.service", "aisoc-console.service"]
CONTAINERS = ["aisoc-suricata", "aisoc-suricata-vpn"]

EVE_STALE_SECS = 600        # Suricata writes a stats record every 8s
RULES_STALE_SECS = 172800   # 48h: the update timer runs daily
QUIET_TRIAGE_SECS = 86400   # no verdict in a day means the pipeline is dry
DISK_WARN_PCT = 85
RENOTIFY_SECS = 21600       # re-push an unchanged failure every 6h, not every run


def _run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def check_units():
    for unit in UNITS:
        if _run("systemctl", "is-active", unit) != "active":
            yield f"{unit} is not active"


def check_containers():
    running = _run("docker", "ps", "--format", "{{.Names}}").splitlines()
    for name in CONTAINERS:
        if name not in running:
            yield f"container {name} is not running"


def check_sensors():
    """A sensor that stopped writing is indistinguishable from a quiet network
    unless you look at the file clock."""
    now = time.time()
    for path in EVE_PATHS:
        try:
            age = now - os.stat(path).st_mtime
        except OSError:
            yield f"{path} is missing"
            continue
        if age > EVE_STALE_SECS:
            yield f"{path} has not been written in {int(age / 60)} min"


def check_rules():
    try:
        age = time.time() - os.stat(RULES_FILE).st_mtime
    except OSError:
        yield f"ruleset {RULES_FILE} is missing"
        return
    if age > RULES_STALE_SECS:
        yield f"signatures are {int(age / 86400)} days old — is aisoc-rules.timer enabled?"


def check_triage():
    """Silence here is the failure mode that hid for 21 hours."""
    try:
        last = os.stat(DECISIONS).st_mtime
    except OSError:
        yield f"{DECISIONS} is missing — the agent has never recorded a verdict"
        return
    age = time.time() - last
    if age > QUIET_TRIAGE_SECS:
        yield f"no triage verdict in {int(age / 3600)}h — check the severity floor and the sensors"


def check_llm():
    try:
        req = urllib.request.Request(
            LLM_URL, data=json.dumps({
                "model": os.environ.get("AISOC_MODEL", "Qwen3.6-27B-MTP-Q4_K_S"),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            }).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        yield f"triage model unreachable at {LLM_URL}: {e}"


def check_console():
    try:
        with urllib.request.urlopen(CONSOLE_URL, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        yield f"console health check failed: {e}"


def check_disk():
    for path in {os.path.dirname(p) for p in EVE_PATHS} | {"/var/lib"}:
        try:
            st = os.statvfs(path)
        except OSError:
            continue
        used = 100 * (1 - st.f_bavail / st.f_blocks)
        if used > DISK_WARN_PCT:
            yield f"{path} is {used:.0f}% full"


CHECKS = (check_units, check_containers, check_sensors, check_rules,
          check_triage, check_llm, check_console, check_disk)


def read_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def write_state(state):
    try:
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE)
    except OSError as e:
        log.warning("cannot persist state: %s", e)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    failures = []
    for check in CHECKS:
        try:
            failures.extend(check())
        except Exception:
            log.exception("check %s raised", check.__name__)
            failures.append(f"watchdog check {check.__name__} raised")

    prev = read_state()
    now = time.time()
    signature = "|".join(sorted(failures))

    if not failures:
        if prev.get("signature"):
            notify.push("All checks passing again.", title="AI SOC recovered", priority="low")
        log.info("all checks passing")
        write_state({"signature": "", "notified_at": now})
        return

    for f in failures:
        log.error("%s", f)

    changed = signature != prev.get("signature")
    stale = now - prev.get("notified_at", 0) > RENOTIFY_SECS
    if changed or stale:
        notify.push("\n".join(f"- {f}" for f in failures),
                    title=f"AI SOC degraded ({len(failures)})", priority="high")
        write_state({"signature": signature, "notified_at": now})
    else:
        write_state({**prev, "signature": signature})


if __name__ == "__main__":
    main()
