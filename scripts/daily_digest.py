#!/usr/bin/env python3
"""Daily AI SOC digest.

Batches the last 24h of triage decisions through the 27B and pushes a short
plain-text summary via ntfy (default) or Telegram. Stdlib only.

Config (env):
  AISOC_DECISIONS           path to decisions.jsonl (same default as the agent)
  AISOC_LLM                 triage endpoint (default http://127.0.0.1:8082/v1/chat/completions)
  AISOC_MODEL               model name
  AISOC_NTFY_URL            ntfy base URL (default https://ntfy.sh)
  AISOC_NTFY_TOPIC          ntfy topic; if unset, falls through to Telegram
  AISOC_TELEGRAM_BOT_TOKEN  Telegram bot token
  AISOC_TELEGRAM_CHAT_ID    Telegram chat id

If neither ntfy topic nor Telegram token is set, the digest is printed to
stdout (for manual runs / debugging).
"""

import collections
import json
import logging
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import notify  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECISIONS = os.environ.get("AISOC_DECISIONS",
    "/var/lib/aisoc/decisions.jsonl" if os.path.isdir("/var/lib/aisoc")
    else os.path.join(BASE, "suricata/logs/decisions.jsonl"))
LLM_URL = os.environ.get("AISOC_LLM", "http://127.0.0.1:8082/v1/chat/completions")
LLM_MODEL = os.environ.get("AISOC_MODEL", "Qwen3.6-27B-MTP-Q4_K_S")

WINDOW_SECS = 86400
MAX_DECISIONS = 100

DIGEST_PROMPT = """You are the daily digest writer for a home AI SOC. Below is a \
JSON list of the last 24 hours of triage decisions — one per detected event, each \
with a verdict (BLOCK/WATCH/IGNORE), the IP involved, the Suricata signature, and \
the reason the triage model gave.

Write a plain-text security summary, no markdown, no JSON, at most 12 lines:
- lead with the most important events: any BLOCK actions, new or escalating \
repeat offenders, and anything that looks like real hostile activity
- note trends: repeated signatures, a source scanning the desktop, odd outbound \
behaviour
- state clearly if the day was quiet
Do not invent facts not present in the data."""

log = logging.getLogger("aisoc-digest")


def last_day_decisions():
    cutoff = time.time() - WINDOW_SECS
    out = []
    try:
        with open(DECISIONS) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = e.get("ts", "")
                # ts is "%Y-%m-%dT%H:%M:%S%z" — compare structurally; parsing
                # tz offsets without stdlib limits is more code than it saves
                try:
                    parsed = time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
                    if time.mktime(parsed) < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
                out.append(e)
    except OSError as e:
        log.warning("cannot read %s: %s", DECISIONS, e)
    # keep the NEWEST, not the oldest: truncating from the front meant that on
    # a busy day the digest described the small hours and dropped the events
    # that actually mattered
    if len(out) > MAX_DECISIONS:
        out = [{"truncated": len(out) - MAX_DECISIONS}] + out[-MAX_DECISIONS:]
    return out


def summarize(decisions):
    if not decisions:
        return "No security alerts triaged in the last 24h. Day was quiet."
    payload = {
        "model": LLM_MODEL,
        "temperature": 0.3,
        "max_tokens": 1024,
        "chat_template_kwargs": {"enable_thinking": False},
        "messages": [
            {"role": "system", "content": DIGEST_PROMPT},
            {"role": "user", "content": json.dumps(decisions)[:16000]},
        ],
    }
    req = urllib.request.Request(
        LLM_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        msg = json.load(resp)["choices"][0]["message"]
    return (msg.get("content") or "Summary unavailable").strip()


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    decisions = last_day_decisions()
    try:
        digest = summarize(decisions)
    except Exception as e:
        # a down model must not cost the day's report entirely — the counts are
        # the part you can still act on
        log.warning("summarize failed, falling back to counts: %s", e)
        verdicts = collections.Counter(d.get("verdict", "?") for d in decisions)
        digest = (f"Digest model unavailable ({e}).\n"
                  f"{len(decisions)} decisions in the last 24h: "
                  + ", ".join(f"{v} {k}" for k, v in verdicts.most_common()))
    print(digest)
    notify.push(digest, title="AI SOC daily digest", priority="low")


if __name__ == "__main__":
    main()
