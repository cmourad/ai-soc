#!/usr/bin/env python3
"""Push a short text somewhere a human will actually see it. Stdlib only.

Shared by the daily digest and the watchdog so there is exactly one place that
knows how to reach the operator.

Config (env):
  AISOC_NTFY_URL            ntfy base URL (default https://ntfy.sh)
  AISOC_NTFY_TOPIC          ntfy topic; if unset, falls through to Telegram
  AISOC_TELEGRAM_BOT_TOKEN  Telegram bot token
  AISOC_TELEGRAM_CHAT_ID    Telegram chat id

ntfy.sh topics are unauthenticated: anyone who knows the topic name can read
every message pushed to it. Use a long random topic, or self-host, or prefer
Telegram — a guessable topic publishes your security posture.
"""

import json
import logging
import os
import urllib.error
import urllib.request

log = logging.getLogger("notify")

NTFY_URL = os.environ.get("AISOC_NTFY_URL", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.environ.get("AISOC_NTFY_TOPIC", "")
TG_TOKEN = os.environ.get("AISOC_TELEGRAM_BOT_TOKEN", "")
TG_CHAT = os.environ.get("AISOC_TELEGRAM_CHAT_ID", "")


def configured():
    return bool(NTFY_TOPIC or (TG_TOKEN and TG_CHAT))


def push(text, title="AI SOC", priority="default"):
    """Best-effort delivery. Returns True if something accepted the message.

    Never raises: a notification failure must not take down the caller, which
    is usually a oneshot whose real job already succeeded.
    """
    try:
        if NTFY_TOPIC:
            req = urllib.request.Request(
                f"{NTFY_URL}/{NTFY_TOPIC}", data=text.encode(),
                headers={"Title": title, "Priority": priority})
        elif TG_TOKEN and TG_CHAT:
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                data=json.dumps({"chat_id": TG_CHAT,
                                 "text": f"{title}\n\n{text}"}).encode(),
                headers={"Content-Type": "application/json"})
        else:
            log.info("no push target configured (AISOC_NTFY_TOPIC or Telegram env)")
            return False
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        return True
    except (urllib.error.URLError, OSError) as e:
        log.warning("push failed: %s", e)
        return False
