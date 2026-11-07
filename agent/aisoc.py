#!/usr/bin/env python3
"""AI SOC agent.

Tails Suricata's eve.json, triages alerts with a local LLM (llama.cpp,
OpenAI-compatible), and blocks hostile IPs via an nftables set whose
elements auto-expire. The LLM only ever returns a verdict; every hard
safety decision (what may never be blocked, timeouts) is enforced here.

Usage:
  aisoc.py run              24/7 loop (root, via systemd)
  aisoc.py block IP [MIN]   manual block (default 60 min)
  aisoc.py unblock IP
  aisoc.py status           nft table + last decisions + top offenders
  aisoc.py test-llm         triage a canned alert end-to-end (no blocking)
"""

import hashlib
import ipaddress
import json
import logging
import os
import pwd
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

from config import (
    AUTOBLOCK,
    BASE,
    COOLDOWN,
    CONTROL_GROUP,
    CONTROL_MAX_BLOCK_SECS,
    CONTROL_MAX_CONNECTIONS,
    CONTROL_MAX_QUEUE,
    CONTROL_MAX_REQUEST,
    CONTROL_SOCKET,
    CONTROL_TIMEOUT,
    CONTROL_USERS,
    DECISIONS,
    EVE_PATHS,
    FAST_IGNORE_CONFIDENCE,
    FAST_LLM_URL,
    FAST_MAX_TOKENS,
    FAST_MODEL,
    FAST_TIMEOUT,
    HOST_EVENTS,
    LLM_MODEL,
    LLM_TIMEOUT,
    LLM_URL,
    LOKI_URL,
    MAX_BLOCKS_PER_HOUR,
    MAX_HISTORY_IPS,
    MAX_SEVERITY,
    MIN_CONFIDENCE,
    TOOLS_ENABLED,
    VPN_CONFIG_DIR,
    VPN_IFACE_RE,
)
from guard import Guard, _cmd, own_ips
from helpers import process_lookup, vpn_quick
from history import ControlLedger, OffenderStore, block_seconds
from ipc import recv_bytes, send_frame
from nft import ensure_nft, nft_block, nft_blocked, nft_unblock
from prompt import SYSTEM_PROMPT

log = logging.getLogger("aisoc")


log = logging.getLogger("aisoc")









# ---------------------------------------------------------------- control socket



def configured_control_uids(spec=CONTROL_USERS):
    """Resolve an explicit comma-separated UID/user allowlist.

    Development defaults to the process UID. Production units set the dedicated
    core account explicitly; a misspelled explicit account resolves to nobody,
    never to a broader fallback.
    """
    if not spec.strip():
        return {os.getuid()}
    out = set()
    for raw in spec.split(","):
        value = raw.strip()
        if not value:
            continue
        try:
            out.add(int(value) if value.isdigit() else pwd.getpwnam(value).pw_uid)
        except KeyError:
            log.error("control user %s does not exist; it will not be authorized", value)
    return out

class ControlServer:
    """Accepts local block/unblock/list requests and hands them to the main loop.

    Connections are served on their own threads so a slow caller cannot stall
    triage, but nothing is executed there: requests go on a queue that the main
    loop drains, keeping nft, the offender DB and the rate cap single-writer and
    lock-free. The caller blocks until the main loop answers, so the console can
    show a real refusal reason instead of guessing.
    """

    def __init__(self, path=CONTROL_SOCKET, group=CONTROL_GROUP, allowed_uids=None):
        self.path = path
        self.group = group
        self.allowed_uids = configured_control_uids() if allowed_uids is None else set(allowed_uids)
        self.requests = queue.Queue(maxsize=CONTROL_MAX_QUEUE)
        self.connections = threading.BoundedSemaphore(CONTROL_MAX_CONNECTIONS)
        self.sock = None

    def start(self):
        """Bring the socket up. Never fatal: losing the console must not stop
        the agent from protecting the host, and AF_UNIX paths over 107 bytes
        fail at bind() rather than at configuration time."""
        try:
            self._bind()
        except OSError as e:
            log.error("control socket %s unavailable (%s); triage continues, "
                      "the console cannot request blocks", self.path, e)
            if self.sock is not None:
                self.sock.close()
            self.sock = None

    def _bind(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        # Narrow the mode before anyone can connect: between bind and chmod the
        # socket would otherwise sit at the process umask.
        os.chmod(self.path, 0o660)
        if self.group:
            try:
                shutil.chown(self.path, group=self.group)
            except (LookupError, PermissionError, OSError) as e:
                log.warning("control socket group %s not applied (%s); "
                            "only %s can reach it", self.group, e, os.getuid())
        self.sock.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()
        log.info("control socket at %s group=%s allowed_uids=%s",
                 self.path, self.group or "-", sorted(self.allowed_uids))

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if not self.connections.acquire(blocking=False):
                conn.close()
                log.warning("control connection refused: concurrency limit reached")
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            with conn:
                conn.settimeout(CONTROL_TIMEOUT)
                try:
                    pid, uid, gid = struct.unpack(
                        "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid not in self.allowed_uids:
                        log.warning("control peer refused pid=%s uid=%s gid=%s", pid, uid, gid)
                        send_frame(conn, {"ok": False, "refused": "unauthorized_peer"})
                        return
                    req = json.loads(recv_bytes(conn, CONTROL_MAX_REQUEST).decode("utf-8"))
                    if not isinstance(req, dict):
                        raise ValueError("request must be an object")
                    try:
                        peer_user = pwd.getpwuid(uid).pw_name
                    except KeyError:
                        peer_user = f"uid-{uid}"
                    req["_peer"] = {"pid": pid, "uid": uid, "gid": gid,
                                    "user": peer_user}
                    if req.get("op") == "process_lookup":
                        reply = process_lookup(req)
                    else:
                        slot, done = {}, threading.Event()
                        try:
                            self.requests.put((req, slot, done), timeout=0.1)
                        except queue.Full:
                            send_frame(conn, {"ok": False, "error": "agent queue full"})
                            return
                        reply = slot if done.wait(CONTROL_TIMEOUT) else {
                            "ok": False, "error": "agent busy"}
                except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as e:
                    reply = {"ok": False, "error": f"bad request: {e}"}
                try:
                    send_frame(conn, reply)
                except OSError:
                    pass
        finally:
            self.connections.release()

    def poll(self, handler):
        """Drain queued requests on the caller's thread. Never raises."""
        while True:
            try:
                req, slot, done = self.requests.get_nowait()
            except queue.Empty:
                return
            try:
                slot.update(handler(req))
            except Exception as e:
                log.exception("control request failed")
                slot.update({"ok": False, "error": str(e)})
            finally:
                done.set()


# ---------------------------------------------------------------- enrichment

_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def sanitize(v, maxlen=200):
    """Neutralize wire-derived strings before they reach the LLM, journald,
    or a terminal: strip control chars/ANSI, cap lengths and collection sizes."""
    if isinstance(v, str):
        return _UNPRINTABLE.sub("?", v)[:maxlen]
    if isinstance(v, dict):
        return {sanitize(k, 60): sanitize(x) for k, x in list(v.items())[:20]}
    if isinstance(v, list):
        return [sanitize(x) for x in v[:10]]
    return v


_rdap_cache = {}


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def rdap(ip):
    if ip in _rdap_cache:
        return _rdap_cache[ip]
    info = None
    try:
        req = urllib.request.Request(
            f"https://rdap.org/ip/{ip}", headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.load(resp)
        info = {"name": data.get("name"), "country": data.get("country"),
                "handle": data.get("handle")}
    except Exception as e:
        log.debug("rdap %s failed: %s", ip, e)
    _rdap_cache[ip] = info
    if len(_rdap_cache) > 2000:
        _rdap_cache.clear()
    return info


# ---------------------------------------------------------------- loki

_loki_down_until = 0


def loki_push(stream, record):
    """Best-effort ship to Loki; a dead Loki must never stall triage."""
    global _loki_down_until
    if not LOKI_URL or time.time() < _loki_down_until:
        return
    body = json.dumps({"streams": [{
        "stream": {"job": "aisoc", "stream": stream},
        "values": [[str(time.time_ns()), json.dumps(record)]],
    }]}).encode()
    req = urllib.request.Request(
        f"{LOKI_URL}/loki/api/v1/push", data=body,
        headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=3).close()
    except Exception as e:
        log.debug("loki push failed: %s", e)
        _loki_down_until = time.time() + 300


# ---------------------------------------------------------------- tools

def _http_get_json(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def tool_abuseipdb(ip):
    key = os.environ.get("AISOC_ABUSEIPDB_KEY", "")
    if not key:
        return "tool unavailable: AISOC_ABUSEIPDB_KEY not set"
    data = _http_get_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": key, "Accept": "application/json"})
    d = data.get("data", {})
    return json.dumps({
        "abuseConfidenceScore": d.get("abuseConfidenceScore"),
        "totalReports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "usageType": d.get("usageType"),
        "isWhitelisted": d.get("isWhitelisted"),
    })


def tool_virustotal(ip):
    key = os.environ.get("AISOC_VIRUSTOTAL_KEY", "")
    if not key:
        return "tool unavailable: AISOC_VIRUSTOTAL_KEY not set"
    data = _http_get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key})
    a = data.get("data", {}).get("attributes", {})
    return json.dumps({
        "last_analysis_stats": a.get("last_analysis_stats"),
        "reputation": a.get("reputation"),
        "total_votes": a.get("total_votes"),
    })


def tool_dns_history(domain):
    key = os.environ.get("AISOC_DNSHISTORY_KEY", "")
    if not key:
        return "tool unavailable: AISOC_DNSHISTORY_KEY not set"
    data = _http_get_json(
        f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
        headers={"APIKEY": key})
    records = data.get("records", [])[:5]
    return json.dumps([
        {"value": r.get("value"), "first_seen": r.get("first_seen"),
         "last_seen": r.get("last_seen")} for r in records])


# name -> (description, parameters schema, callable(ip_or_domain) -> str, env key)
TOOLS = {
    "abuseipdb_lookup": {
        "description": "Query AbuseIPDB for the abuse history of an IP address. "
                       "Returns a confidence score, report count, and usage type.",
        "parameters": {"type": "object",
                       "properties": {"ip": {"type": "string",
                                             "description": "IPv4 or IPv6 address"}},
                       "required": ["ip"]},
        "fn": tool_abuseipdb, "env": "AISOC_ABUSEIPDB_KEY",
    },
    "virustotal_lookup": {
        "description": "Query VirusTotal for the last analysis stats of an IP "
                       "address (malicious/harmless counts and reputation).",
        "parameters": {"type": "object",
                       "properties": {"ip": {"type": "string",
                                             "description": "IPv4 or IPv6 address"}},
                       "required": ["ip"]},
        "fn": tool_virustotal, "env": "AISOC_VIRUSTOTAL_KEY",
    },
    "dns_history": {
        "description": "Look up historical DNS A records for a domain, useful to "
                       "spot fast-flux or suspicious hosting changes.",
        "parameters": {"type": "object",
                       "properties": {"domain": {"type": "string",
                                                 "description": "domain name"}},
                       "required": ["domain"]},
        "fn": tool_dns_history, "env": "AISOC_DNSHISTORY_KEY",
    },
}

# no-key tool: does the LLM already see recent activity from this IP? provide it
TOOL_PORT_SCAN = {
    "description": "Local context: what the agent has already observed from this "
                   "IP (recent signatures and how many times).",
    "parameters": {"type": "object",
                   "properties": {"ip": {"type": "string",
                                         "description": "IPv4 or IPv6 address"}},
                   "required": ["ip"]},
}


def available_tools(history):
    """Tool schemas for this round: key-gated tools that have a key, plus the
    always-available local context tool. Passed to the LLM, not executed here."""
    tools = [{"type": "function",
              "function": {"name": "port_scan_context",
                           "description": TOOL_PORT_SCAN["description"],
                           "parameters": TOOL_PORT_SCAN["parameters"]}}]
    for name, t in TOOLS.items():
        if os.environ.get(t["env"]):
            tools.append({"type": "function",
                          "function": {"name": name,
                                       "description": t["description"],
                                       "parameters": t["parameters"]}})
    return tools


def run_tool(name, args, history):
    """Execute one tool call. Read-only lookups only — nothing here can block."""
    if name == "port_scan_context":
        ip = args.get("ip", "")
        recent = history.get(ip, [])
        return json.dumps({"recent_signatures": recent,
                           "count": len(recent)})
    t = TOOLS.get(name)
    if not t:
        return "unknown tool"
    target = args.get("ip") or args.get("domain", "")
    try:
        return sanitize(t["fn"](target), 800)
    except Exception as e:
        return f"lookup failed: {e}"


# ---------------------------------------------------------------- LLM

def _parse_verdict(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    m = None
    for m in re.finditer(r"\{[^{}]*\}", text):
        pass
    if not m:
        raise ValueError(f"no JSON in LLM reply: {text[:200]!r}")
    verdict = json.loads(m.group(0))
    if verdict.get("verdict") not in ("BLOCK", "WATCH", "IGNORE"):
        raise ValueError(f"bad verdict: {verdict}")
    verdict["confidence"] = float(verdict.get("confidence", 0))
    return verdict


def llm_verdict(url, model, context, *, timeout=LLM_TIMEOUT, max_tokens=4096,
                thinking=True, tools=None, run_tool=None, max_rounds=3):
    """One triage call. Without tools: single shot. With tools: agentic loop —
    the model may call tools (read-only enrichment) before giving a verdict.
    The verdict is still just a suggestion; enforcement stays in Python."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(context, indent=1)},
    ]
    payload = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if not thinking:
        # the CPU-served fast tier burns its whole budget on reasoning otherwise
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    if tools:
        payload["tools"] = tools
    for _ in range(max_rounds + 1):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            msg = json.load(resp)["choices"][0]["message"]
        calls = msg.get("tool_calls")
        if not calls:
            return _parse_verdict(msg.get("content") or "")
        if not run_tool:
            break  # tools offered but no executor bound; fail closed
        # feed the tool requests and results back as the next turn
        messages.append({"role": "assistant",
                         "content": msg.get("content") or "",
                         "tool_calls": calls})
        for tc in calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except (ValueError, TypeError):
                args = {}
            result = run_tool(name, sanitize(args))
            messages.append({"role": "tool", "tool_call_id": tc["id"],
                             "content": result})
        payload["messages"] = messages
    raise ValueError(f"no verdict after {max_rounds} tool rounds")


def llm_triage(context, tools=None, run_tool=None):
    return llm_verdict(LLM_URL, LLM_MODEL, context, tools=tools, run_tool=run_tool)


# ---------------------------------------------------------------- event tails

def tail_jsonl(path):
    """Yield parsed records from a JSONL file forever; survives rotation and
    missing file. Yields None when idle so the caller can multiplex sources.

    Never sleeps: an idle source must not stall the other sources sharing the
    loop. multiplex() owns the sleeping.
    """
    f = None
    inode = None
    pending = ""       # partial trailing line, carried until its newline lands
    retry_at = 0.0
    while True:
        if f is None:
            if time.time() < retry_at:
                yield None
                continue
            try:
                f = open(path)
                inode = os.fstat(f.fileno()).st_ino
                f.seek(0, os.SEEK_END)  # don't replay history on startup
                pending = ""
                log.info("tailing %s", path)
            except OSError:
                retry_at = time.time() + 5
                yield None
                continue
        line = f.readline()
        if line:
            # a read can land mid-line: the offset has already moved past it,
            # so dropping it here loses the record outright
            if not line.endswith("\n"):
                pending += line
                yield None
                continue
            if pending:
                line, pending = pending + line, ""
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                log.debug("undecodable line in %s", path)
            continue
        try:
            st = os.stat(path)
            rotated = st.st_ino != inode or st.st_size < f.tell()
        except OSError:
            rotated = True
        if rotated:
            f.close()
            f = None
            pending = ""
            # reopen at start: post-rotation content is all new
            try:
                f = open(path)
                inode = os.fstat(f.fileno()).st_ino
            except OSError:
                f = None
                retry_at = time.time() + 5
        yield None


def multiplex(paths, idle=0.5):
    """Round-robin several JSONL tails, sleeping only when every source is dry.

    One tail per vantage point (clear-text tunnel, physical NIC, auditd bridge).
    They must not sleep individually: the previous version polled a permanently
    empty auditd stream once per iteration and its 1s sleep capped the whole
    agent near one event per second regardless of how far behind eve.json was.
    """
    tails = [tail_jsonl(p) for p in paths]
    while True:
        idled = True
        for t in tails:
            ev = next(t)
            if ev is not None:
                idled = False
                yield ev
        if idled:
            time.sleep(idle)
            yield None


# ---------------------------------------------------------------- agent

class Agent:
    def __init__(self):
        self.guard = Guard()
        self.seen = {}       # (sig_id, ip) -> [last_triage_ts, count_since]
        self.offenders = OffenderStore()
        self.control_ledger = ControlLedger()
        self.history = {}    # ip -> recent signature names
        self.block_log = []  # timestamps of recent blocks, for the rate cap
        self.control = ControlServer()

    def prune(self):
        """Drop dedupe/history state that can no longer affect a decision.

        Both dicts gain an entry per unique (signature, IP) and per IP and were
        never trimmed. A scan sweep, or the LAN-wide mirror on the roadmap,
        turns that into the leak that ends the process. Nothing here is load
        bearing beyond COOLDOWN: repeat-offender escalation lives in SQLite.
        """
        cutoff = time.time() - COOLDOWN
        self.seen = {k: v for k, v in self.seen.items() if v[0] > cutoff}
        # history outlives the cooldown on purpose — port_scan_context escalates
        # on what an IP did earlier in the session — so bound it by size, oldest
        # first-seen evicted, rather than by the dedupe window
        while len(self.history) > MAX_HISTORY_IPS:
            self.history.pop(next(iter(self.history)))

    def remote_ip(self, ev):
        # direction keys off our own addresses only — allowlist entries must
        # not be able to skew it
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        own = self.guard.own
        if src in own and dst not in own:
            return dst, "outbound"
        if dst in own and src not in own:
            return src, "inbound"
        return src, "inbound"

    def record(self, entry):
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(DECISIONS, "a") as f:
            f.write(json.dumps(entry) + "\n")
        loki_push("decisions", entry)

    def triage_verdict(self, context, severity):
        """Run the LLM tier logic; returns (verdict, tier)."""
        tier = "full"
        verdict = None
        if FAST_LLM_URL:
            try:
                fast = llm_verdict(FAST_LLM_URL, FAST_MODEL, context,
                                   timeout=FAST_TIMEOUT,
                                   max_tokens=FAST_MAX_TOKENS,
                                   thinking=False)
                log.info("fast %s: %s conf=%.2f", FAST_MODEL,
                         fast["verdict"], fast["confidence"])
            except Exception as e:
                log.warning("fast tier failed (%s); escalating to %s",
                            e, LLM_MODEL)
                fast = None
            if fast and (fast["verdict"] == "IGNORE"
                         and fast["confidence"] >= FAST_IGNORE_CONFIDENCE
                         and severity > 1):
                verdict = fast
                tier = "fast"
            elif fast:
                log.info("escalating %s conf=%.2f to %s",
                         fast["verdict"], fast["confidence"], LLM_MODEL)
        if verdict is None:
            try:
                if TOOLS_ENABLED:
                    tools = available_tools(self.history)
                    verdict = llm_triage(context, tools=tools,
                                         run_tool=lambda n, a: run_tool(n, a, self.history))
                else:
                    verdict = llm_triage(context)
            except Exception as e:
                log.warning("LLM triage failed (%s); logging as WATCH", e)
                verdict = {"verdict": "WATCH", "confidence": 0,
                           "reason": f"llm_error: {e}"}
            if severity == 1 and verdict["verdict"] == "IGNORE":
                # a sev-1 IGNORE may itself be injection-driven evasion
                verdict = {**verdict, "verdict": "WATCH",
                           "reason": "sev-1 floored to WATCH | "
                                     + sanitize(str(verdict.get("reason", "")))}
        return verdict, tier

    def handle(self, ev):
        alert = ev.get("alert", {})
        severity = alert.get("severity", 3)
        sig = sanitize(alert.get("signature", "?"), 160)
        ip, direction = self.remote_ip(ev)
        if not ip:
            # decoder-level alerts (truncated packet, bad checksum) carry no
            # addresses. Nothing to enrich, nothing an nft rule could act on.
            log.debug("no remote ip, skipping: %s", sig)
            return
        key = (alert.get("signature_id"), ip)

        hist = self.history.setdefault(ip, [])
        if sig not in hist:
            hist.append(sig)
            del hist[:-5]

        now = time.time()
        last, count = self.seen.get(key, (0, 0))
        if now - last < COOLDOWN:
            self.seen[key] = (last, count + 1)
            return
        if severity > MAX_SEVERITY and not AUTOBLOCK.match(sig):
            self.seen[key] = (now, 0)
            return
        self.seen[key] = (now, 0)

        tier = "policy"
        if AUTOBLOCK.match(sig):
            # policy tier: reputation-feed hits skip the LLM entirely, so they
            # work through prompt injection and LLM downtime alike
            verdict = {"verdict": "BLOCK", "confidence": 1.0,
                       "reason": f"reputation auto-block: {sig}"}
        else:
            context = {
                "alert": {
                    "signature": sig,
                    "signature_id": alert.get("signature_id"),
                    "category": sanitize(alert.get("category")),
                    "severity": severity,
                },
                "src_ip": ev.get("src_ip"), "src_port": ev.get("src_port"),
                "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
                "proto": ev.get("proto"), "app_proto": ev.get("app_proto"),
                "direction": direction,
                "remote_ip": ip,
                "occurrences_since_last_triage": count + 1,
                "untrusted_observed_data": sanitize({
                    "remote_rdns": rdns(ip),
                    "remote_rdap": None if self.guard.is_protected(ip) else rdap(ip),
                    "recent_signatures_from_this_ip": hist,
                    **{k: ev[k] for k in ("http", "dns", "tls", "ssh") if k in ev},
                }),
            }
            log.info("triaging sev=%s %s %s (%s)", severity, direction, ip, sig)
            verdict, tier = self.triage_verdict(context, severity)

        action = "logged"
        if verdict["verdict"] == "BLOCK":
            self.block_log = [t for t in self.block_log if now - t < 3600]
            if self.guard.is_protected(ip):
                action = "refused_protected_ip"
            elif verdict["confidence"] < MIN_CONFIDENCE:
                action = "downgraded_low_confidence"
            elif len(self.block_log) >= MAX_BLOCKS_PER_HOUR:
                action = "rate_limited"
            else:
                n = self.offenders.bump(ip)
                secs = block_seconds(n)
                ok, err = nft_block(ip, secs)
                action = f"blocked_{secs}s" if ok else f"block_failed: {err}"
                if ok:
                    self.block_log.append(now)

        verdict["reason"] = sanitize(str(verdict.get("reason", "")), 300)
        log.info("%s %s conf=%.2f -> %s | %s",
                 verdict["verdict"], ip, verdict["confidence"], action, verdict["reason"])
        self.record({"ip": ip, "direction": direction, "signature": sig,
                     "severity": severity, "tier": tier,
                     **verdict, "action": action})

    def handle_host(self, ev):
        """Host-based signals (auditd): same triage loop, no remote IP to block."""
        alert = ev.get("alert", {})
        severity = alert.get("severity", 3)
        sig = sanitize(alert.get("signature", "?"), 160)
        observed = sanitize(ev.get("untrusted_observed_data", {}))
        key = (alert.get("signature_id"), "host")

        now = time.time()
        last, count = self.seen.get(key, (0, 0))
        if now - last < COOLDOWN:
            self.seen[key] = (last, count + 1)
            return
        if severity > MAX_SEVERITY:
            self.seen[key] = (now, 0)
            return
        self.seen[key] = (now, 0)

        context = {
            "event_type": "host",
            "alert": {
                "signature": sig,
                "signature_id": alert.get("signature_id"),
                "category": sanitize(alert.get("category")),
                "severity": severity,
            },
            "occurrences_since_last_triage": count + 1,
            "untrusted_observed_data": observed,
        }
        log.info("triaging host sev=%s %s", severity, sig)
        verdict, tier = self.triage_verdict(context, severity)

        # host events carry no remote IP; a BLOCK verdict is reported, not enforced
        action = "logged"
        if verdict["verdict"] == "BLOCK":
            action = "host_block_reported"
        verdict["reason"] = sanitize(str(verdict.get("reason", "")), 300)
        log.info("%s (host) conf=%.2f -> %s | %s",
                 verdict["verdict"], verdict["confidence"], action, verdict["reason"])
        self.record({"ip": "host", "direction": "host", "signature": sig,
                     "severity": severity, "tier": tier,
                     **verdict, "action": action})

    def handle_control(self, req):
        """Serve one console request. Runs on the main thread via ControlServer.poll."""
        op = req.get("op")
        peer = req.get("_peer") if isinstance(req.get("_peer"), dict) else {}
        peer_user = sanitize(str(peer.get("user", f"uid-{peer.get('uid', '?')}")), 60)
        if op in ("vpn_up", "vpn_down", "vpn_replace"):
            result = vpn_quick(
                "replace" if op == "vpn_replace" else "up" if op == "vpn_up" else "down",
                req.get("interface", ""),
                req.get("config", ""),
            )
            log.info("VPN helper %s requested by %s: %s", op, peer_user,
                     "ok" if result.get("ok") else result.get("error"))
            return result
        if op == "vpn_status":
            interface = req.get("interface", "")
            if not isinstance(interface, str) or not VPN_IFACE_RE.fullmatch(interface):
                return {"ok": False, "error": "invalid VPN interface name"}
            status = _cmd(["wg", "show", interface, "dump"])
            if status.returncode != 0:
                return {"ok": False,
                        "error": (status.stderr or status.stdout or "").strip()[-1000:] or None}
            return {"ok": True, "dump": status.stdout}
        if op == "list":
            now = time.time()
            return {"ok": True, "blocked": nft_blocked(),
                    "protected": self.guard.listed(),
                    "blocks_last_hour": len([t for t in self.block_log if now - t < 3600]),
                    "max_blocks_per_hour": MAX_BLOCKS_PER_HOUR}
        if op not in ("block", "unblock"):
            return {"ok": False, "error": f"unknown op {op!r}"}

        ip = str(req.get("ip", ""))
        requested_by = sanitize(str(req.get("requested_by", "unknown")), 60)
        reason = sanitize(str(req.get("reason", "")), 300)
        action_id = str(req.get("action_id", ""))
        policy_version = sanitize(str(req.get("policy_version", "")), 80)
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return {"ok": False, "refused": "invalid_ip"}
        try:
            if str(uuid.UUID(action_id)) != action_id.lower():
                raise ValueError("non-canonical UUID")
        except ValueError:
            return {"ok": False, "refused": "invalid_action_id"}
        if not policy_version:
            return {"ok": False, "refused": "missing_policy_version"}

        minutes = req.get("minutes")
        if op == "block" and minutes is not None:
            if isinstance(minutes, bool) or not isinstance(minutes, int):
                return {"ok": False, "refused": "invalid_ttl"}
            if minutes < 1 or minutes * 60 > CONTROL_MAX_BLOCK_SECS:
                return {"ok": False, "refused": "ttl_out_of_range"}

        canonical = {"op": op, "ip": ip, "minutes": minutes,
                     "requested_by": requested_by, "reason": reason,
                     "policy_version": policy_version}
        request_hash = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        ledger_state, cached = self.control_ledger.begin(action_id, request_hash)
        if ledger_state == "complete":
            return {**cached, "replayed": True}
        if ledger_state == "conflict":
            return {"ok": False, "refused": "action_id_conflict"}
        if ledger_state == "pending":
            return {"ok": False, "refused": "action_in_progress"}
        if ledger_state == "unavailable":
            return {"ok": False, "refused": "audit_unavailable"}

        def finish(response):
            # Do not claim success unless its idempotency/audit result is durable.
            if not self.control_ledger.complete(action_id, response):
                return {"ok": False, "refused": "audit_unavailable",
                        "effect_may_have_applied": bool(response.get("ok"))}
            return response

        if op == "unblock":
            ok, err = nft_unblock(ip)
            err = err or ("" if ok else "no such element in the set")
            self.record({"ip": ip, "direction": "control", "signature": f"control:{peer_user}",
                         "severity": None, "tier": "console", "verdict": "UNBLOCK",
                         "confidence": 1.0, "reason": reason, "action_id": action_id,
                         "requested_by": requested_by, "peer_uid": peer.get("uid"),
                         "policy_version": policy_version,
                         "action": "unblocked" if ok else f"unblock_failed: {err}"})
            return finish({"ok": ok, "error": err or None})

        # A block asked for by the console goes through exactly the checks an
        # LLM verdict does. The console is not more trusted than the model: its
        # playbooks fire automatically too.
        now = time.time()
        self.block_log = [t for t in self.block_log if now - t < 3600]
        refusal = None
        if self.guard.is_protected(ip):
            refusal = "protected"
        elif len(self.block_log) >= MAX_BLOCKS_PER_HOUR:
            refusal = "rate_limited"
        if refusal:
            self.record({"ip": ip, "direction": "control", "signature": f"control:{peer_user}",
                         "severity": None, "tier": "console", "verdict": "BLOCK",
                         "confidence": 1.0, "reason": reason, "action_id": action_id,
                         "requested_by": requested_by, "peer_uid": peer.get("uid"),
                         "policy_version": policy_version,
                         "action": f"refused_{refusal}"})
            return finish({"ok": False, "refused": refusal})

        offenses = self.offenders.bump(ip)
        secs = int(minutes) * 60 if minutes else block_seconds(offenses)
        ok, err = nft_block(ip, secs)
        if ok:
            self.block_log.append(now)
        self.record({"ip": ip, "direction": "control", "signature": f"control:{peer_user}",
                     "severity": None, "tier": "console", "verdict": "BLOCK",
                     "confidence": 1.0, "reason": reason, "action_id": action_id,
                     "requested_by": requested_by, "peer_uid": peer.get("uid"),
                     "policy_version": policy_version,
                     "action": f"blocked_{secs}s" if ok else f"block_failed: {err}"})
        return finish({"ok": ok, "seconds": secs, "offenses": offenses,
                       "error": err or None})

    def run(self):
        ensure_nft()
        self.control.start()
        log.info("guarding; protected=%d ips, llm=%s", len(self.guard.protected), LLM_URL)
        last_refresh = time.time()
        sources = EVE_PATHS + ([HOST_EVENTS] if HOST_EVENTS else [])
        stream = multiplex(sources)
        while True:
            if time.time() - last_refresh > 300:
                self.guard.refresh()
                self.prune()
                last_refresh = time.time()
            # multiplex idles at 0.5s, so a console request waits at most that
            self.control.poll(self.handle_control)
            ev = next(stream)
            if ev is None:
                continue
            if ev.get("_source") == "host" or ev.get("event_type") == "alert":
                self._dispatch(ev)

    def _dispatch(self, ev):
        if ev.get("_source") == "host":
            try:
                self.handle_host(ev)
            except Exception:
                log.exception("host handler error")
            return
        if ev.get("event_type") == "alert":
            a = ev.get("alert", {})
            loki_push("alerts", {
                "src_ip": ev.get("src_ip"), "dest_ip": ev.get("dest_ip"),
                "dest_port": ev.get("dest_port"), "proto": ev.get("proto"),
                "signature": a.get("signature"), "category": a.get("category"),
                "severity": a.get("severity"),
            })
            try:
                self.handle(ev)
            except Exception:
                log.exception("handler error")


# ---------------------------------------------------------------- cli

TEST_ALERT = {
    "event_type": "alert", "proto": "TCP",
    "src_ip": "185.220.101.34", "src_port": 51234,
    "dest_ip": "192.0.2.9", "dest_port": 22,
    "alert": {"signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219,
              "category": "Attempted Information Leak", "severity": 2},
}


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        Agent().run()
    elif cmd == "block":
        ip = sys.argv[2]
        minutes = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        if Guard().is_protected(ip):
            sys.exit(f"refusing: {ip} is protected")
        ensure_nft()
        ok, err = nft_block(ip, minutes * 60)
        print("blocked" if ok else f"failed: {err}")
    elif cmd == "unblock":
        ok, err = nft_unblock(sys.argv[2])
        print("unblocked" if ok else f"failed: {err}")
    elif cmd == "status":
        print(_cmd(["nft", "list", "table", "inet", "aisoc"]).stdout or "no aisoc table")
        try:
            with open(DECISIONS) as f:
                lines = f.readlines()[-10:]
            print("--- last decisions ---")
            sys.stdout.writelines(lines)
        except OSError:
            print("no decisions yet")
        print("--- top offenders (ip, blocks, last block epoch) ---")
        for ip, blocks, last in OffenderStore().top():
            print(f"{ip}  {blocks}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last))}")
    elif cmd == "test-llm":
        agent = Agent()
        ev = dict(TEST_ALERT)
        ip, direction = agent.remote_ip(ev)
        ctx = {**ev, "remote_ip": ip, "direction": direction,
               "remote_rdns": rdns(ip), "remote_rdap": rdap(ip),
               "occurrences_since_last_triage": 1}
        print(json.dumps(llm_triage(ctx), indent=2))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
