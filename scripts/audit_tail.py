#!/usr/bin/env python3
"""auditd -> AI SOC host events.

Tails /var/log/audit/audit.log (root-only) and converts selected events into
the same alert-shaped JSONL the agent already consumes, so host signals flow
through the identical triage loop (same prompt shape, same guardrails).

Emits (stdlib only):
  - curl|bash / wget|sh pipes detected in EXECVE argv       (severity 1)
  - setuid/setgid by a non-root auid (priv_esc rule)        (severity 1)
  - root execve (root_exec rule)                            (severity 2)
  - passwd/shadow/cron/sshd_config writes (identity rules)  (severity 3)
  - btmp writes / login events (logins rule)                (severity 3)

One auditd *event* (a SYSCALL record plus its EXECVE/CWD/PATH companions, all
sharing an audit event id) produces at most one output record. auditd splits an
event across records, and the fields a triage model needs are split with it:
argv lives on EXECVE while tty, auid, ppid and the rule key live on SYSCALL.
Emitting per record therefore produced both duplicates and alerts with no
session context — a `sudo` by an admin at a terminal and a privilege escalation
by malware were literally the same JSON. Merging first is what makes them
distinguishable.

Severity 3 events are counted, not LLM-triaged (AISOC_MAX_SEVERITY=2).
Output is appended to AISOC_HOST_EVENTS (default /var/lib/aisoc/host-events.jsonl)
and chowned to the agent user so the sandboxed service can read it.

Install: copy to /usr/local/bin, systemd oneshot on boot + auditd. Run as root.
"""

import hashlib
import json
import os
import re
import time
from collections import OrderedDict

OUT_PATH = os.environ.get("AISOC_HOST_EVENTS",
    "/var/lib/aisoc-host-events/host-events.jsonl")
AGENT_OWNER = os.environ.get("AISOC_HOST_OWNER", "aisoc:aisoc")
AUDIT_LOG = os.environ.get("AISOC_AUDIT_LOG", "/var/log/audit/audit.log")

# rule key -> (signature, category, severity)
KEY_SIGNATURES = {
    "priv_esc":   ("HOST privilege escalation (setuid/setgid by non-root user)",
                   "Suspicious Local Activity", 1),
    "root_exec":  ("HOST root exec",
                   "Suspicious Local Activity", 2),
    "identity":   ("HOST /etc/passwd or /etc/shadow modified",
                   "System Integrity", 3),
    "cron_change": ("HOST cron/at modified",
                    "System Integrity", 3),
    "sshd_config": ("HOST sshd_config modified",
                    "System Integrity", 3),
    "logins":     ("HOST login record written",
                   "Account Activity", 3),
}

_CURL_PIPE = re.compile(
    r"(curl|wget|lynx|nc)\b.*[;|\n].*(ba)?sh\b"
    r"|(ba)?sh\b.*(\bcurl\b|\bwget\b)")

# "type=X msg=audit(ts:seq): rest"  — rest is key=value tokens, some quoted
_LINE = re.compile(r"type=(\S+)\s+msg=audit\(([^)]*)\):(.*)$", re.S)

# An event is complete when auditd moves on to the next one, so records are held
# only for as long as it takes the next event id to appear. The caps exist
# because a truncated log or a lost EOE must not accumulate forever.
_PENDING_MAX = 256
_PENDING_AGE_S = 5
# Parent lookup goes through /proc, which loses the race against a short-lived
# process. This cache remembers what every pid exec'd, so the parent of a
# process whose own parent already exited is still nameable.
_EXE_CACHE_MAX = 4096

_pending = OrderedDict()
_exe_by_pid = OrderedDict()

# tty on a non-interactive process. auditd writes "(none)" and, on some kernels,
# an empty value.
_NO_TTY = ("", "(none)", "?")


def _tokens(s):
    """Split on whitespace, respecting double/single-quoted values."""
    out, buf, quote = [], "", None
    for ch in s:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf += ch
        elif ch in ('"', "'"):
            quote = ch
        elif ch.isspace():
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


def parse_line(line):
    """(record type, audit event id, fields) or None."""
    m = _LINE.match(line)
    if not m:
        return None
    fields = {}
    for tok in _tokens(m.group(3)):
        if "=" in tok:
            k, _, v = tok.partition("=")
            fields[k] = v
    return m.group(1), m.group(2), fields


def _argv(fields):
    """Reconstruct argv from EXECVE a0..aN fields."""
    args = []
    i = 0
    while f"a{i}" in fields:
        args.append(fields[f"a{i}"])
        i += 1
    return args


def _remember_exe(fields):
    pid, exe = fields.get("pid"), fields.get("exe")
    if not pid or not exe or exe == "(null)":
        return
    _exe_by_pid[pid] = exe
    _exe_by_pid.move_to_end(pid)
    while len(_exe_by_pid) > _EXE_CACHE_MAX:
        _exe_by_pid.popitem(last=False)


def parent_exe(ppid):
    """Best-effort parent executable: exec cache first, then /proc."""
    if not ppid:
        return ""
    cached = _exe_by_pid.get(ppid)
    if cached:
        return cached
    try:
        return os.readlink(f"/proc/{ppid}/exe")
    except OSError:
        return ""


def absorb(etype, evid, fields, now=None):
    """Fold one record into its event. Returns the events that are now complete."""
    now = time.time() if now is None else now
    event = _pending.get(evid)
    if event is None:
        event = {"_evid": evid, "_types": set(), "_argv": "", "_at": now}
        _pending[evid] = event
    event["_types"].add(etype)

    if etype == "EXECVE":
        argv = " ".join(_argv(fields))
        if argv:
            event["_argv"] = (event["_argv"] + " " + argv).strip()
        return _reap(now)

    # SYSCALL carries the identity of the event; PATH/CWD only add context, and
    # neither may overwrite a field the SYSCALL record already set.
    if etype == "SYSCALL":
        _remember_exe(fields)
    for k, v in fields.items():
        if etype == "SYSCALL" or k not in event:
            event[k] = v
    return _reap(now)


def _reap(now):
    """Complete every event older than the one currently being written."""
    done = []
    while _pending:
        evid, event = next(iter(_pending.items()))
        if evid == next(reversed(_pending)) and now - event["_at"] < _PENDING_AGE_S \
                and len(_pending) <= _PENDING_MAX:
            break
        done.append(_pending.pop(evid))
    return done


def flush_idle(now=None):
    """Called when the log goes quiet, so the last event is not held forever."""
    now = time.time() if now is None else now
    done = []
    for evid in list(_pending):
        if now - _pending[evid]["_at"] >= _PENDING_AGE_S:
            done.append(_pending.pop(evid))
    return done


def host_event(event):
    """Map one merged audit event to an agent event, or None if not interesting."""
    key = event.get("key", "")
    argv = event.get("_argv", "")

    if argv and _CURL_PIPE.search(argv):
        return _mk(event, "HOST curl|bash shell pipe",
                   "Suspicious Local Activity", 1,
                   detail=argv[:300])

    if "SYSCALL" in event["_types"] and key in KEY_SIGNATURES:
        sig, cat, sev = KEY_SIGNATURES[key]
        detail = f"{event.get('comm', '?')} exe={event.get('exe', '?')}"
        if argv:
            detail += f" argv={argv[:300]}"
        return _mk(event, sig, cat, sev, detail=detail)
    return None


def _stable_id(sig, detail):
    """A signature id that survives a restart; hash() is salted per process."""
    digest = hashlib.blake2s(f"{sig}\0{detail}".encode(), digest_size=4).digest()
    return int.from_bytes(digest, "big") % (2 ** 31)


def _mk(event, sig, cat, sev, detail):
    tty = event.get("tty", "")
    ppid = event.get("ppid", "")
    return {
        "event_type": "alert",
        "_source": "host",
        "proto": "audit",
        "src_ip": event.get("_own_ip", "0.0.0.0"),
        "dest_ip": event.get("_own_ip", "0.0.0.0"),
        "alert": {
            "signature": sig,
            "signature_id": _stable_id(sig, detail),
            "category": cat,
            "severity": sev,
        },
        "untrusted_observed_data": {
            "audit_type": "+".join(sorted(event["_types"])),
            "rule_key": event.get("key", ""),
            "comm": event.get("comm", ""),
            "exe": event.get("exe", ""),
            "argv": detail,
            "uid": event.get("uid", ""),
            "auid": event.get("auid", ""),
            "tty": tty,
            # An admin at a terminal and malware escalating produce the same
            # syscalls. Session context is the only thing that separates them,
            # so it travels with the alert rather than being inferred by the
            # model from an execve it cannot see the origin of.
            "interactive": tty not in _NO_TTY,
            "session": event.get("ses", ""),
            "ppid": ppid,
            "parent_exe": parent_exe(ppid),
            "success": event.get("success", ""),
        },
    }


def own_ip():
    """Best LAN IPv4 for the record; the Guard re-protects regardless."""
    try:
        import subprocess
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True).stdout
        for iface in json.loads(out or "[]"):
            for a in iface.get("addr_info", []):
                ip = a["local"]
                if ip.startswith("192.0.2."):
                    return ip
    except Exception:
        pass
    return "127.0.0.1"


def tail_log():
    """Yields lines, and None whenever the log is idle."""
    f, inode = None, None
    while True:
        if f is None:
            try:
                f = open(AUDIT_LOG)
                inode = os.fstat(f.fileno()).st_ino
                f.seek(0, os.SEEK_END)
            except OSError:
                yield None
                time.sleep(5)
                continue
        line = f.readline()
        if line:
            yield line
            continue
        try:
            st = os.stat(AUDIT_LOG)
            rotated = st.st_ino != inode or st.st_size < f.tell()
        except OSError:
            rotated = True
        if rotated:
            f.close()
            f = None
        yield None
        time.sleep(1)


def main():
    out = open(OUT_PATH, "a", buffering=1)
    try:
        uid, gid = AGENT_OWNER.split(":")
        import grp, pwd
        os.chown(OUT_PATH, pwd.getpwnam(uid).pw_uid, grp.getgrnam(gid).gr_gid)
    except Exception:
        pass
    ip = own_ip()
    for line in tail_log():
        try:
            if line is None:
                complete = flush_idle()
            else:
                parsed = parse_line(line)
                if not parsed:
                    continue
                complete = absorb(*parsed)
            for event in complete:
                event["_own_ip"] = ip
                ev = host_event(event)
                if ev:
                    out.write(json.dumps(ev) + "\n")
        except Exception:
            continue


if __name__ == "__main__":
    main()
