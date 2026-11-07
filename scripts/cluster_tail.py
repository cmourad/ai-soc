#!/usr/bin/env python3
"""Tetragon + k3s API-server audit -> AI SOC cluster events.

Both source files are root-only and stay that way: the Tetragon export carries
full argv for every exec on this host, and the API-server audit log carries
object metadata for the whole cluster. This collector is the only thing that
reads them. It runs as root, keeps nothing, and appends a *minimised* record to
a spool the unprivileged console reads — the collector/core split from
docs/reference/architecture-target.md, applied to cluster telemetry.

Minimisation is a control, not a convenience:
  - request and response *bodies* are dropped unconditionally, so a regression
    in the audit policy can never push secret material into the spool, the
    console, or an LLM prompt;
  - node labels, pod labels and image digests are dropped: bulk, never evidence;
  - every free-text field is length-capped.

Volume is the other half of the job. Tetragon emits ~100 events/second on this
host, which no triage queue should ever see. The filters below keep what a
detection could plausibly fire on and drop the rest; the export file and Loki
remain the complete evidence copy, and a dropped-count record makes the
filtering visible rather than silent.

Install: run as root from aisoc-cluster-events.service.
"""

import json
import os
import time
from collections import OrderedDict

OUT_PATH = os.environ.get("AISOC_CLUSTER_EVENTS",
    "/var/lib/aisoc-host-events/cluster-events.jsonl")
# The console is the only consumer of this spool, and it runs as aisoc-core —
# not as `aisoc`, which owns the auditd bridge's output because the Python agent
# reads that one. Getting this wrong is silent: the file appears, the setting is
# on, and the reader gets EACCES on a path it can stat.
OWNER = os.environ.get("AISOC_CLUSTER_OWNER", "aisoc-core:aisoc-core")
TETRAGON_LOG = os.environ.get("AISOC_TETRAGON_LOG",
    "/var/run/cilium/tetragon/tetragon.log")
AUDIT_LOG = os.environ.get("AISOC_K8S_AUDIT_LOG",
    "/var/log/k3s-audit/audit.log")

# Emitted events per second. The limit applies to *bulk* records only — routine
# container execs — because a rate limit that treats every record alike lets a
# noisy workload shed the one host exec that mattered. That is not theoretical:
# the first run of this collector dropped a drill's `curl | bash` while faithfully
# recording several hundred container health checks around it. A flood is also
# how an intruder buries an exec, so priority records are never shed and the
# dropped count is reported as its own event.
RATE_PER_SEC = float(os.environ.get("AISOC_CLUSTER_RATE", "50"))
MAX_ARG_LEN = 300

# Binaries worth an event wherever they run. Interpreters and network tools are
# how a foothold becomes execution; credential and container tools are how it
# becomes privilege.
WATCHED_BINARIES = {
    "sh", "bash", "dash", "zsh", "ksh", "busybox", "ash",
    "python", "python3", "perl", "ruby", "php", "node",
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "nmap",
    "sudo", "su", "pkexec", "doas", "chpasswd", "passwd", "useradd", "usermod",
    "kubectl", "crictl", "ctr", "docker", "runc", "nsenter", "unshare",
    "tcpdump", "base64", "xxd", "chattr", "shred",
}
# Namespaces whose every exec is interesting: the emulation namespace, and the
# runners that execute untrusted pull-request code beside production (S5).
WATCHED_NAMESPACES = {"attack-lab", "arc-runners"}

# API resources where a write is an authority change, a credential access, or an
# attempt to disable detection. The catch-all Metadata tier in the audit policy
# exists for Loki; only these reach triage.
AUDIT_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
AUDIT_ALWAYS_RESOURCES = {
    "clusterroles", "clusterrolebindings", "roles", "rolebindings",
    "serviceaccounts", "tracingpolicies", "tracingpoliciesnamespaced",
    "prometheusrules", "networkpolicies", "validatingwebhookconfigurations",
    "mutatingwebhookconfigurations", "validatingadmissionpolicies",
    "validatingadmissionpolicybindings", "certificatesigningrequests",
}
AUDIT_SUBRESOURCES = {"exec", "attach", "portforward", "proxy", "token"}
AUDIT_CREDENTIAL_RESOURCES = {"secrets"}


def cap(value, limit=MAX_ARG_LEN):
    """Bounded, control-character-free text. Anything else becomes ''. """
    if not isinstance(value, str):
        return ""
    out = "".join(ch for ch in value[:limit * 2] if ch.isprintable())
    return out[:limit]


def _pod(process):
    pod = process.get("pod") or {}
    container = pod.get("container") or {}
    return {
        "namespace": cap(pod.get("namespace"), 63),
        "name": cap(pod.get("name"), 253),
        "workload": cap(pod.get("workload"), 253),
        "container": cap(container.get("name"), 63),
    }


def _process(process):
    """Only the fields a detection reads. Everything else is bulk."""
    return {
        "binary": cap(process.get("binary")),
        "arguments": cap(process.get("arguments")),
        "pid": process.get("pid"),
        "uid": process.get("uid"),
        "auid": process.get("auid"),
        "cwd": cap(process.get("cwd"), 120),
        "pod": _pod(process),
    }


def tetragon_record(raw):
    """Trim and filter one Tetragon export record, or None to drop it."""
    kind = "process_exec" if "process_exec" in raw else (
        "process_kprobe" if "process_kprobe" in raw else None)
    if kind is None:
        return None
    body = raw[kind] or {}
    process = body.get("process") or {}
    if not process:
        return None

    binary = process.get("binary") or ""
    namespace = ((process.get("pod") or {}).get("namespace")) or ""
    base = os.path.basename(binary)
    host_process = not namespace

    if kind == "process_exec":
        interesting = (
            base in WATCHED_BINARIES
            or namespace in WATCHED_NAMESPACES
            # A host exec by a real logged-in user: the desktop attack path.
            or (host_process and process.get("auid") not in (None, 4294967295))
        )
        if not interesting:
            return None

    parent = body.get("parent") or {}
    out = {
        "kind": kind,
        # Never shed: a kprobe is rare by construction, an exec in the emulation
        # or runner namespaces is the scenario, and a host exec carrying a login
        # session is the desktop attack path.
        "_priority": bool(
            kind == "process_kprobe"
            or namespace in WATCHED_NAMESPACES
            or (host_process and process.get("auid") not in (None, 4294967295))
        ),
        "process": _process(process),
        "parent": {
            "binary": cap(parent.get("binary")),
            "arguments": cap(parent.get("arguments")),
            "pid": parent.get("pid"),
        },
        "node": cap(raw.get("node_name"), 63),
    }
    if kind == "process_kprobe":
        out["function"] = cap(body.get("function_name"), 120)
        out["args"] = _kprobe_args(body.get("args") or [])
    return out


def _kprobe_args(args):
    """Flatten the handful of argument shapes the socket policies produce."""
    flat = []
    for arg in args[:4]:
        if not isinstance(arg, dict):
            continue
        for key, value in arg.items():
            if isinstance(value, dict):
                flat.append({
                    "type": key,
                    "family": cap(value.get("family"), 20),
                    "addr": cap(value.get("addr"), 45),
                    "port": value.get("port"),
                })
            else:
                flat.append({"type": key, "value": cap(str(value), 60)})
    return flat


def audit_record(raw):
    """Trim and filter one API-server audit event, or None to drop it."""
    if raw.get("kind") != "Event":
        return None
    # ResponseComplete is the only stage with an outcome. Panic is kept because
    # a crashed handler is worth seeing.
    if raw.get("stage") not in ("ResponseComplete", "Panic"):
        return None

    ref = raw.get("objectRef") or {}
    resource = ref.get("resource") or ""
    sub = ref.get("subresource") or ""
    verb = raw.get("verb") or ""
    user = (raw.get("user") or {}).get("username") or ""
    code = ((raw.get("responseStatus") or {}).get("code")) or 0
    decision = ((raw.get("annotations") or {}).get(
        "authorization.k8s.io/decision")) or ""

    interesting = (
        resource in AUDIT_ALWAYS_RESOURCES
        or sub in AUDIT_SUBRESOURCES
        or (resource in AUDIT_CREDENTIAL_RESOURCES and verb != "watch")
        or (verb in AUDIT_WRITE_VERBS and resource in ("daemonsets", "nodes"))
        or decision == "forbid"
        or code == 403
        or user in ("system:anonymous", "")
    )
    if not interesting:
        return None

    return {
        # The audit stream is already filtered to authority, credential and
        # escape paths, so all of it is priority.
        "_priority": True,
        "auditId": cap(raw.get("auditID"), 40),
        "verb": cap(verb, 20),
        "user": cap(user, 253),
        "groups": [cap(g, 120) for g in (raw.get("user") or {}).get("groups", [])[:6]],
        "resource": cap(f"{resource}/{sub}" if sub else resource, 80),
        "namespace": cap(ref.get("namespace"), 63),
        "objectName": cap(ref.get("name"), 253),
        "sourceIPs": [cap(ip, 45) for ip in (raw.get("sourceIPs") or [])[:3]],
        "userAgent": cap(raw.get("userAgent"), 120),
        "decision": cap(decision, 20),
        "code": code,
        "requestURI": cap(raw.get("requestURI"), 200),
        # requestObject / responseObject are never copied. See the module
        # docstring: the spool must stay safe even if the audit policy is wrong.
    }


class RateLimiter:
    """Token bucket over emitted records, with a visible drop count."""

    def __init__(self, per_sec):
        self.per_sec = per_sec
        self.allowance = per_sec
        self.last = time.monotonic()
        self.dropped = 0

    def allow(self):
        now = time.monotonic()
        self.allowance = min(self.per_sec,
                             self.allowance + (now - self.last) * self.per_sec)
        self.last = now
        if self.allowance < 1:
            self.dropped += 1
            return False
        self.allowance -= 1
        return True

    def take_dropped(self):
        count, self.dropped = self.dropped, 0
        return count


class Tail:
    """One followed file. Reopens on rotation, starts at the end."""

    def __init__(self, path, stream):
        self.path = path
        self.stream = stream
        self.f = None
        self.inode = None

    def _open(self):
        try:
            self.f = open(self.path, errors="replace")
            self.inode = os.fstat(self.f.fileno()).st_ino
            self.f.seek(0, os.SEEK_END)
        except OSError:
            self.f = None

    def lines(self):
        if self.f is None:
            self._open()
            if self.f is None:
                return
        while True:
            line = self.f.readline()
            if not line:
                break
            yield line
        try:
            st = os.stat(self.path)
            rotated = st.st_ino != self.inode or st.st_size < self.f.tell()
        except OSError:
            rotated = True
        if rotated:
            try:
                self.f.close()
            except OSError:
                pass
            self.f = None


def main():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    out = open(OUT_PATH, "a", buffering=1)
    try:
        user, group = OWNER.split(":")
        import grp
        import pwd
        os.chown(OUT_PATH, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
        os.chmod(OUT_PATH, 0o640)
    except Exception:
        pass

    tails = [Tail(TETRAGON_LOG, "tetragon"), Tail(AUDIT_LOG, "k3s-audit")]
    limiter = RateLimiter(RATE_PER_SEC)
    seen = OrderedDict()  # audit ids already emitted, to survive a re-read
    last_drop_report = time.monotonic()

    while True:
        wrote = False
        for tail in tails:
            for line in tail.lines():
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                record = (tetragon_record(raw) if tail.stream == "tetragon"
                          else audit_record(raw))
                if record is None:
                    continue
                if tail.stream == "k3s-audit":
                    audit_id = record.get("auditId")
                    if audit_id and audit_id in seen:
                        continue
                    if audit_id:
                        seen[audit_id] = None
                        while len(seen) > 4096:
                            seen.popitem(last=False)
                if not record.get("_priority") and not limiter.allow():
                    continue
                record.pop("_priority", None)
                out.write(json.dumps({
                    "_stream": tail.stream,
                    "ts": raw.get("time") or raw.get("requestReceivedTimestamp")
                          or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "record": record,
                }) + "\n")
                wrote = True

        now = time.monotonic()
        if now - last_drop_report >= 60:
            dropped = limiter.take_dropped()
            last_drop_report = now
            if dropped:
                # Shed load is evidence: a flood is also how an intruder buries
                # one exec inside a million.
                out.write(json.dumps({
                    "_stream": "collector",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "record": {"dropped": dropped, "window_seconds": 60},
                }) + "\n")
        if not wrote:
            time.sleep(0.5)


if __name__ == "__main__":
    main()
