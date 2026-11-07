#!/usr/bin/env python3
"""Clients for the two root helpers the agent talks to.

The agent holds CAP_NET_ADMIN but not root, so bringing a tunnel up and reading
socket ownership both cross a process boundary. Each call is a single framed
request over an authenticated Unix socket; neither helper accepts a command
line, and neither is reachable from the console directly.
"""

import json
import socket

from config import PROCESS_HELPER_SOCKET, VPN_HELPER_SOCKET, VPN_IFACE_RE
from ipc import frame, recv_bytes

def vpn_quick(action, interface, config=""):
    """Narrow privileged VPN boundary: only validated wg-quick actions.

    The console cannot mutate routes or invoke a shell. It sends the already
    parsed, hook-free profile over the authenticated control socket; this
    process owns CAP_NET_ADMIN and is the sole writer of the tunnel.
    """
    if not isinstance(interface, str) or not VPN_IFACE_RE.fullmatch(interface):
        return {"ok": False, "error": "invalid VPN interface name"}
    request = {"action": action, "interface": interface, "config": config or ""}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            # vpn_replace may run two 45s bounded subprocesses. Keep this hop
            # alive long enough to return the authoritative up result.
            conn.settimeout(95); conn.connect(VPN_HELPER_SOCKET)
            conn.sendall(frame(request))
            reply = json.loads(recv_bytes(conn).decode("utf-8"))
            return reply if isinstance(reply, dict) else {"ok": False, "error": "invalid VPN helper reply"}
    except OSError as exc:
        return {"ok": False, "error": f"VPN helper unavailable: {exc}"}


def process_lookup(req):
    """Proxy a bounded tuple lookup without exposing the root helper socket."""
    request = {
        "protocol": req.get("protocol"),
        "local_ip": req.get("local_ip"),
        "local_port": req.get("local_port"),
        "remote_ip": req.get("remote_ip"),
        "remote_port": req.get("remote_port"),
        "observed_at": req.get("observed_at"),
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2)
            conn.connect(PROCESS_HELPER_SOCKET)
            conn.sendall(frame(request))
            reply = json.loads(recv_bytes(conn).decode("utf-8"))
            if not isinstance(reply, dict):
                return {"ok": False, "error": "invalid process helper reply"}
            return reply
    except OSError as exc:
        return {"ok": False, "error": f"process helper unavailable: {exc}"}
