#!/usr/bin/env python3
"""Small root boundary for wg-quick; accepts only framed, peer-authenticated requests."""
import os, pwd, re, socket, struct, subprocess

from ipc import frame, read_frame

SOCKET = os.environ.get("AISOC_VPN_SOCKET", "/run/aisoc-vpn/helper.sock")
CONFIG_DIR = os.environ.get("AISOC_VPN_CONFIG_DIR", "/var/lib/aisoc-vpn")
ALLOWED_UID = pwd.getpwnam(os.environ.get("AISOC_VPN_USER", "aisoc")).pw_uid
IFACE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")

def handle(req):
    action, interface = req.get("action"), req.get("interface")
    if action not in ("up", "down", "replace") or not isinstance(interface, str) or not IFACE.fullmatch(interface):
        return {"ok": False, "error": "invalid VPN request"}
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(CONFIG_DIR, interface + ".conf")
    config = None
    if action in ("up", "replace"):
        config = req.get("config")
        if not isinstance(config, str) or not config or len(config) > 8192 or "PostUp" in config or "PreUp" in config:
            return {"ok": False, "error": "invalid VPN configuration"}
    try:
        if action == "replace":
            # One request makes replacement atomic with respect to every client
            # of this single-writer helper. An absent interface is already the
            # desired result of down, so only the following up is authoritative.
            subprocess.run(["/usr/bin/wg-quick", "down", path], capture_output=True, text=True, timeout=45)
            action = "up"
        if config is not None:
            # Replacement must tear down with the old config (routes and DNS),
            # then atomically publish the new config before bringing it up.
            with open(path, "w", opener=lambda p, f: os.open(p, f, 0o600)) as out:
                out.write(config); out.flush(); os.fsync(out.fileno())
            os.chmod(path, 0o600)
        result = subprocess.run(["/usr/bin/wg-quick", action, path], capture_output=True, text=True, timeout=45)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": result.returncode == 0, "error": (result.stderr or result.stdout or "").strip()[-1000:] or None}

os.makedirs(os.path.dirname(SOCKET), mode=0o755, exist_ok=True)
try: os.unlink(SOCKET)
except FileNotFoundError: pass
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(SOCKET); os.chmod(SOCKET, 0o660); sock.listen(8)
while True:
    conn, _ = sock.accept()
    with conn:
        try:
            _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != ALLOWED_UID: raise PermissionError("unauthorized peer")
            conn.sendall(frame(handle(read_frame(conn))))
        except Exception as exc:
            conn.sendall(frame({"ok": False, "error": str(exc)}))
