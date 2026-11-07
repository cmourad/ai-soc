#!/usr/bin/env python3
"""Root-only socket ownership sampler for Network Compass."""

import glob
import ipaddress
import os
import pwd
import re
import socket
import struct
import threading
import time

from ipc import frame, read_frame


SOCKET = os.environ.get("AISOC_PROCESS_SOCKET", "/run/aisoc-process/helper.sock")
ALLOWED_USER = os.environ.get("AISOC_PROCESS_USER", "aisoc")
SAMPLE_SECONDS = 0.5
TTL_SECONDS = 12.0
COMM = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


def _address(raw, version):
    packed = bytes.fromhex(raw)
    if version == 4:
        packed = packed[::-1]
    else:
        packed = b"".join(packed[offset:offset + 4][::-1] for offset in range(0, 16, 4))
    return str(ipaddress.ip_address(packed))


def parse_socket_table(lines, protocol, version):
    rows = []
    for line in list(lines)[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_address, local_port = fields[1].split(":")
            remote_address, remote_port = fields[2].split(":")
            local_ip = _address(local_address, version)
            remote_ip = _address(remote_address, version)
            local_port = int(local_port, 16)
            remote_port = int(remote_port, 16)
            inode = fields[9]
        except (ValueError, IndexError):
            continue
        if remote_port == 0 or int(ipaddress.ip_address(remote_ip)) == 0 or not inode.isdigit():
            continue
        rows.append(((protocol, local_ip, local_port, remote_ip, remote_port), inode))
    return rows


def sample_socket_owners(proc_root="/proc"):
    sockets = []
    for name, protocol, version in (
        ("tcp", "TCP", 4),
        ("tcp6", "TCP", 6),
        ("udp", "UDP", 4),
        ("udp6", "UDP", 6),
    ):
        try:
            with open(os.path.join(proc_root, "net", name), encoding="ascii") as source:
                sockets.extend(parse_socket_table(source, protocol, version))
        except (FileNotFoundError, PermissionError, OSError):
            continue

    wanted = {inode for _, inode in sockets}
    inode_comms = {}
    for process in glob.iglob(os.path.join(proc_root, "[0-9]*")):
        try:
            with open(os.path.join(process, "comm"), encoding="utf-8", errors="replace") as source:
                comm = source.read(65).rstrip("\n")
            if not COMM.fullmatch(comm):
                continue
            for descriptor in os.scandir(os.path.join(process, "fd")):
                try:
                    target = os.readlink(descriptor.path)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if not target.startswith("socket:[") or not target.endswith("]"):
                    continue
                inode = target[8:-1]
                if inode in wanted:
                    inode_comms.setdefault(inode, set()).add(comm)
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue

    owners = []
    for key, inode in sockets:
        comms = inode_comms.get(inode, set())
        owners.append((key, next(iter(comms)) if len(comms) == 1 else None))
    return owners


class SocketOwnerCache:
    def __init__(self, ttl=TTL_SECONDS, clock=time.monotonic):
        self.ttl = ttl
        self.clock = clock
        self.entries = {}
        self.lock = threading.Lock()

    def observe(self, owners):
        now = self.clock()
        grouped = {}
        for key, comm in owners:
            grouped.setdefault(key, set()).add(comm)
        with self.lock:
            for key, comms in grouped.items():
                self.entries[key] = (next(iter(comms)) if len(comms) == 1 else None, now)
            self._expire(now)

    def _expire(self, now):
        for key, (_, seen) in list(self.entries.items()):
            if now - seen > self.ttl:
                del self.entries[key]

    def lookup(self, key):
        now = self.clock()
        with self.lock:
            self._expire(now)
            entry = self.entries.get(key)
            return entry[0] if entry else None


def lookup_key(req):
    protocol = req.get("protocol")
    local_ip = req.get("local_ip")
    remote_ip = req.get("remote_ip")
    local_port = req.get("local_port")
    remote_port = req.get("remote_port")
    if protocol not in ("TCP", "UDP"):
        raise ValueError("unsupported protocol")
    if not isinstance(local_port, int) or not 1 <= local_port <= 65535:
        raise ValueError("invalid local port")
    if not isinstance(remote_port, int) or not 1 <= remote_port <= 65535:
        raise ValueError("invalid remote port")
    return (
        protocol,
        str(ipaddress.ip_address(local_ip)),
        local_port,
        str(ipaddress.ip_address(remote_ip)),
        remote_port,
    )


def serve(cache):
    allowed_uid = pwd.getpwnam(ALLOWED_USER).pw_uid
    os.makedirs(os.path.dirname(SOCKET), mode=0o755, exist_ok=True)
    try:
        os.unlink(SOCKET)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(SOCKET)
    os.chmod(SOCKET, 0o660)
    listener.listen(16)
    while True:
        conn, _ = listener.accept()
        with conn:
            try:
                conn.settimeout(2)
                _, uid, _ = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if uid != allowed_uid:
                    raise PermissionError("unauthorized peer")
                req = read_frame(conn)
                observed_at = req.get("observed_at")
                if not isinstance(observed_at, (int, float)) or abs(time.time() - observed_at) > cache.ttl:
                    conn.sendall(frame({"ok": True, "process_name": None}))
                    continue
                conn.sendall(frame({"ok": True, "process_name": cache.lookup(lookup_key(req))}))
            except Exception as exc:
                conn.sendall(frame({"ok": False, "error": str(exc)}))


def main():
    cache = SocketOwnerCache()

    def sample():
        while True:
            cache.observe(sample_socket_owners())
            time.sleep(SAMPLE_SECONDS)

    threading.Thread(target=sample, daemon=True).start()
    serve(cache)


if __name__ == "__main__":
    main()
