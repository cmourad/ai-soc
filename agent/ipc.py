#!/usr/bin/env python3
"""The framing every privileged AI SOC boundary speaks.

One JSON object per frame, prefixed with its length as four network-order
bytes. Every read is exact: `recv` returns what happens to have arrived, so a
helper that trusts a single `recv(4)` rejects a valid request whenever the
kernel splits the header across two stream packets. That is a rare, load
dependent failure, which is exactly why it must not be re-implemented per
helper.
"""

import json
import struct

MAX_FRAME = 8192


def read_exact(conn, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ValueError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_bytes(conn, maximum=MAX_FRAME):
    """One frame's body, still encoded."""
    size = struct.unpack("!I", read_exact(conn, 4))[0]
    if not 1 <= size <= maximum:
        raise ValueError(f"frame length {size} outside 1..{maximum}")
    return read_exact(conn, size)


def read_frame(conn, maximum=MAX_FRAME):
    return json.loads(recv_bytes(conn, maximum))


def frame(value):
    body = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(body)) + body


def send_frame(conn, value):
    conn.sendall(frame(value))
